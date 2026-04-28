use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc};
use std::thread;

use bytes::Bytes;
use pxe_nfs::{NfsConfig, NfsServer};
use pxe_profiles::{load_all_files, load_file, ubuntu, LinuxProfile};

use crate::boot::{add_binary_asset, add_ipxe_script_asset, build_boot_assets};
use crate::network::NetworkSelection;
use crate::runtime::{RuntimeInfo, RuntimeSession};
use crate::services::{CoreServers, DhcpBoot, ServiceRunner};
use crate::{
    default_ipxe_tftp_files, is_iso, profile_error, require_known_architecture, run_core_start,
    DEFAULT_HTTP_PORT,
};

pub fn run_http_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: LinuxProfile,
) -> Result<RuntimeSession, String> {
    let arch = require_known_architecture(profile.architecture)?;
    let serial_console = arch
        .serial_console()
        .ok_or_else(|| "error: unsupported serial console for architecture: unknown".to_string())?;

    let file_bytes: HashMap<String, Bytes> = load_all_files(&source_path)
        .map_err(|err| profile_error(&source_path, err))?
        .into_iter()
        .map(|(file_path, content)| (file_path, Bytes::from(content)))
        .collect();

    let kernel = file_bytes
        .get(profile.kernel_path.as_str())
        .ok_or_else(|| format!("error: kernel not found at {}", profile.kernel_path))?
        .clone();
    let initrd = file_bytes
        .get(profile.initrd_path.as_str())
        .ok_or_else(|| format!("error: initrd not found at {}", profile.initrd_path))?
        .clone();

    let mut assets = HashMap::new();
    for (file_path, content) in file_bytes {
        add_binary_asset(
            &mut assets,
            &format!("/boot/{}", file_path.trim_start_matches('/')),
            content,
        );
    }
    add_binary_asset(&mut assets, "/boot/linux", kernel);
    add_binary_asset(&mut assets, "/boot/initrd", initrd);

    let mut boot_params = profile.boot_params.clone();
    if !boot_params.contains("console=") {
        if !boot_params.is_empty() {
            boot_params.push(' ');
        }
        boot_params.push_str(&format!("console=tty0 console={serial_console},115200n8"));
    }

    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let ipxe_script = ubuntu::build_ipxe_script(network.ip, DEFAULT_HTTP_PORT, &boot_params);

    run_core_start(
        profile.label,
        network,
        assets,
        default_ipxe_tftp_files(arch)?,
        DhcpBoot::ipxe(ipxe_boot_file),
        Some(ipxe_script),
    )
}

pub fn run_nfs_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: LinuxProfile,
) -> Result<RuntimeSession, String> {
    if !is_iso(&source_path) {
        return Err("error: Ubuntu live ISO boot requires an ISO source".to_string());
    }

    let arch = require_known_architecture(profile.architecture)?;
    let serial_console = arch
        .serial_console()
        .ok_or_else(|| "error: unsupported serial console for architecture: unknown".to_string())?;
    let kernel = load_file(&source_path, &profile.kernel_path)
        .map_err(|err| profile_error(&source_path, err))?;
    let initrd = load_file(&source_path, &profile.initrd_path)
        .map_err(|err| profile_error(&source_path, err))?;

    let nfs_export_path = "/";
    let nfs_server = NfsServer::bind(NfsConfig {
        iso_path: source_path.clone(),
        bind_ip: network.ip,
        export_path: nfs_export_path.to_string(),
    })
    .map_err(|err| format!("error: failed to bind NFS server: {err}"))?;
    let nfs_addr = nfs_server
        .nfs_local_addr()
        .map_err(|err| format!("error: failed to read NFS socket address: {err}"))?;

    let boot_params = format!(
        "{} console=tty0 console={},115200n8",
        ubuntu::nfs_boot_params(network.ip, nfs_export_path),
        serial_console
    );

    let mut assets = build_boot_assets(kernel, initrd);
    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let ipxe_script = ubuntu::build_ipxe_script(network.ip, DEFAULT_HTTP_PORT, &boot_params);
    add_ipxe_script_asset(&mut assets, &ipxe_boot_file, ipxe_script);

    let core = CoreServers::bind(
        network.ip,
        assets,
        default_ipxe_tftp_files(arch)?,
        DhcpBoot::ipxe(ipxe_boot_file),
    )?;

    let info = RuntimeInfo {
        label: profile.label,
        interface: network.name.clone(),
        ip: network.ip,
        dhcp_addr: core.dhcp_addr,
        tftp_addr: core.tftp_addr,
        http_addr: core.http_addr,
        nfs_addr: Some(nfs_addr),
        smb_addr: None,
        smb_share_name: None,
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let worker = thread::spawn(move || {
        let mut runner = ServiceRunner::new(worker_shutdown);
        runner.spawn("NFS", move |sd| nfs_server.serve_until_shutdown(sd));
        core.spawn(&mut runner);
        runner.run()
    });

    Ok(RuntimeSession::new(info, shutdown, worker))
}
