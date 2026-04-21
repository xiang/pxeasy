pub mod boot;
pub mod network;
pub mod services;
mod wim;

use std::{
    collections::HashMap,
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use boot::{add_binary_asset, add_ipxe_script_asset, build_boot_assets};
use bytes::Bytes;
pub use network::{resolve_network, NetworkSelection};
use pxe_http::HttpAsset;
use pxe_nfs::{NfsConfig, NfsServer};
use pxe_profiles::{
    detect_profile, load_all_files, load_file, load_file_slice, ubuntu, BootProfile, LinuxProfile,
    ProfileError, WindowsProfile,
};
pub use pxe_profiles::{Architecture, BootSourceKind};
use pxe_smb::{SmbConfig, SmbServer};
use services::{CoreServers, DhcpBoot, ServiceRunner};
use wim::Wim;

const DEFAULT_HTTP_PORT: u16 = 8080;
const DEFAULT_SMB_PORT: u16 = 445;
const WINDOWS_SHARE_NAME: &str = "windows";
const WINDOWS_SOURCE_WINPE_IMAGE: i32 = 1;
const WINDOWS_CUSTOM_WINPE_IMAGE: i32 = 1;
const WINDOWS_VIRTIO_ROOT: &str = "/Users/sfortner/work/lab/pxeasy/assets/windows/virtio-win";
const WINDOWS_STARTNET_TEMPLATE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/windows/startnet.cmd"
);

#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub source_path: PathBuf,
    pub interface: Option<String>,
    pub bind_ip: Option<Ipv4Addr>,
    pub ipxe_boot_file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub label: String,
    pub architecture: Architecture,
    pub source_kind: BootSourceKind,
}

#[derive(Debug, Clone)]
pub struct RuntimeInfo {
    pub label: String,
    pub interface: String,
    pub ip: Ipv4Addr,
    pub dhcp_addr: SocketAddr,
    pub tftp_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub nfs_addr: Option<SocketAddr>,
    pub smb_addr: Option<SocketAddr>,
    pub smb_share_name: Option<String>,
}

pub struct RuntimeSession {
    info: RuntimeInfo,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<(), String>>>,
}

impl RuntimeSession {
    pub fn info(&self) -> &RuntimeInfo {
        &self.info
    }

    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn wait(mut self) -> Result<(), String> {
        match self.worker.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| "error: runtime worker thread panicked".to_string())?,
            None => Ok(()),
        }
    }
}

impl Drop for RuntimeSession {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

pub fn inspect_source(source_path: &Path) -> Result<ResolvedSource, String> {
    let profile = resolve_profile(source_path)?;
    Ok(ResolvedSource {
        label: profile.label().to_string(),
        architecture: profile.architecture(),
        source_kind: profile.source_kind(),
    })
}

pub fn start(request: LaunchRequest) -> Result<RuntimeSession, String> {
    let network = resolve_network(request.interface.as_deref(), request.bind_ip)?;
    let profile = resolve_profile(&request.source_path)?;

    match profile {
        BootProfile::Linux(profile) => match profile.source_kind {
            BootSourceKind::UbuntuLiveIso => run_nfs_start(
                request.source_path,
                request.ipxe_boot_file,
                network,
                profile,
            ),
            BootSourceKind::FreeBSDBootOnly => run_freebsd_start(
                request.source_path,
                request.ipxe_boot_file,
                network,
                profile,
            ),
            _ => run_http_start(
                request.source_path,
                request.ipxe_boot_file,
                network,
                profile,
            ),
        },
        BootProfile::Windows(profile) => run_windows_start(
            request.source_path,
            request.ipxe_boot_file,
            network,
            profile,
        ),
    }
}

fn run_http_start(
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
        DhcpBoot {
            first_stage_bootfile: "ipxe.efi".to_string(),
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: None,
            ipxe_bootfile: Some(ipxe_boot_file),
            root_path: None,
        },
        Some(ipxe_script),
    )
}

fn run_nfs_start(
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
        DhcpBoot {
            first_stage_bootfile: "ipxe.efi".to_string(),
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: None,
            ipxe_bootfile: Some(ipxe_boot_file),
            root_path: None,
        },
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

    Ok(RuntimeSession {
        info,
        shutdown,
        worker: Some(worker),
    })
}

fn run_freebsd_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: LinuxProfile,
) -> Result<RuntimeSession, String> {
    if !is_freebsd_boot_image(&source_path) {
        return Err("error: FreeBSD boot requires an ISO or memstick disk image".to_string());
    }

    if is_iso(&source_path) {
        return run_freebsd_iso_start(source_path, ipxe_boot_file, network, profile);
    }

    let arch = require_known_architecture(profile.architecture)?;

    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let sanboot_url = format!("http://{}:{}/disk.img", network.ip, DEFAULT_HTTP_PORT);
    let ipxe_script = format!("#!ipxe\nsanboot {sanboot_url}\n");

    let mut assets = HashMap::new();
    assets.insert(
        "/disk.img".to_string(),
        HttpAsset::File {
            content_type: "application/octet-stream",
            path: source_path,
        },
    );
    add_ipxe_script_asset(&mut assets, &ipxe_boot_file, ipxe_script);

    run_core_start(
        profile.label,
        network,
        assets,
        default_ipxe_tftp_files(arch)?,
        DhcpBoot {
            first_stage_bootfile: "ipxe.efi".to_string(),
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: None,
            ipxe_bootfile: Some(ipxe_boot_file),
            root_path: None,
        },
        None,
    )
}

fn run_freebsd_iso_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: LinuxProfile,
) -> Result<RuntimeSession, String> {
    let arch = require_known_architecture(profile.architecture)?;
    let boot_filename = profile.efi_path.clone();
    let loader_args = freebsd_loader_args();
    let direct_efi = freebsd_direct_efi();

    let extracted_root = extract_iso_tree(&source_path)?;
    let mut assets = build_http_assets_from_tree(extracted_root.path())?;
    let mut tftp_files = default_ipxe_tftp_files(arch)?;
    let chain_transport = freebsd_chain_transport();

    if direct_efi || matches!(chain_transport, FreebsdChainTransport::Tftp) {
        tftp_files.extend(build_tftp_files_from_subtree(
            extracted_root.path(),
            Path::new("boot"),
        )?);
    }

    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let ipxe_script = build_freebsd_script(
        chain_transport,
        network.ip,
        DEFAULT_HTTP_PORT,
        boot_filename.as_deref(),
        loader_args.as_deref(),
    );

    add_ipxe_script_asset(&mut assets, &ipxe_boot_file, ipxe_script);

    let core = CoreServers::bind(
        network.ip,
        assets,
        tftp_files,
        DhcpBoot {
            first_stage_bootfile: if direct_efi {
                "boot/loader.efi".to_string()
            } else {
                "ipxe.efi".to_string()
            },
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: if direct_efi {
                Some("boot/loader.efi".to_string())
            } else {
                None
            },
            ipxe_bootfile: if direct_efi {
                None
            } else {
                Some(ipxe_boot_file)
            },
            root_path: freebsd_root_path(),
        },
    )?;

    let info = RuntimeInfo {
        label: profile.label,
        interface: network.name.clone(),
        ip: network.ip,
        dhcp_addr: core.dhcp_addr,
        tftp_addr: core.tftp_addr,
        http_addr: core.http_addr,
        nfs_addr: None,
        smb_addr: None,
        smb_share_name: None,
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let worker = thread::spawn(move || {
        let _keep_tempdir = extracted_root;
        let mut runner = ServiceRunner::new(worker_shutdown);
        core.spawn(&mut runner);
        runner.run()
    });

    Ok(RuntimeSession {
        info,
        shutdown,
        worker: Some(worker),
    })
}

fn extract_iso_tree(source_path: &Path) -> Result<tempfile::TempDir, String> {
    let tempdir = tempfile::tempdir()
        .map_err(|e| format!("error: failed to create temporary directory: {e}"))?;
    let status = Command::new("xorriso")
        .args(["-osirrox", "on", "-indev"])
        .arg(source_path)
        .args(["-extract", "/"])
        .arg(tempdir.path())
        .status()
        .map_err(|e| format!("error: failed to extract FreeBSD ISO with xorriso: {e}"))?;
    if !status.success() {
        return Err(format!(
            "error: xorriso failed to extract FreeBSD ISO: {status}"
        ));
    }
    Ok(tempdir)
}

fn build_http_assets_from_tree(root: &Path) -> Result<HashMap<String, HttpAsset>, String> {
    let mut assets = HashMap::new();
    add_tree_assets(root, root, &mut assets)?;
    Ok(assets)
}

fn build_tftp_files_from_subtree(
    root: &Path,
    subtree: &Path,
) -> Result<HashMap<String, Bytes>, String> {
    let mut files = HashMap::new();
    let subtree_root = root.join(subtree);
    add_tftp_tree_assets(&subtree_root, &subtree_root, &mut files)?;
    Ok(files)
}

fn add_tree_assets(
    root: &Path,
    dir: &Path,
    assets: &mut HashMap<String, HttpAsset>,
) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("error: failed to read {:?}: {e}", dir))? {
        let entry = entry.map_err(|e| format!("error: failed to read directory entry: {e}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("error: failed to read file type for {:?}: {e}", path))?;

        if file_type.is_dir() {
            add_tree_assets(root, &path, assets)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .map_err(|e| format!("error: failed to relativize {:?}: {e}", path))?;
        let http_path = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
        assets.insert(
            http_path,
            HttpAsset::File {
                content_type: "application/octet-stream",
                path,
            },
        );
    }
    Ok(())
}

fn add_tftp_tree_assets(
    root: &Path,
    dir: &Path,
    files: &mut HashMap<String, Bytes>,
) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("error: failed to read {:?}: {e}", dir))? {
        let entry = entry.map_err(|e| format!("error: failed to read directory entry: {e}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("error: failed to read file type for {:?}: {e}", path))?;

        if file_type.is_dir() {
            add_tftp_tree_assets(root, &path, files)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .map_err(|e| format!("error: failed to relativize {:?}: {e}", path))?;
        let tftp_path = format!("boot/{}", rel.to_string_lossy().replace('\\', "/"));
        let data = fs::read(&path)
            .map_err(|e| format!("error: failed to read {:?} for TFTP export: {e}", path))?;
        files.insert(tftp_path, Bytes::from(data));
    }
    Ok(())
}

fn run_windows_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: WindowsProfile,
) -> Result<RuntimeSession, String> {
    let arch = require_known_architecture(profile.architecture)?;
    let cached_wimboot = fetch_wimboot(arch)?;
    let prepared_boot_wim =
        prepare_windows_boot_wim(&source_path, &profile.boot_wim_path, network.ip, arch)?;

    let mut assets = HashMap::new();
    add_windows_iso_asset(
        &mut assets,
        &source_path,
        "/windows/bootmgr",
        &profile.bootmgr_path,
    )?;
    add_windows_iso_asset(
        &mut assets,
        &source_path,
        "/windows/boot/bcd",
        &profile.bcd_path,
    )?;
    add_windows_iso_asset(
        &mut assets,
        &source_path,
        "/windows/boot/boot.sdi",
        &profile.boot_sdi_path,
    )?;
    assets.insert(
        "/windows/wimboot".to_string(),
        HttpAsset::File {
            content_type: "application/octet-stream",
            path: cached_wimboot,
        },
    );
    assets.insert(
        "/windows/sources/boot.wim".to_string(),
        HttpAsset::File {
            content_type: "application/octet-stream",
            path: prepared_boot_wim,
        },
    );

    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let ipxe_script = build_windows_ipxe_script(network.ip, DEFAULT_HTTP_PORT);
    add_ipxe_script_asset(&mut assets, &ipxe_boot_file, ipxe_script);

    let core = CoreServers::bind(
        network.ip,
        assets,
        default_ipxe_tftp_files(arch)?,
        DhcpBoot {
            first_stage_bootfile: "ipxe.efi".to_string(),
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: None,
            ipxe_bootfile: Some(ipxe_boot_file),
            root_path: None,
        },
    )?;

    let smb = SmbServer::bind(SmbConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_SMB_PORT,
        share_name: WINDOWS_SHARE_NAME.to_string(),
        source_path,
    })
    .map_err(smb_bind_error)?;
    let smb_addr = smb
        .local_addr()
        .map_err(|err| format!("error: failed to read SMB socket address: {err}"))?;

    let info = RuntimeInfo {
        label: profile.label,
        interface: network.name.clone(),
        ip: network.ip,
        dhcp_addr: core.dhcp_addr,
        tftp_addr: core.tftp_addr,
        http_addr: core.http_addr,
        nfs_addr: None,
        smb_addr: Some(smb_addr),
        smb_share_name: Some(WINDOWS_SHARE_NAME.to_string()),
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let worker = thread::spawn(move || {
        let mut runner = ServiceRunner::new(worker_shutdown);
        core.spawn(&mut runner);
        runner.spawn("SMB", move |sd| smb.serve_until_shutdown(sd));
        runner.run()
    });

    Ok(RuntimeSession {
        info,
        shutdown,
        worker: Some(worker),
    })
}

fn run_core_start(
    label: String,
    network: NetworkSelection,
    mut assets: HashMap<String, HttpAsset>,
    tftp_files: HashMap<String, Bytes>,
    dhcp_boot: DhcpBoot,
    ipxe_script: Option<String>,
) -> Result<RuntimeSession, String> {
    if let (Some(boot_file), Some(script)) = (&dhcp_boot.ipxe_bootfile, ipxe_script) {
        add_ipxe_script_asset(&mut assets, boot_file, script);
    }

    let core = CoreServers::bind(network.ip, assets, tftp_files, dhcp_boot)?;
    let info = RuntimeInfo {
        label,
        interface: network.name.clone(),
        ip: network.ip,
        dhcp_addr: core.dhcp_addr,
        tftp_addr: core.tftp_addr,
        http_addr: core.http_addr,
        nfs_addr: None,
        smb_addr: None,
        smb_share_name: None,
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let worker = thread::spawn(move || {
        let mut runner = ServiceRunner::new(worker_shutdown);
        core.spawn(&mut runner);
        runner.run()
    });

    Ok(RuntimeSession {
        info,
        shutdown,
        worker: Some(worker),
    })
}

fn default_ipxe_tftp_files(arch: Architecture) -> Result<HashMap<String, Bytes>, String> {
    let mut tftp_files = HashMap::new();
    tftp_files.insert("ipxe.efi".to_string(), Bytes::from(fetch_ipxe(arch)?));
    Ok(tftp_files)
}

fn is_iso(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("iso"))
}

fn is_freebsd_boot_image(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("iso")
                || ext.eq_ignore_ascii_case("img")
                || ext.eq_ignore_ascii_case("raw")
        })
}

fn build_freebsd_script(
    transport: FreebsdChainTransport,
    bind_ip: Ipv4Addr,
    http_port: u16,
    boot_filename: Option<&str>,
    loader_args: Option<&str>,
) -> String {
    let loader_url = boot_filename
        .map(|filename| freebsd_loader_url(transport, bind_ip, http_port, filename))
        .unwrap_or_else(|| {
            freebsd_loader_url(transport, bind_ip, http_port, "/boot/EFI/BOOT/BOOTAA64.EFI")
        });

    let boot_command = match loader_args {
        Some(args) if !args.trim().is_empty() => {
            format!("chain --autofree {loader_url} {}", args.trim())
        }
        _ => format!("chain --autofree {loader_url}"),
    };
    format!("#!ipxe\n{boot_command}\n")
}

#[derive(Copy, Clone)]
enum FreebsdChainTransport {
    Http,
    Tftp,
}

fn freebsd_loader_url(
    transport: FreebsdChainTransport,
    bind_ip: Ipv4Addr,
    http_port: u16,
    filename: &str,
) -> String {
    match transport {
        FreebsdChainTransport::Http => format!("http://{bind_ip}:{http_port}{filename}"),
        FreebsdChainTransport::Tftp => format!("tftp://{bind_ip}{filename}"),
    }
}

fn freebsd_loader_args() -> Option<String> {
    std::env::var("PXEASY_FREEBSD_LOADER_ARGS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn freebsd_root_path() -> Option<String> {
    std::env::var("PXEASY_FREEBSD_ROOT_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn freebsd_chain_transport() -> FreebsdChainTransport {
    match std::env::var("PXEASY_FREEBSD_CHAIN_PROTO") {
        Ok(value) if value.trim().eq_ignore_ascii_case("tftp") => FreebsdChainTransport::Tftp,
        _ => FreebsdChainTransport::Http,
    }
}

fn freebsd_direct_efi() -> bool {
    std::env::var("PXEASY_FREEBSD_DIRECT_EFI")
        .ok()
        .map(|value| {
            let value = value.trim();
            value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn add_windows_iso_asset(
    assets: &mut HashMap<String, HttpAsset>,
    source_path: &Path,
    http_path: &str,
    iso_path: &str,
) -> Result<(), String> {
    match load_file_slice(source_path, iso_path) {
        Ok(slice) => {
            assets.insert(
                http_path.to_string(),
                HttpAsset::IsoSlice {
                    content_type: "application/octet-stream",
                    path: source_path.to_path_buf(),
                    offset: slice.offset,
                    length: slice.length,
                },
            );
        }
        Err(_) => {
            let bytes =
                load_file(source_path, iso_path).map_err(|err| profile_error(source_path, err))?;
            assets.insert(
                http_path.to_string(),
                HttpAsset::Memory {
                    content_type: "application/octet-stream",
                    data: Bytes::from(bytes),
                },
            );
        }
    }
    Ok(())
}

fn build_windows_ipxe_script(bind_ip: Ipv4Addr, http_port: u16) -> String {
    format!(
        "#!ipxe\nkernel http://{bind_ip}:{http_port}/windows/wimboot\ninitrd http://{bind_ip}:{http_port}/windows/bootmgr bootmgr\ninitrd http://{bind_ip}:{http_port}/windows/boot/bcd BCD\ninitrd http://{bind_ip}:{http_port}/windows/boot/boot.sdi boot.sdi\ninitrd http://{bind_ip}:{http_port}/windows/sources/boot.wim boot.wim\nboot\n"
    )
}

fn prepare_windows_boot_wim(
    source_path: &Path,
    boot_wim_path: &str,
    server_ip: Ipv4Addr,
    arch: Architecture,
) -> Result<PathBuf, String> {
    let source_metadata = fs::metadata(source_path)
        .map_err(|err| format!("error: failed to stat {}: {err}", source_path.display()))?;
    let modified = source_metadata
        .modified()
        .map_err(|err| format!("error: failed to read ISO mtime: {err}"))?;
    let modified_secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("error: failed to normalize ISO mtime: {err}"))?
        .as_secs();

    let virtio_drivers = windows_virtio_drivers(arch)?;
    let startnet_script = windows_startnet_cmd(server_ip, &virtio_drivers)?;
    let cache_dir = PathBuf::from(format!("{}.pxeasy", source_path.display()));
    fs::create_dir_all(&cache_dir)
        .map_err(|err| format!("error: failed to create Windows cache dir: {err}"))?;

    let cached_wim = cache_dir.join("boot.wim");
    let cached_meta = cache_dir.join("boot.wim.meta");
    let expected_meta = format!(
        "size={}\nmtime={modified_secs}\nserver_ip={server_ip}\narch={}\nvirtio_drivers={}\nstartnet_hash={:016x}\n",
        source_metadata.len(),
        arch.slug().unwrap_or("unknown"),
        windows_virtio_meta(&virtio_drivers),
        stable_hash(&startnet_script)
    );

    if cached_wim.exists() {
        if let Ok(existing_meta) = fs::read_to_string(&cached_meta) {
            if existing_meta == expected_meta {
                return Ok(cached_wim);
            }
        }
    }

    let tempdir = tempfile::tempdir()
        .map_err(|err| format!("error: failed to create temporary directory: {err}"))?;
    let temp_boot_wim = tempdir.path().join("boot.wim");
    let startnet_cmd = tempdir.path().join("startnet.cmd");
    let source_boot_wim = tempdir.path().join("source-boot.wim");
    let boot_wim_bytes =
        load_file(source_path, boot_wim_path).map_err(|err| profile_error(source_path, err))?;

    fs::write(&source_boot_wim, boot_wim_bytes)
        .map_err(|err| format!("error: failed to write temporary source boot.wim: {err}"))?;
    fs::write(&startnet_cmd, startnet_script)
        .map_err(|err| format!("error: failed to write startnet.cmd: {err}"))?;

    Wim::export_image_to_new_wim(&source_boot_wim, WINDOWS_SOURCE_WINPE_IMAGE, &temp_boot_wim)?;

    let mut wim = Wim::open_for_update(&temp_boot_wim)?;
    wim.replace_file(
        WINDOWS_CUSTOM_WINPE_IMAGE,
        &startnet_cmd,
        "/Windows/System32/startnet.cmd",
    )?;
    for driver in &virtio_drivers {
        wim.add_tree(
            WINDOWS_CUSTOM_WINPE_IMAGE,
            &driver.host_dir,
            &driver.wim_dir,
        )?;
    }
    wim.overwrite()?;

    fs::copy(&temp_boot_wim, &cached_wim)
        .map_err(|err| format!("error: failed to cache prepared boot.wim: {err}"))?;
    fs::write(&cached_meta, expected_meta)
        .map_err(|err| format!("error: failed to write boot.wim cache metadata: {err}"))?;

    Ok(cached_wim)
}

fn windows_startnet_cmd(
    server_ip: Ipv4Addr,
    virtio_drivers: &[WindowsVirtioDriver],
) -> Result<String, String> {
    let template = fs::read_to_string(WINDOWS_STARTNET_TEMPLATE).map_err(|err| {
        format!(
            "error: failed to read Windows startnet template at {}: {err}",
            WINDOWS_STARTNET_TEMPLATE
        )
    })?;

    let mut drvload_lines = String::new();
    for driver in virtio_drivers {
        for inf_path in &driver.inf_paths {
            drvload_lines.push_str(&format!("drvload X:{inf_path}\n"));
        }
    }

    let script = template
        .replace("{{DRVLOAD_LINES}}", &drvload_lines)
        .replace("{{SERVER_IP}}", &server_ip.to_string())
        .replace("{{SHARE_NAME}}", WINDOWS_SHARE_NAME);

    Ok(script.replace("\r\n", "\n").replace('\n', "\r\n"))
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

struct WindowsVirtioDriver {
    host_dir: PathBuf,
    wim_dir: String,
    inf_paths: Vec<String>,
}

fn windows_virtio_drivers(arch: Architecture) -> Result<Vec<WindowsVirtioDriver>, String> {
    if arch != Architecture::Arm64 {
        return Ok(Vec::new());
    }

    let root = PathBuf::from(WINDOWS_VIRTIO_ROOT);
    if !root.is_dir() {
        return Err(format!(
            "error: expected virtio driver root at {}",
            root.display()
        ));
    }

    let mut drivers = Vec::new();
    let entries = fs::read_dir(&root)
        .map_err(|err| format!("error: failed to read virtio driver root: {err}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("error: failed to read virtio driver entry: {err}"))?;
        if !entry
            .file_type()
            .map_err(|err| format!("error: failed to stat virtio driver entry: {err}"))?
            .is_dir()
        {
            continue;
        }

        let host_dir = entry.path().join("w11").join("ARM64");
        if !host_dir.is_dir() {
            continue;
        }

        let driver_name = entry.file_name().to_string_lossy().into_owned();
        let mut inf_paths = Vec::new();
        let driver_entries = fs::read_dir(&host_dir).map_err(|err| {
            format!(
                "error: failed to read ARM64 driver dir {}: {err}",
                host_dir.display()
            )
        })?;
        for driver_entry in driver_entries {
            let driver_entry = driver_entry
                .map_err(|err| format!("error: failed to read ARM64 driver entry: {err}"))?;
            let path = driver_entry.path();
            if !path.is_file() {
                continue;
            }
            let is_inf = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("inf"));
            if !is_inf {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("error: non-UTF-8 INF path: {}", path.display()))?;
            inf_paths.push(format!("/Drivers/{driver_name}/{file_name}"));
        }

        if inf_paths.is_empty() {
            continue;
        }
        inf_paths.sort();

        drivers.push(WindowsVirtioDriver {
            host_dir,
            wim_dir: format!("/Drivers/{driver_name}"),
            inf_paths,
        });
    }

    drivers.sort_by(|left, right| left.wim_dir.cmp(&right.wim_dir));
    if drivers.is_empty() {
        return Err(format!(
            "error: no ARM64 virtio driver directories found under {}",
            root.display()
        ));
    }

    Ok(drivers)
}

fn windows_virtio_meta(drivers: &[WindowsVirtioDriver]) -> String {
    if drivers.is_empty() {
        return "none".to_string();
    }

    drivers
        .iter()
        .map(|driver| driver.host_dir.display().to_string())
        .collect::<Vec<_>>()
        .join(";")
}

fn fetch_wimboot(arch: Architecture) -> Result<PathBuf, String> {
    let cache_dir = pxeasy_cache_dir()?.join("cache");
    fs::create_dir_all(&cache_dir)
        .map_err(|err| format!("error: failed to create wimboot cache dir: {err}"))?;

    let (filename, url) = match arch {
        Architecture::Unknown => {
            return Err("error: unsupported wimboot architecture: unknown".to_string());
        }
        Architecture::Amd64 => (
            "wimboot",
            "https://github.com/ipxe/wimboot/releases/latest/download/wimboot",
        ),
        Architecture::Arm64 => (
            "wimboot.arm64",
            "https://github.com/ipxe/wimboot/releases/latest/download/wimboot.arm64",
        ),
    };

    let cached_wimboot = cache_dir.join(filename);
    if cached_wimboot.exists() {
        return Ok(cached_wimboot);
    }

    let output_path = cached_wimboot
        .to_str()
        .ok_or("error: wimboot cache path contains non-UTF-8 characters")?;
    let status = Command::new("curl")
        .args(["-fsSL", url, "-o", output_path])
        .status()
        .map_err(|err| format!("error: failed to spawn curl for wimboot download: {err}"))?;
    if !status.success() {
        return Err("error: wimboot not cached — download from https://github.com/ipxe/wimboot/releases and place at ~/.pxeasy/cache/wimboot".to_string());
    }

    Ok(cached_wimboot)
}

fn pxeasy_cache_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".pxeasy"))
        .ok_or_else(|| "error: HOME is not set; cannot resolve ~/.pxeasy cache".to_string())
}

fn resolve_profile(source_path: &Path) -> Result<BootProfile, String> {
    match detect_profile(source_path) {
        Ok(profile) => Ok(profile),
        Err(err) => Err(profile_error(source_path, err)),
    }
}

fn profile_error(source_path: &Path, err: ProfileError) -> String {
    match err {
        ProfileError::SourceUnreadable(_, io_err) if io_err.kind() == io::ErrorKind::NotFound => {
            format!("error: ISO not found: {}", source_path.display())
        }
        ProfileError::UnknownDistro => {
            "error: no boot profile matched — unsupported boot source".to_string()
        }
        ProfileError::SourceUnreadable(_, io_err) => {
            format!("error: boot source unreadable: {}", io_err)
        }
        ProfileError::MissingFile { path } => {
            format!("error: boot source is missing required file: {}", path)
        }
    }
}

fn require_known_architecture(arch: Architecture) -> Result<Architecture, String> {
    match arch {
        Architecture::Unknown => Err(
            "error: could not determine boot architecture from source metadata; need filename or contents that identify amd64 vs arm64".to_string(),
        ),
        _ => Ok(arch),
    }
}

fn fetch_ipxe(arch: Architecture) -> Result<Vec<u8>, String> {
    let cache_dir = std::env::temp_dir().join("pxeasy-ipxe");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("error: failed to create iPXE cache dir: {e}"))?;

    let url = match arch {
        Architecture::Unknown => {
            return Err("error: unsupported iPXE architecture: unknown".to_string());
        }
        Architecture::Amd64 => "https://boot.ipxe.org/snponly.efi",
        Architecture::Arm64 => "https://boot.ipxe.org/arm64-efi/snponly.efi",
    };

    let arch_slug = arch
        .slug()
        .ok_or_else(|| "error: unsupported iPXE architecture: unknown".to_string())?;
    let local_path = cache_dir.join(format!("snponly-{arch_slug}.efi"));

    if !local_path.exists() {
        log::info!("downloading iPXE payload from {}", url);
        let local_str = local_path
            .to_str()
            .ok_or("error: iPXE cache path contains non-UTF-8 characters")?;
        let status = std::process::Command::new("curl")
            .args(["-sL", url, "-o", local_str])
            .status()
            .map_err(|e| format!("error: failed to spawn curl: {e}"))?;
        if !status.success() {
            return Err(format!(
                "error: curl failed to download iPXE. Exit code: {status}"
            ));
        }
    }

    std::fs::read(&local_path).map_err(|e| format!("error: failed to read cached iPXE: {e}"))
}

fn smb_bind_error(err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => {
            "error: failed to bind SMB socket on TCP port 445; re-run as root".to_string()
        }
        std::io::ErrorKind::AddrInUse => {
            "error: cannot bind SMB port 445 — another SMB server may be running".to_string()
        }
        _ => format!("error: failed to bind SMB socket: {err}"),
    }
}
