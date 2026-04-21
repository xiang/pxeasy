pub mod boot;
pub mod network;
pub mod services;

use std::{
    collections::HashMap,
    fs, io,
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
    detect_profile, load_all_files, load_file, load_file_slice, ubuntu, BootProfile, BootSource,
    ProfileError,
};
pub use pxe_profiles::{Architecture, BootSourceKind};
use pxe_smb::{SmbConfig, SmbServer};
use services::{CoreServers, DhcpBoot, ServiceRunner};

const DEFAULT_HTTP_PORT: u16 = 8080;
const DEFAULT_SMB_PORT: u16 = 445;
const WINDOWS_SHARE_NAME: &str = "windows";

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
        label: profile.label,
        architecture: profile.architecture,
        source_kind: profile.source_kind,
    })
}

pub fn start(request: LaunchRequest) -> Result<RuntimeSession, String> {
    let network = resolve_network(request.interface.as_deref(), request.bind_ip)?;
    let profile = resolve_profile(&request.source_path)?;

    match profile.source_kind {
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
        BootSourceKind::WindowsIso => run_windows_start(
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
    }
}

struct LinuxBootSource<'a> {
    kernel_path: &'a str,
    initrd_path: &'a str,
    boot_params: &'a str,
}

struct WindowsBootSource<'a> {
    bootmgr_path: &'a str,
    bcd_path: &'a str,
    boot_sdi_path: &'a str,
    boot_wim_path: &'a str,
}

fn linux_boot_source(profile: &BootProfile) -> Result<LinuxBootSource<'_>, String> {
    match &profile.source {
        BootSource::Linux {
            kernel_path,
            initrd_path,
            boot_params,
        } => Ok(LinuxBootSource {
            kernel_path,
            initrd_path,
            boot_params,
        }),
        _ => Err("error: boot source does not provide Linux kernel/initrd metadata".to_string()),
    }
}

fn windows_boot_source(profile: &BootProfile) -> Result<WindowsBootSource<'_>, String> {
    match &profile.source {
        BootSource::Windows {
            bootmgr_path,
            bcd_path,
            boot_sdi_path,
            boot_wim_path,
            ..
        } => Ok(WindowsBootSource {
            bootmgr_path,
            bcd_path,
            boot_sdi_path,
            boot_wim_path,
        }),
        _ => Err("error: boot source does not provide Windows boot metadata".to_string()),
    }
}

fn run_http_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: BootProfile,
) -> Result<RuntimeSession, String> {
    let arch = require_known_architecture(profile.architecture)?;
    let serial_console = arch
        .serial_console()
        .ok_or_else(|| "error: unsupported serial console for architecture: unknown".to_string())?;
    let linux = linux_boot_source(&profile)?;

    let file_bytes: HashMap<String, Bytes> = load_all_files(&source_path)
        .map_err(|err| profile_error(&source_path, err))?
        .into_iter()
        .map(|(file_path, content)| (file_path, Bytes::from(content)))
        .collect();

    let kernel = file_bytes
        .get(linux.kernel_path)
        .ok_or_else(|| format!("error: kernel not found at {}", linux.kernel_path))?
        .clone();
    let initrd = file_bytes
        .get(linux.initrd_path)
        .ok_or_else(|| format!("error: initrd not found at {}", linux.initrd_path))?
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

    let mut boot_params = linux.boot_params.to_string();
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
    profile: BootProfile,
) -> Result<RuntimeSession, String> {
    if !is_iso(&source_path) {
        return Err("error: Ubuntu live ISO boot requires an ISO source".to_string());
    }

    let arch = require_known_architecture(profile.architecture)?;
    let serial_console = arch
        .serial_console()
        .ok_or_else(|| "error: unsupported serial console for architecture: unknown".to_string())?;
    let linux = linux_boot_source(&profile)?;

    let kernel = load_file(&source_path, linux.kernel_path)
        .map_err(|err| profile_error(&source_path, err))?;
    let initrd = load_file(&source_path, linux.initrd_path)
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
    profile: BootProfile,
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
    profile: BootProfile,
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
    profile: BootProfile,
) -> Result<RuntimeSession, String> {
    let arch = require_known_architecture(profile.architecture)?;
    if arch != Architecture::Amd64 {
        return Err(
            "error: Windows PXE currently supports x86_64 UEFI only; arm64 Windows PXE is not supported"
                .to_string(),
        );
    }

    ensure_wimlib_available()?;
    let windows = windows_boot_source(&profile)?;
    let cached_wimboot = fetch_wimboot()?;
    let prepared_boot_wim =
        prepare_windows_boot_wim(&source_path, windows.boot_wim_path, network.ip)?;

    let mut assets = HashMap::new();
    add_windows_iso_asset(
        &mut assets,
        &source_path,
        "/windows/bootmgr",
        windows.bootmgr_path,
    )?;
    add_windows_iso_asset(
        &mut assets,
        &source_path,
        "/windows/boot/bcd",
        windows.bcd_path,
    )?;
    add_windows_iso_asset(
        &mut assets,
        &source_path,
        "/windows/boot/boot.sdi",
        windows.boot_sdi_path,
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
    let slice =
        load_file_slice(source_path, iso_path).map_err(|err| profile_error(source_path, err))?;
    assets.insert(
        http_path.to_string(),
        HttpAsset::IsoSlice {
            content_type: "application/octet-stream",
            path: source_path.to_path_buf(),
            offset: slice.offset,
            length: slice.length,
        },
    );
    Ok(())
}

fn build_windows_ipxe_script(bind_ip: Ipv4Addr, http_port: u16) -> String {
    format!(
        "#!ipxe\nkernel http://{bind_ip}:{http_port}/windows/wimboot\ninitrd http://{bind_ip}:{http_port}/windows/bootmgr bootmgr\ninitrd http://{bind_ip}:{http_port}/windows/boot/bcd BCD\ninitrd http://{bind_ip}:{http_port}/windows/boot/boot.sdi boot.sdi\ninitrd http://{bind_ip}:{http_port}/windows/sources/boot.wim boot.wim\nboot\n"
    )
}

fn ensure_wimlib_available() -> Result<(), String> {
    let status = Command::new("wimlib-imagex")
        .arg("--version")
        .status()
        .map_err(|_| {
            "error: wimlib-imagex required for Windows boot — install with: brew install wimlib"
                .to_string()
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(
            "error: wimlib-imagex required for Windows boot — install with: brew install wimlib"
                .to_string(),
        )
    }
}

fn prepare_windows_boot_wim(
    source_path: &Path,
    boot_wim_path: &str,
    server_ip: Ipv4Addr,
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

    let cache_dir = PathBuf::from(format!("{}.pxeasy", source_path.display()));
    fs::create_dir_all(&cache_dir)
        .map_err(|err| format!("error: failed to create Windows cache dir: {err}"))?;

    let cached_wim = cache_dir.join("boot.wim");
    let cached_meta = cache_dir.join("boot.wim.meta");
    let expected_meta = format!(
        "size={}\nmtime={modified_secs}\nserver_ip={server_ip}\n",
        source_metadata.len()
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
    let boot_wim_bytes =
        load_file(source_path, boot_wim_path).map_err(|err| profile_error(source_path, err))?;

    fs::write(&temp_boot_wim, boot_wim_bytes)
        .map_err(|err| format!("error: failed to write temporary boot.wim: {err}"))?;
    fs::write(&startnet_cmd, windows_startnet_cmd(server_ip))
        .map_err(|err| format!("error: failed to write startnet.cmd: {err}"))?;

    let command = format!(
        "add {} /Windows/System32/startnet.cmd",
        startnet_cmd.display()
    );
    let status = Command::new("wimlib-imagex")
        .arg("update")
        .arg(&temp_boot_wim)
        .arg("2")
        .arg("--command")
        .arg(command)
        .status()
        .map_err(|err| format!("error: failed to run wimlib-imagex: {err}"))?;
    if !status.success() {
        return Err(format!(
            "error: wimlib-imagex failed to prepare Windows boot.wim: {status}"
        ));
    }

    fs::copy(&temp_boot_wim, &cached_wim)
        .map_err(|err| format!("error: failed to cache prepared boot.wim: {err}"))?;
    fs::write(&cached_meta, expected_meta)
        .map_err(|err| format!("error: failed to write boot.wim cache metadata: {err}"))?;

    Ok(cached_wim)
}

fn windows_startnet_cmd(server_ip: Ipv4Addr) -> String {
    format!(
        "@echo off\r\nwpeinit\r\nnet use Z: \\\\{server_ip}\\{WINDOWS_SHARE_NAME} /persistent:no\r\nZ:\\setup.exe\r\n"
    )
}

fn fetch_wimboot() -> Result<PathBuf, String> {
    let cache_dir = pxeasy_cache_dir()?.join("cache");
    fs::create_dir_all(&cache_dir)
        .map_err(|err| format!("error: failed to create wimboot cache dir: {err}"))?;

    let cached_wimboot = cache_dir.join("wimboot");
    if cached_wimboot.exists() {
        return Ok(cached_wimboot);
    }

    let output_path = cached_wimboot
        .to_str()
        .ok_or("error: wimboot cache path contains non-UTF-8 characters")?;
    let status = Command::new("curl")
        .args([
            "-fsSL",
            "https://github.com/ipxe/wimboot/releases/latest/download/wimboot",
            "-o",
            output_path,
        ])
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
