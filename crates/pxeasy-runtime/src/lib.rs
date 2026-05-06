pub mod boot;
pub mod flows;
pub mod host;
pub mod network;
pub mod runtime;
pub mod services;

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
    thread,
};

use bytes::Bytes;
use log::info;

use boot::add_ipxe_script_asset;
pub use network::{resolve_network, NetworkSelection};
use pxe_http::HttpAsset;
pub use pxe_profiles::{detect_profile, Architecture, BootProfile, BootSourceKind, ProfileError};
pub use runtime::{LaunchRequest, ResolvedSource, RuntimeInfo, RuntimeSession};
use services::{CoreServers, DhcpBoot, ServiceRunner};

pub const DEFAULT_HTTP_PORT: u16 = 8080;

pub fn inspect_source(source_path: &Path) -> Result<ResolvedSource, String> {
    let profile = resolve_profile(source_path)?;
    Ok(ResolvedSource {
        label: profile.label().to_string(),
        architecture: profile.architecture(),
        source_kind: profile.source_kind(),
    })
}

pub fn start(request: LaunchRequest) -> Result<RuntimeSession, String> {
    ensure_example_config()?;
    let network = resolve_network(request.interface.as_deref(), request.bind_ip)?;
    let profile = resolve_profile(&request.source_path)?;

    match profile {
        BootProfile::Linux(profile) => match profile.source_kind {
            pxe_profiles::BootSourceKind::UbuntuLiveIso => flows::linux::run_nfs_start(
                request.source_path,
                request.ipxe_boot_file,
                network,
                profile,
            ),
            pxe_profiles::BootSourceKind::FreeBSDBootOnly => flows::freebsd::run_freebsd_start(
                request.source_path,
                request.ipxe_boot_file,
                network,
                profile,
            ),
            _ => flows::linux::run_http_start(
                request.source_path,
                request.ipxe_boot_file,
                network,
                profile,
            ),
        },
        BootProfile::Windows(profile) => flows::windows::run_windows_start(
            request.source_path,
            request.ipxe_boot_file,
            network,
            profile,
            request.autoinstall,
        ),
    }
}

pub fn run_core_start(
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

    Ok(RuntimeSession::new(info, shutdown, worker))
}

pub fn default_ipxe_tftp_files(arch: Architecture) -> Result<HashMap<String, Bytes>, String> {
    let mut tftp_files = HashMap::new();
    tftp_files.insert("ipxe.efi".to_string(), Bytes::from(fetch_ipxe(arch, true)?));
    if matches!(arch, Architecture::Amd64) {
        tftp_files.insert(
            "ipxe.pxe".to_string(),
            Bytes::from(fetch_ipxe(arch, false)?),
        );
    }
    Ok(tftp_files)
}

pub fn is_iso(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("iso"))
}

pub fn pxeasy_home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".pxeasy"))
        .ok_or_else(|| "error: HOME is not set; cannot resolve ~/.pxeasy".to_string())
}

pub fn ensure_example_config() -> Result<(), String> {
    let home = pxeasy_home_dir()?;
    std::fs::create_dir_all(&home).map_err(|e| format!("error: failed to create home dir: {e}"))?;

    let example_path = home.join("config.example.toml");
    let content = r#"# pxeasy configuration example
# Copy this to ~/.pxeasy/config.toml to customize your setup.

# The network interface to bind to (e.g., "eth0", "en0").
# interface = "en0"

# The specific IPv4 address to bind services to.
# bind_ip = "192.168.1.10"

# The filename to serve for iPXE boot (advanced).
# ipxe_boot_file = "boot.ipxe"

# [autoinstall]
# If true, pxeasy will automatically generate autoinstall scripts (like autounattend.xml)
# for supported OSes if a custom one isn't found in ~/.pxeasy/<os>/autoinstall/.
# enabled = true

# The default user to create during installation (optional).
# username = "pxeasy"

# The password for the default user (optional).
# password = "password"

# The hostname for the installed system.
# hostname = "pxeasy-vm"

# [autoinstall.windows]
# hostname = "win-lab"

# Regional settings.
language = "en-US"
keyboard = "us"
timezone = "UTC"

# If true, the first disk found will be wiped and used for the installation.
wipe_disk = true
"#;

    std::fs::write(&example_path, content)
        .map_err(|e| format!("error: failed to write config.example.toml: {e}"))?;

    Ok(())
}

fn resolve_profile(source_path: &Path) -> Result<BootProfile, String> {
    match detect_profile(source_path) {
        Ok(profile) => Ok(profile),
        Err(err) => Err(profile_error(source_path, err)),
    }
}

pub fn profile_error(source_path: &Path, err: ProfileError) -> String {
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

pub fn require_known_architecture(arch: Architecture) -> Result<Architecture, String> {
    match arch {
        Architecture::Unknown => Err(
            "error: could not determine boot architecture from source metadata; need filename or contents that identify amd64 vs arm64".to_string(),
        ),
        _ => Ok(arch),
    }
}

fn fetch_ipxe(arch: Architecture, uefi: bool) -> Result<Vec<u8>, String> {
    let cache_dir = std::env::temp_dir().join("pxeasy-ipxe");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("error: failed to create iPXE cache dir: {e}"))?;

    let url = match (arch, uefi) {
        (Architecture::Amd64, true) => "https://boot.ipxe.org/snponly.efi",
        (Architecture::Amd64, false) => "https://boot.ipxe.org/undionly.kpxe",
        (Architecture::Arm64, true) => "https://boot.ipxe.org/arm64-efi/snponly.efi",
        _ => {
            return Err(format!(
                "error: unsupported iPXE configuration: arch={:?}, uefi={}",
                arch, uefi
            ));
        }
    };

    let arch_slug = arch
        .slug()
        .ok_or_else(|| "error: unsupported iPXE architecture: unknown".to_string())?;
    let filename = if uefi {
        format!("snponly-{arch_slug}.efi")
    } else {
        format!("undionly-{arch_slug}.kpxe")
    };
    let local_path = cache_dir.join(filename);

    if !local_path.exists() {
        info!("downloading iPXE payload from {}", url);
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

pub fn smb_bind_error(err: std::io::Error) -> String {
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
