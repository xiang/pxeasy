use std::collections::HashMap;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};
use std::thread;

use bytes::Bytes;
use log::{debug, info};
use pxe_http::HttpAsset;
use pxe_profiles::{load_file, load_file_slice, Architecture, WindowsProfile};
use pxe_smb::{SmbConfig, SmbServer};
use pxe_wim::Wim;

use crate::boot::add_ipxe_script_asset;
use crate::network::NetworkSelection;
use crate::runtime::{RuntimeInfo, RuntimeSession};
use crate::services::{CoreServers, DhcpBoot, ServiceRunner};
use crate::{
    default_ipxe_tftp_files, profile_error, pxeasy_home_dir, require_known_architecture,
    smb_bind_error, DEFAULT_HTTP_PORT,
};

pub const WINDOWS_SHARE_NAME: &str = "windows";
pub const DEFAULT_SMB_PORT: u16 = 445;
const WINDOWS_SOURCE_WINPE_IMAGE: i32 = 2;
const WINDOWS_CUSTOM_WINPE_IMAGE: i32 = 1;

const DEFAULT_WINDOWS_STARTNET_TEMPLATE: &str =
    include_str!("../../../../templates/windows/startnet.cmd");
const DEFAULT_WINDOWS_WINPESHL_TEMPLATE: &str =
    include_str!("../../../../templates/windows/winpeshl.ini");
const DEFAULT_WINDOWS_BOOTSTRAP_TEMPLATE: &str =
    include_str!("../../../../templates/windows/pxeasy-bootstrap.cmd");

pub fn run_windows_start(
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
        DhcpBoot::ipxe(ipxe_boot_file),
    )?;

    let smb = SmbServer::bind(SmbConfig::new(
        network.ip,
        DEFAULT_SMB_PORT,
        WINDOWS_SHARE_NAME.to_string(),
        source_path,
    ))
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

    Ok(RuntimeSession::new(info, shutdown, worker))
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
    let startnet_script = windows_startnet_cmd()?;
    let winpeshl_ini = Some(render_windows_template(
        "winpeshl.ini",
        DEFAULT_WINDOWS_WINPESHL_TEMPLATE,
        server_ip,
    )?);
    let bootstrap_script = windows_bootstrap_cmd(server_ip, &virtio_drivers)?;

    let cache_dir = PathBuf::from(format!("{}.pxeasy", source_path.display()));
    fs::create_dir_all(&cache_dir)
        .map_err(|err| format!("error: failed to create Windows cache dir: {err}"))?;

    let cached_wim = cache_dir.join("boot.wim");
    let cached_meta = cache_dir.join("boot.wim.meta");
    let expected_meta = format!(
        "size={}\nmtime={modified_secs}\nserver_ip={server_ip}\nshare_name={WINDOWS_SHARE_NAME}\narch={}\nvirtio_drivers={}\nstartnet_hash={:016x}\nbootstrap_hash={:016x}\nwinpeshl_hash={}\nsource_image={WINDOWS_SOURCE_WINPE_IMAGE}\n",
        source_metadata.len(),
        arch.slug().unwrap_or("unknown"),
        windows_virtio_meta(&virtio_drivers),
        stable_hash(&startnet_script),
        stable_hash(&bootstrap_script),
        winpeshl_ini.as_ref().map(|s| format!("{:016x}", stable_hash(s))).unwrap_or_else(|| "none".to_string()),
    );

    if cached_wim.exists() {
        if let Ok(existing_meta) = fs::read_to_string(&cached_meta) {
            if existing_meta == expected_meta {
                debug!("using cached Windows boot image: {}", cached_wim.display());
                return Ok(cached_wim);
            }
        }
    }

    info!("preparing custom Windows boot image (this may take a minute)...");
    let tempdir = tempfile::tempdir()
        .map_err(|err| format!("error: failed to create temporary directory: {err}"))?;
    let temp_boot_wim = tempdir.path().join("boot.wim");
    let startnet_cmd = tempdir.path().join("startnet.cmd");
    let bootstrap_cmd = tempdir.path().join("pxeasy-bootstrap.cmd");
    let winpeshl_ini_path = tempdir.path().join("winpeshl.ini");
    let source_boot_wim = tempdir.path().join("source-boot.wim");

    debug!("extracting source boot.wim from ISO...");
    let boot_wim_bytes =
        load_file(source_path, boot_wim_path).map_err(|err| profile_error(source_path, err))?;

    fs::write(&source_boot_wim, boot_wim_bytes)
        .map_err(|err| format!("error: failed to write temporary source boot.wim: {err}"))?;
    fs::write(&startnet_cmd, startnet_script)
        .map_err(|err| format!("error: failed to write startnet.cmd: {err}"))?;
    fs::write(&bootstrap_cmd, bootstrap_script)
        .map_err(|err| format!("error: failed to write pxeasy-bootstrap.cmd: {err}"))?;
    if let Some(content) = &winpeshl_ini {
        debug!("writing custom winpeshl.ini to boot image...");
        fs::write(&winpeshl_ini_path, content)
            .map_err(|err| format!("error: failed to write winpeshl.ini: {err}"))?;
    }

    debug!("exporting WIM image...");
    Wim::export_image_to_new_wim(&source_boot_wim, WINDOWS_SOURCE_WINPE_IMAGE, &temp_boot_wim)?;

    let mut wim = Wim::open_for_update(&temp_boot_wim)?;
    debug!("injecting custom startnet.cmd...");
    wim.replace_file(
        WINDOWS_CUSTOM_WINPE_IMAGE,
        &startnet_cmd,
        "/Windows/System32/startnet.cmd",
    )?;
    debug!("injecting custom pxeasy-bootstrap.cmd...");
    wim.replace_file(
        WINDOWS_CUSTOM_WINPE_IMAGE,
        &bootstrap_cmd,
        "/Windows/System32/pxeasy-bootstrap.cmd",
    )?;
    if winpeshl_ini.is_some() {
        debug!("injecting custom winpeshl.ini...");
        wim.replace_file(
            WINDOWS_CUSTOM_WINPE_IMAGE,
            &winpeshl_ini_path,
            "/Windows/System32/winpeshl.ini",
        )?;
    }
    for driver in &virtio_drivers {
        debug!("injecting virtio driver: {}", driver.wim_dir);
        wim.add_tree(
            WINDOWS_CUSTOM_WINPE_IMAGE,
            &driver.host_dir,
            &driver.wim_dir,
        )?;
    }
    debug!("finalizing WIM (rebuilding)...");
    wim.overwrite()?;

    debug!("caching prepared boot image...");
    fs::copy(&temp_boot_wim, &cached_wim)
        .map_err(|err| format!("error: failed to cache prepared boot.wim: {err}"))?;
    fs::write(&cached_meta, expected_meta)
        .map_err(|err| format!("error: failed to write boot.wim cache metadata: {err}"))?;

    info!("Windows boot image prepared successfully");
    Ok(cached_wim)
}

fn windows_startnet_cmd() -> Result<String, String> {
    let template = load_windows_template("startnet.cmd", DEFAULT_WINDOWS_STARTNET_TEMPLATE)?;
    Ok(template.replace("\r\n", "\n").replace('\n', "\r\n"))
}

fn windows_bootstrap_cmd(
    server_ip: Ipv4Addr,
    virtio_drivers: &[WindowsVirtioDriver],
) -> Result<String, String> {
    let template =
        load_windows_template("pxeasy-bootstrap.cmd", DEFAULT_WINDOWS_BOOTSTRAP_TEMPLATE)?;
    let mut drvload_lines = String::new();
    for driver in virtio_drivers {
        if !driver.winpe_load {
            continue;
        }
        for inf_path in &driver.inf_paths {
            drvload_lines.push_str(&format!("drvload X:{inf_path}\n"));
        }
    }
    let post_drvload_network_init = if drvload_lines.is_empty() {
        String::new()
    } else {
        "wpeutil InitializeNetwork\n".to_string()
    };

    let script = template
        .replace("{{DRVLOAD_LINES}}", &drvload_lines)
        .replace("{{POST_DRVLOAD_NETWORK_INIT}}", &post_drvload_network_init)
        .replace("{{SERVER_IP}}", &server_ip.to_string())
        .replace("{{SHARE_NAME}}", WINDOWS_SHARE_NAME);

    Ok(script.replace("\r\n", "\n").replace('\n', "\r\n"))
}

fn render_windows_template(
    template_name: &str,
    default_template: &str,
    server_ip: Ipv4Addr,
) -> Result<String, String> {
    let template = load_windows_template(template_name, default_template)?;
    Ok(template
        .replace("{{SERVER_IP}}", &server_ip.to_string())
        .replace("{{SHARE_NAME}}", WINDOWS_SHARE_NAME)
        .replace("\r\n", "\n")
        .replace('\n', "\r\n"))
}

fn load_windows_template(template_name: &str, default_template: &str) -> Result<String, String> {
    let template_path = ensure_windows_template(template_name, default_template)?;
    fs::read_to_string(&template_path).map_err(|err| {
        format!(
            "error: failed to read Windows template {}: {err}",
            template_path.display()
        )
    })
}

fn ensure_windows_template(template_name: &str, default_template: &str) -> Result<PathBuf, String> {
    let template_dir = pxeasy_home_dir()?.join("templates/windows");
    fs::create_dir_all(&template_dir)
        .map_err(|err| format!("error: failed to create Windows template dir: {err}"))?;

    let template_path = template_dir.join(template_name);
    if !template_path.exists() {
        fs::write(&template_path, default_template).map_err(|err| {
            format!(
                "error: failed to initialize Windows template {}: {err}",
                template_path.display()
            )
        })?;
    }

    Ok(template_path)
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
    winpe_load: bool,
}

fn windows_virtio_drivers(arch: Architecture) -> Result<Vec<WindowsVirtioDriver>, String> {
    let Some(root) = windows_virtio_root()? else {
        return Ok(Vec::new());
    };
    let arch_subdir = match arch {
        Architecture::Arm64 => "ARM64",
        Architecture::Amd64 => "amd64",
        Architecture::Unknown => return Ok(Vec::new()),
    };

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

        let host_dir = entry.path().join("w11").join(arch_subdir);
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

        let name_lower = driver_name.to_lowercase();
        let winpe_load =
            name_lower == "netkvm" || name_lower == "vioscsi" || name_lower == "viostor";
        drivers.push(WindowsVirtioDriver {
            host_dir,
            wim_dir: format!("/Drivers/{driver_name}"),
            inf_paths,
            winpe_load,
        });
    }

    drivers.sort_by(|left, right| left.wim_dir.cmp(&right.wim_dir));

    Ok(drivers)
}

fn windows_virtio_root() -> Result<Option<PathBuf>, String> {
    if let Some(root) = std::env::var_os("PXEASY_WINDOWS_VIRTIO_ROOT") {
        let path = PathBuf::from(root);
        if !path.is_dir() {
            return Err(format!(
                "error: PXEASY_WINDOWS_VIRTIO_ROOT is not a directory: {}",
                path.display()
            ));
        }
        return Ok(Some(path));
    }

    let path = pxeasy_home_dir()?.join("dev/windows/virtio-win");
    if path.is_dir() {
        return Ok(Some(path));
    }

    Ok(None)
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
    let cache_dir = pxeasy_home_dir()?.join("cache");
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
    let status = std::process::Command::new("curl")
        .args(["-fsSL", url, "-o", output_path])
        .status()
        .map_err(|err| format!("error: failed to spawn curl for wimboot download: {err}"))?;
    if !status.success() {
        return Err("error: wimboot not cached — download from https://github.com/ipxe/wimboot/releases and place at ~/.pxeasy/cache/wimboot".to_string());
    }

    Ok(cached_wimboot)
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
