use std::{
    collections::HashMap,
    env, io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use if_addrs::{get_if_addrs, IfAddr};
use pxe_dhcp::{DhcpConfig, ProxyDhcpServer};
use pxe_http::{HttpAsset, HttpConfig, HttpServer};
use pxe_iscsi::{build_direct_boot_script, IscsiServer};
use pxe_nbd::{NbdConfig, NbdServer, NBD_PORT};
use pxe_nfs::{NfsConfig, NfsServer};
use pxe_profiles::{
    detect_profile, list_files, load_all_files, load_file, load_file_slice, ubuntu, BootSourceKind,
    ProfileError,
};
use pxe_tftp::{TftpConfig, TftpServer};
use serde::{Deserialize, Serialize};

const DEFAULT_DHCP_BIND_IP: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const DEFAULT_DHCP_PORT: u16 = 67;
const DEFAULT_TFTP_PORT: u16 = 69;
const DEFAULT_HTTP_PORT: u16 = 8080;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum StorageMode {
    Http,
    Iscsi,
    Nbd,
    Nfs,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();
    match parse_args(env::args_os())? {
        CliCommand::Start(command) => run_start(command),
        CliCommand::ConfigWrite(command) => run_config_write(command),
        CliCommand::Daemon(command) => run_daemon(command),
    }
}

fn run_start(command: StartCommand) -> Result<(), String> {
    let network = resolve_network(command.interface.as_deref(), command.bind_ip)?;
    let profile = detect_profile(&command.source_path)
        .map_err(|err| profile_error(&command.source_path, err))?;
    let storage_mode = command.storage_mode.unwrap_or_else(default_storage_mode);

    if storage_mode == StorageMode::Iscsi {
        return run_iscsi_start(command, network, profile);
    }

    if storage_mode == StorageMode::Nbd {
        return run_nbd_start(command, network, profile);
    }

    if storage_mode == StorageMode::Nfs {
        return run_nfs_start(command, network, profile);
    }

    let efi_path = profile
        .efi_path
        .as_ref()
        .ok_or_else(|| "error: no EFI loader found in boot source".to_string())?;

    println!("[pxeasy] Loading files from source...");
    let mut file_bytes = HashMap::new();
    for (file_path, content) in load_all_files(&command.source_path)
        .map_err(|err| profile_error(&command.source_path, err))?
    {
        file_bytes.insert(file_path, Bytes::from(content));
    }

    let kernel = file_bytes
        .get(&profile.kernel_path)
        .ok_or_else(|| format!("error: kernel not found at {}", profile.kernel_path))?
        .clone();
    let initrd = file_bytes
        .get(&profile.initrd_path)
        .ok_or_else(|| format!("error: initrd not found at {}", profile.initrd_path))?
        .clone();

    let mut assets = HashMap::new();
    let mut tftp_files = HashMap::new();

    let arch = if efi_path.contains("amd64") {
        "amd64"
    } else {
        "arm64"
    };

    let efi_dir = Path::new(efi_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let efi_dir_prefix = if efi_dir.is_empty() || efi_dir == "/" {
        String::new()
    } else {
        format!("{}/", efi_dir.trim_start_matches('/'))
    };

    // Map all discovered files efficiently
    for (file_path, content) in file_bytes {
        let rel_path = file_path.trim_start_matches('/').to_string();

        // TFTP: Map to original path
        tftp_files.insert(rel_path.clone(), content.clone());
        tftp_files.insert(rel_path.to_ascii_lowercase(), content.clone());

        // TFTP: Map files in same dir as EFI loader to root (for shim chainloading grub)
        if !efi_dir_prefix.is_empty() {
            let rel_lower = rel_path.to_ascii_lowercase();
            let prefix_lower = efi_dir_prefix.to_ascii_lowercase();
            if let Some(short_lower) = rel_lower.strip_prefix(&prefix_lower) {
                // Also store the exact requested short_path into map
                tftp_files.insert(short_lower.to_string(), content.clone());
            }
        }

        // TFTP: Map without arch prefix for flatter RRQs (e.g. arm64/grub/... -> grub/...)
        if let Some(short_path) = rel_path
            .strip_prefix(arch)
            .and_then(|p| p.strip_prefix('/'))
        {
            tftp_files.insert(short_path.to_string(), content.clone());
            tftp_files.insert(short_path.to_ascii_lowercase(), content.clone());
        } else if let Some(short_path) = rel_path.strip_prefix(arch) {
            tftp_files.insert(
                short_path.trim_start_matches('/').to_string(),
                content.clone(),
            );
            tftp_files.insert(
                short_path.trim_start_matches('/').to_ascii_lowercase(),
                content.clone(),
            );
        }

        // TFTP: Map /boot/grub/... to grub/...
        if let Some(short_path) = rel_path.strip_prefix("boot/") {
            tftp_files.insert(short_path.to_string(), content.clone());
            tftp_files.insert(short_path.to_ascii_lowercase(), content.clone());
        }

        // HTTP: Expose under /boot/
        assets.insert(
            format!("/boot/{}", rel_path),
            HttpAsset::Memory {
                content_type: "application/octet-stream",
                data: content,
            },
        );
    }

    // Ensure kernel/initrd are at root for GRUB (TFTP) and at /boot/linux,
    // /boot/initrd for iPXE (HTTP) — the iPXE script references these paths.
    let kernel_bytes = kernel.clone();
    let initrd_bytes = initrd.clone();
    tftp_files.insert("linux".to_string(), kernel_bytes.clone());
    tftp_files.insert("vmlinuz".to_string(), kernel_bytes.clone());
    tftp_files.insert("initrd".to_string(), initrd_bytes.clone());
    tftp_files.insert("initrd.gz".to_string(), initrd_bytes.clone());
    assets.insert(
        "/boot/linux".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: kernel_bytes,
        },
    );
    assets.insert(
        "/boot/initrd".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: initrd_bytes,
        },
    );

    // Use iPXE as the first-stage handoff for all netboot flows. That keeps the
    // smoke path consistent across architectures and avoids baking in source-
    // specific EFI loader behavior.
    let ipxe_payload = fetch_ipxe(arch)?;
    tftp_files.insert("ipxe.efi".to_string(), Bytes::from(ipxe_payload));
    let first_stage = "ipxe.efi".to_string();
    let ipxe_script = Some("boot.ipxe".to_string());

    let mut boot_params = match profile.source_kind {
        BootSourceKind::UbuntuLiveIso if is_iso(&command.source_path) => {
            ubuntu::netboot_boot_params(network.ip, DEFAULT_HTTP_PORT)
        }
        BootSourceKind::UbuntuNetboot => ubuntu::netboot_boot_params(network.ip, DEFAULT_HTTP_PORT),
        _ => profile.boot_params.clone(),
    };

    let is_ubuntu_iso =
        is_iso(&command.source_path) && profile.distro == pxe_profiles::Distro::Ubuntu;
    if is_ubuntu_iso {
        let mirror_uri = format!("http://{}:{}/ubuntu", network.ip, DEFAULT_HTTP_PORT);
        let user_data = ubuntu::build_nocloud_user_data(&mirror_uri);
        let meta_data = ubuntu::build_nocloud_meta_data();
        assets.insert(
            "/seed/user-data".to_string(),
            HttpAsset::Memory {
                content_type: "text/cloud-config; charset=utf-8",
                data: Bytes::from(user_data),
            },
        );
        assets.insert(
            "/seed/meta-data".to_string(),
            HttpAsset::Memory {
                content_type: "text/plain; charset=utf-8",
                data: Bytes::from(meta_data),
            },
        );

        for file_path in list_files(&command.source_path, "/")
            .map_err(|err| profile_error(&command.source_path, err))?
        {
            if !ubuntu::should_stream_repo_path(&file_path) {
                continue;
            }

            let slice = load_file_slice(&command.source_path, &file_path)
                .map_err(|err| profile_error(&command.source_path, err))?;
            let rel_path = file_path.trim_start_matches('/').to_string();
            assets.insert(
                format!("/ubuntu/{}", rel_path),
                HttpAsset::IsoSlice {
                    content_type: "application/octet-stream",
                    path: command.source_path.clone(),
                    offset: slice.offset,
                    length: slice.length,
                },
            );
        }
    }

    // Always include dual consoles (VGA + Serial) to support both physical hardware
    // and headless integration testing/debugging.
    if !boot_params.contains("console=") {
        if !boot_params.is_empty() {
            boot_params.push(' ');
        }
        let serial = if arch == "amd64" { "ttyS0" } else { "ttyAMA0" };
        boot_params.push_str(&format!("console=tty0 console={},115200n8", serial));
    }

    let ipxe_script_content =
        ubuntu::build_ipxe_script(network.ip, DEFAULT_HTTP_PORT, &boot_params);
    let ipxe_script_bytes = Bytes::from(ipxe_script_content);
    assets.insert(
        "/boot.ipxe".to_string(),
        HttpAsset::Memory {
            content_type: "text/plain",
            data: ipxe_script_bytes,
        },
    );

    let grub_cfg = ubuntu::build_grub_cfg(&profile.label, &boot_params);
    let grub_cfg_bytes = Bytes::from(grub_cfg);

    for path in &[
        "grub.cfg",
        "grub/grub.cfg",
        "boot/grub/grub.cfg",
        "EFI/BOOT/grub.cfg",
        "efi/boot/grub.cfg",
        "ubuntu/grub.cfg",
        "grubaa64.cfg",
        "grubx64.cfg",
        "boot/grub/grubaa64.cfg",
    ] {
        tftp_files.insert(path.to_string(), grub_cfg_bytes.clone());
    }

    assets.insert(
        "/grub.cfg".to_string(),
        HttpAsset::Memory {
            content_type: "text/plain",
            data: grub_cfg_bytes,
        },
    );

    let http_server = HttpServer::bind(HttpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_HTTP_PORT,
        assets,
    })
    .map_err(http_bind_error)?;

    let http_addr = http_server
        .local_addr()
        .map_err(|err| format!("error: failed to read HTTP socket address: {err}"))?;

    let tftp_server = TftpServer::bind(TftpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_TFTP_PORT,
        file_map: tftp_files,
    })
    .map_err(tftp_bind_error)?;
    let tftp_addr = tftp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read TFTP socket address: {err}"))?;

    let dhcp_server = ProxyDhcpServer::bind(DhcpConfig {
        bind_ip: DEFAULT_DHCP_BIND_IP,
        bind_port: DEFAULT_DHCP_PORT,
        server_ip: network.ip,
        http_port: DEFAULT_HTTP_PORT,
        first_stage_bootfile: first_stage,
        ipxe_bootfile: ipxe_script,
    })
    .map_err(dhcp_bind_error)?;
    let dhcp_addr = dhcp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read DHCP socket address: {err}"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    let (event_tx, event_rx) = mpsc::channel();

    let http_shutdown = Arc::clone(&shutdown);
    let http_tx = event_tx.clone();
    let http_handle = thread::spawn(move || {
        if let Err(err) = http_server.serve_until_shutdown(&http_shutdown) {
            let _ = http_tx.send(ServiceEvent::Failed("HTTP", err.to_string()));
        }
    });

    let dhcp_shutdown = Arc::clone(&shutdown);
    let dhcp_tx = event_tx.clone();
    let dhcp_handle = thread::spawn(move || {
        if let Err(err) = dhcp_server.serve_until_shutdown(&dhcp_shutdown) {
            let _ = dhcp_tx.send(ServiceEvent::Failed("DHCP", err.to_string()));
        }
    });

    let tftp_shutdown = Arc::clone(&shutdown);
    let tftp_tx = event_tx.clone();
    let tftp_handle = thread::spawn(move || {
        if let Err(err) = tftp_server.serve_until_shutdown(&tftp_shutdown) {
            let _ = tftp_tx.send(ServiceEvent::Failed("TFTP", err.to_string()));
        }
    });

    println!("[pxeasy] Detected: {}", profile.label);
    println!("[pxeasy] Interface: {} ({})", network.name, network.ip);
    println!("[pxeasy] DHCP:      listening on {}", dhcp_addr);
    println!("[pxeasy] TFTP:      listening on {}", tftp_addr);
    println!("[pxeasy] HTTP:      http://{}", http_addr);
    println!("[pxeasy] Ready — waiting for PXE clients");

    let mut failure = None;
    while !shutdown.load(Ordering::SeqCst) {
        match event_rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(ServiceEvent::Failed(service, err)) => {
                shutdown.store(true, Ordering::SeqCst);
                failure = Some(format!("error: {service} server failed: {err}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    http_handle
        .join()
        .map_err(|_| "error: HTTP worker thread panicked".to_string())?;
    dhcp_handle
        .join()
        .map_err(|_| "error: DHCP worker thread panicked".to_string())?;
    tftp_handle
        .join()
        .map_err(|_| "error: TFTP worker thread panicked".to_string())?;

    if let Some(message) = failure {
        return Err(message);
    }

    Ok(())
}

fn run_iscsi_start(
    command: StartCommand,
    network: NetworkSelection,
    profile: pxe_profiles::BootProfile,
) -> Result<(), String> {
    if !is_iso(&command.source_path) {
        return Err("error: iSCSI storage mode requires an ISO source".to_string());
    }

    let efi_path = profile
        .efi_path
        .as_ref()
        .ok_or_else(|| "error: no EFI loader found in boot source".to_string())?;

    let arch = if efi_path.contains("amd64") {
        "amd64"
    } else {
        "arm64"
    };

    let kernel = load_file(&command.source_path, &profile.kernel_path)
        .map_err(|err| profile_error(&command.source_path, err))?;
    let initrd = load_file(&command.source_path, &profile.initrd_path)
        .map_err(|err| profile_error(&command.source_path, err))?;

    let iscsi = IscsiServer::bind(&command.source_path, network.ip, &profile.label)
        .map_err(|err| err.to_string())?;
    let iscsi_addr = iscsi
        .local_addr()
        .map_err(|err| format!("error: failed to read iSCSI socket address: {err}"))?;
    let serial_console = if arch == "amd64" { "ttyS0" } else { "ttyAMA0" };
    let ipxe_script_content = build_direct_boot_script(
        network.ip,
        DEFAULT_HTTP_PORT,
        iscsi.target_name(),
        0,
        serial_console,
    );
    let ipxe_script_bytes = Bytes::from(ipxe_script_content);

    let mut assets = HashMap::new();
    assets.insert(
        "/boot/linux".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(kernel),
        },
    );
    assets.insert(
        "/boot/initrd".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(initrd),
        },
    );
    assets.insert(
        "/boot.ipxe".to_string(),
        HttpAsset::Memory {
            content_type: "text/plain",
            data: ipxe_script_bytes,
        },
    );

    let mut tftp_files = HashMap::new();
    let ipxe_payload = fetch_ipxe(arch)?;
    tftp_files.insert("ipxe.efi".to_string(), Bytes::from(ipxe_payload));

    let first_stage = "ipxe.efi".to_string();
    let ipxe_script = Some("boot.ipxe".to_string());

    let http_server = HttpServer::bind(HttpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_HTTP_PORT,
        assets,
    })
    .map_err(http_bind_error)?;
    let http_addr = http_server
        .local_addr()
        .map_err(|err| format!("error: failed to read HTTP socket address: {err}"))?;

    let tftp_server = TftpServer::bind(TftpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_TFTP_PORT,
        file_map: tftp_files,
    })
    .map_err(tftp_bind_error)?;
    let tftp_addr = tftp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read TFTP socket address: {err}"))?;

    let dhcp_server = ProxyDhcpServer::bind(DhcpConfig {
        bind_ip: DEFAULT_DHCP_BIND_IP,
        bind_port: DEFAULT_DHCP_PORT,
        server_ip: network.ip,
        http_port: DEFAULT_HTTP_PORT,
        first_stage_bootfile: first_stage,
        ipxe_bootfile: ipxe_script,
    })
    .map_err(dhcp_bind_error)?;
    let dhcp_addr = dhcp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read DHCP socket address: {err}"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    let (event_tx, event_rx) = mpsc::channel();

    let http_shutdown = Arc::clone(&shutdown);
    let http_tx = event_tx.clone();
    let http_handle = thread::spawn(move || {
        if let Err(err) = http_server.serve_until_shutdown(&http_shutdown) {
            let _ = http_tx.send(ServiceEvent::Failed("HTTP", err.to_string()));
        }
    });

    let dhcp_shutdown = Arc::clone(&shutdown);
    let dhcp_tx = event_tx.clone();
    let dhcp_handle = thread::spawn(move || {
        if let Err(err) = dhcp_server.serve_until_shutdown(&dhcp_shutdown) {
            let _ = dhcp_tx.send(ServiceEvent::Failed("DHCP", err.to_string()));
        }
    });

    let tftp_shutdown = Arc::clone(&shutdown);
    let tftp_tx = event_tx.clone();
    let tftp_handle = thread::spawn(move || {
        if let Err(err) = tftp_server.serve_until_shutdown(&tftp_shutdown) {
            let _ = tftp_tx.send(ServiceEvent::Failed("TFTP", err.to_string()));
        }
    });

    let iscsi_shutdown = Arc::clone(&shutdown);
    let iscsi_tx = event_tx.clone();
    let iscsi_handle = thread::spawn(move || {
        if let Err(err) = iscsi.serve_until_shutdown(&iscsi_shutdown) {
            let _ = iscsi_tx.send(ServiceEvent::Failed("iSCSI", err.to_string()));
        }
    });

    println!("[pxeasy] Detected: {}", profile.label);
    println!("[pxeasy] Interface: {} ({})", network.name, network.ip);
    println!("[pxeasy] DHCP:      listening on {}", dhcp_addr);
    println!("[pxeasy] TFTP:      listening on {}", tftp_addr);
    println!("[pxeasy] HTTP:      http://{}", http_addr);
    println!("[pxeasy] iSCSI:     listening on {}", iscsi_addr);
    println!("[pxeasy] Ready — waiting for PXE clients");

    let mut failure = None;
    while !shutdown.load(Ordering::SeqCst) {
        match event_rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(ServiceEvent::Failed(service, err)) => {
                shutdown.store(true, Ordering::SeqCst);
                failure = Some(format!("error: {service} server failed: {err}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    http_handle
        .join()
        .map_err(|_| "error: HTTP worker thread panicked".to_string())?;
    dhcp_handle
        .join()
        .map_err(|_| "error: DHCP worker thread panicked".to_string())?;
    tftp_handle
        .join()
        .map_err(|_| "error: TFTP worker thread panicked".to_string())?;
    iscsi_handle
        .join()
        .map_err(|_| "error: iSCSI worker thread panicked".to_string())?;

    if let Some(message) = failure {
        return Err(message);
    }

    Ok(())
}

fn run_nbd_start(
    command: StartCommand,
    network: NetworkSelection,
    profile: pxe_profiles::BootProfile,
) -> Result<(), String> {
    if !is_iso(&command.source_path) {
        return Err("error: NBD storage mode requires an ISO source".to_string());
    }

    let efi_path = profile
        .efi_path
        .as_ref()
        .ok_or_else(|| "error: no EFI loader found in boot source".to_string())?;

    let arch = if efi_path.contains("amd64") {
        "amd64"
    } else {
        "arm64"
    };

    let kernel = load_file(&command.source_path, &profile.kernel_path)
        .map_err(|err| profile_error(&command.source_path, err))?;
    let initrd = load_file(&command.source_path, &profile.initrd_path)
        .map_err(|err| profile_error(&command.source_path, err))?;

    let nbd_server = NbdServer::bind(NbdConfig {
        iso_path: command.source_path.clone(),
        bind_ip: network.ip,
        bind_port: NBD_PORT,
    })
    .map_err(|err| format!("error: failed to bind NBD server: {err}"))?;
    let nbd_addr = nbd_server
        .local_addr()
        .map_err(|err| format!("error: failed to read NBD socket address: {err}"))?;

    let serial_console = if arch == "amd64" { "ttyS0" } else { "ttyAMA0" };
    let mut boot_params = ubuntu::nbd_boot_params(network.ip, NBD_PORT);
    boot_params.push_str(&format!(" console=tty0 console={serial_console},115200n8"));

    let ipxe_script_content =
        ubuntu::build_ipxe_script(network.ip, DEFAULT_HTTP_PORT, &boot_params);

    let mut assets = HashMap::new();
    assets.insert(
        "/boot/linux".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(kernel),
        },
    );
    assets.insert(
        "/boot/initrd".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(initrd),
        },
    );
    assets.insert(
        "/boot.ipxe".to_string(),
        HttpAsset::Memory {
            content_type: "text/plain",
            data: Bytes::from(ipxe_script_content),
        },
    );

    let mut tftp_files = HashMap::new();
    let ipxe_payload = fetch_ipxe(arch)?;
    tftp_files.insert("ipxe.efi".to_string(), Bytes::from(ipxe_payload));

    let http_server = HttpServer::bind(HttpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_HTTP_PORT,
        assets,
    })
    .map_err(http_bind_error)?;
    let http_addr = http_server
        .local_addr()
        .map_err(|err| format!("error: failed to read HTTP socket address: {err}"))?;

    let tftp_server = TftpServer::bind(TftpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_TFTP_PORT,
        file_map: tftp_files,
    })
    .map_err(tftp_bind_error)?;
    let tftp_addr = tftp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read TFTP socket address: {err}"))?;

    let dhcp_server = ProxyDhcpServer::bind(DhcpConfig {
        bind_ip: DEFAULT_DHCP_BIND_IP,
        bind_port: DEFAULT_DHCP_PORT,
        server_ip: network.ip,
        http_port: DEFAULT_HTTP_PORT,
        first_stage_bootfile: "ipxe.efi".to_string(),
        ipxe_bootfile: Some("boot.ipxe".to_string()),
    })
    .map_err(dhcp_bind_error)?;
    let dhcp_addr = dhcp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read DHCP socket address: {err}"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    let (event_tx, event_rx) = mpsc::channel();

    let http_shutdown = Arc::clone(&shutdown);
    let http_tx = event_tx.clone();
    let http_handle = thread::spawn(move || {
        if let Err(err) = http_server.serve_until_shutdown(&http_shutdown) {
            let _ = http_tx.send(ServiceEvent::Failed("HTTP", err.to_string()));
        }
    });

    let dhcp_shutdown = Arc::clone(&shutdown);
    let dhcp_tx = event_tx.clone();
    let dhcp_handle = thread::spawn(move || {
        if let Err(err) = dhcp_server.serve_until_shutdown(&dhcp_shutdown) {
            let _ = dhcp_tx.send(ServiceEvent::Failed("DHCP", err.to_string()));
        }
    });

    let tftp_shutdown = Arc::clone(&shutdown);
    let tftp_tx = event_tx.clone();
    let tftp_handle = thread::spawn(move || {
        if let Err(err) = tftp_server.serve_until_shutdown(&tftp_shutdown) {
            let _ = tftp_tx.send(ServiceEvent::Failed("TFTP", err.to_string()));
        }
    });

    let nbd_shutdown = Arc::clone(&shutdown);
    let nbd_tx = event_tx.clone();
    let nbd_handle = thread::spawn(move || {
        if let Err(err) = nbd_server.serve_until_shutdown(&nbd_shutdown) {
            let _ = nbd_tx.send(ServiceEvent::Failed("NBD", err.to_string()));
        }
    });

    println!("[pxeasy] Detected: {}", profile.label);
    println!("[pxeasy] Interface: {} ({})", network.name, network.ip);
    println!("[pxeasy] DHCP:      listening on {}", dhcp_addr);
    println!("[pxeasy] TFTP:      listening on {}", tftp_addr);
    println!("[pxeasy] HTTP:      http://{}", http_addr);
    println!("[pxeasy] NBD:       listening on {}", nbd_addr);
    println!("[pxeasy] Ready — waiting for PXE clients");

    let mut failure = None;
    while !shutdown.load(Ordering::SeqCst) {
        match event_rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(ServiceEvent::Failed(service, err)) => {
                shutdown.store(true, Ordering::SeqCst);
                failure = Some(format!("error: {service} server failed: {err}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    http_handle
        .join()
        .map_err(|_| "error: HTTP worker thread panicked".to_string())?;
    dhcp_handle
        .join()
        .map_err(|_| "error: DHCP worker thread panicked".to_string())?;
    tftp_handle
        .join()
        .map_err(|_| "error: TFTP worker thread panicked".to_string())?;
    nbd_handle
        .join()
        .map_err(|_| "error: NBD worker thread panicked".to_string())?;

    if let Some(message) = failure {
        return Err(message);
    }

    Ok(())
}

fn run_nfs_start(
    command: StartCommand,
    network: NetworkSelection,
    profile: pxe_profiles::BootProfile,
) -> Result<(), String> {
    if !is_iso(&command.source_path) {
        return Err("error: NFS storage mode requires an ISO source".to_string());
    }

    let efi_path = profile
        .efi_path
        .as_ref()
        .ok_or_else(|| "error: no EFI loader found in boot source".to_string())?;

    let arch = if efi_path.contains("amd64") {
        "amd64"
    } else {
        "arm64"
    };

    let kernel = load_file(&command.source_path, &profile.kernel_path)
        .map_err(|err| profile_error(&command.source_path, err))?;
    let initrd = load_file(&command.source_path, &profile.initrd_path)
        .map_err(|err| profile_error(&command.source_path, err))?;

    let nfs_server = NfsServer::bind(NfsConfig {
        iso_path: command.source_path.clone(),
        bind_ip: network.ip,
        export_path: "/".to_string(),
    })
    .map_err(|err| format!("error: failed to bind NFS server: {err}"))?;
    let nfs_addr = nfs_server
        .nfs_local_addr()
        .map_err(|err| format!("error: failed to read NFS socket address: {err}"))?;

    let serial_console = if arch == "amd64" { "ttyS0" } else { "ttyAMA0" };
    let nfs_export_path = "/";
    let mut boot_params = ubuntu::nfs_boot_params(network.ip, nfs_export_path);
    boot_params.push_str(&format!(" console=tty0 console={serial_console},115200n8"));

    let ipxe_script_content =
        ubuntu::build_ipxe_script(network.ip, DEFAULT_HTTP_PORT, &boot_params);

    let mut assets = HashMap::new();
    assets.insert(
        "/boot/linux".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(kernel),
        },
    );
    assets.insert(
        "/boot/initrd".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(initrd),
        },
    );
    assets.insert(
        "/boot.ipxe".to_string(),
        HttpAsset::Memory {
            content_type: "text/plain",
            data: Bytes::from(ipxe_script_content),
        },
    );

    let mut tftp_files = HashMap::new();
    let ipxe_payload = fetch_ipxe(arch)?;
    tftp_files.insert("ipxe.efi".to_string(), Bytes::from(ipxe_payload));

    let http_server = HttpServer::bind(HttpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_HTTP_PORT,
        assets,
    })
    .map_err(http_bind_error)?;
    let http_addr = http_server
        .local_addr()
        .map_err(|err| format!("error: failed to read HTTP socket address: {err}"))?;

    let tftp_server = TftpServer::bind(TftpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_TFTP_PORT,
        file_map: tftp_files,
    })
    .map_err(tftp_bind_error)?;
    let tftp_addr = tftp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read TFTP socket address: {err}"))?;

    let dhcp_server = ProxyDhcpServer::bind(DhcpConfig {
        bind_ip: DEFAULT_DHCP_BIND_IP,
        bind_port: DEFAULT_DHCP_PORT,
        server_ip: network.ip,
        http_port: DEFAULT_HTTP_PORT,
        first_stage_bootfile: "ipxe.efi".to_string(),
        ipxe_bootfile: Some("boot.ipxe".to_string()),
    })
    .map_err(dhcp_bind_error)?;
    let dhcp_addr = dhcp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read DHCP socket address: {err}"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    let (event_tx, event_rx) = mpsc::channel();

    let http_shutdown = Arc::clone(&shutdown);
    let http_tx = event_tx.clone();
    let http_handle = thread::spawn(move || {
        if let Err(err) = http_server.serve_until_shutdown(&http_shutdown) {
            let _ = http_tx.send(ServiceEvent::Failed("HTTP", err.to_string()));
        }
    });

    let dhcp_shutdown = Arc::clone(&shutdown);
    let dhcp_tx = event_tx.clone();
    let dhcp_handle = thread::spawn(move || {
        if let Err(err) = dhcp_server.serve_until_shutdown(&dhcp_shutdown) {
            let _ = dhcp_tx.send(ServiceEvent::Failed("DHCP", err.to_string()));
        }
    });

    let tftp_shutdown = Arc::clone(&shutdown);
    let tftp_tx = event_tx.clone();
    let tftp_handle = thread::spawn(move || {
        if let Err(err) = tftp_server.serve_until_shutdown(&tftp_shutdown) {
            let _ = tftp_tx.send(ServiceEvent::Failed("TFTP", err.to_string()));
        }
    });

    let nfs_shutdown = Arc::clone(&shutdown);
    let nfs_tx = event_tx.clone();
    let nfs_handle = thread::spawn(move || {
        if let Err(err) = nfs_server.serve_until_shutdown(&nfs_shutdown) {
            let _ = nfs_tx.send(ServiceEvent::Failed("NFS", err.to_string()));
        }
    });

    println!("[pxeasy] Detected: {}", profile.label);
    println!("[pxeasy] Interface: {} ({})", network.name, network.ip);
    println!("[pxeasy] DHCP:      listening on {}", dhcp_addr);
    println!("[pxeasy] TFTP:      listening on {}", tftp_addr);
    println!("[pxeasy] HTTP:      http://{}", http_addr);
    println!("[pxeasy] NFS:       listening on {}", nfs_addr);
    println!("[pxeasy] Export:    {}:{}", network.ip, nfs_export_path);
    println!("[pxeasy] Ready — waiting for PXE clients");

    let mut failure = None;
    while !shutdown.load(Ordering::SeqCst) {
        match event_rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(ServiceEvent::Failed(service, err)) => {
                shutdown.store(true, Ordering::SeqCst);
                failure = Some(format!("error: {service} server failed: {err}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    http_handle
        .join()
        .map_err(|_| "error: HTTP worker thread panicked".to_string())?;
    dhcp_handle
        .join()
        .map_err(|_| "error: DHCP worker thread panicked".to_string())?;
    tftp_handle
        .join()
        .map_err(|_| "error: TFTP worker thread panicked".to_string())?;
    nfs_handle
        .join()
        .map_err(|_| "error: NFS worker thread panicked".to_string())?;

    if let Some(message) = failure {
        return Err(message);
    }

    Ok(())
}

fn run_daemon(command: DaemonCommand) -> Result<(), String> {
    let start = load_start_command_from_config(&command.config_path)?;
    run_start(start)
}

fn run_config_write(command: ConfigWriteCommand) -> Result<(), String> {
    write_daemon_config(&command.config_path, &command.start)?;
    println!(
        "[pxeasy] wrote daemon config to {}",
        command.config_path.display()
    );
    Ok(())
}

fn load_start_command_from_config(config_path: &Path) -> Result<StartCommand, String> {
    let contents = std::fs::read_to_string(config_path).map_err(|err| {
        format!(
            "error: failed to read daemon config {}: {err}",
            config_path.display()
        )
    })?;
    let config: DaemonConfigFile = toml::from_str(&contents).map_err(|err| {
        format!(
            "error: failed to parse daemon config {}: {err}",
            config_path.display()
        )
    })?;

    Ok(StartCommand {
        source_path: config.source_path,
        interface: config.interface,
        bind_ip: config.bind_ip,
        storage_mode: config.storage_mode,
    })
}

fn write_daemon_config(config_path: &Path, start: &StartCommand) -> Result<(), String> {
    let source_path = std::fs::canonicalize(&start.source_path).map_err(|err| {
        format!(
            "error: failed to resolve source path {}: {err}",
            start.source_path.display()
        )
    })?;
    let config = DaemonConfigFile {
        source_path,
        interface: start.interface.clone(),
        bind_ip: start.bind_ip,
        storage_mode: start.storage_mode,
    };
    let contents = toml::to_string_pretty(&config)
        .map_err(|err| format!("error: failed to serialize daemon config: {err}"))?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "error: failed to create config directory {}: {err}",
                parent.display()
            )
        })?;
    }

    std::fs::write(config_path, contents).map_err(|err| {
        format!(
            "error: failed to write daemon config {}: {err}",
            config_path.display()
        )
    })
}

fn fetch_ipxe(arch: &str) -> Result<Vec<u8>, String> {
    let cache_dir = std::env::temp_dir().join("pxeasy-ipxe");
    if !cache_dir.exists() {
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("error: failed to create iPXE cache dir: {e}"))?;
    }

    let url = match arch {
        "x86_64" | "amd64" => "https://boot.ipxe.org/snponly.efi",
        "aarch64" | "arm64" => "https://boot.ipxe.org/arm64-efi/snponly.efi",
        _ => return Err(format!("error: unsupported iPXE architecture: {arch}")),
    };

    let local_path = cache_dir.join(format!("snponly-{arch}.efi"));

    if !local_path.exists() {
        println!("[pxeasy] Downloading iPXE payload from {}", url);
        let status = std::process::Command::new("curl")
            .args(["-sL", url, "-o", local_path.to_str().unwrap()])
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

struct StartCommand {
    source_path: PathBuf,
    interface: Option<String>,
    bind_ip: Option<Ipv4Addr>,
    storage_mode: Option<StorageMode>,
}

struct ConfigWriteCommand {
    config_path: PathBuf,
    start: StartCommand,
}

struct DaemonCommand {
    config_path: PathBuf,
}

enum CliCommand {
    Start(StartCommand),
    ConfigWrite(ConfigWriteCommand),
    Daemon(DaemonCommand),
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonConfigFile {
    source_path: PathBuf,
    interface: Option<String>,
    bind_ip: Option<Ipv4Addr>,
    storage_mode: Option<StorageMode>,
}

struct NetworkSelection {
    name: String,
    ip: Ipv4Addr,
}

enum ServiceEvent {
    Failed(&'static str, String),
}

fn parse_args<I>(args: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut iter = args.into_iter();
    let _program = iter.next();

    let Some(command) = iter.next() else {
        return Err(usage_error("missing command"));
    };
    match command.to_string_lossy().as_ref() {
        "start" => {
            let start = parse_start_command(iter)?;
            Ok(CliCommand::Start(start))
        }
        "config" => {
            let Some(action) = iter.next() else {
                return Err(usage_error("missing config action"));
            };
            match action.to_string_lossy().as_ref() {
                "write" => {
                    let (config_path, start) = parse_config_write_args(iter)?;
                    Ok(CliCommand::ConfigWrite(ConfigWriteCommand {
                        config_path,
                        start,
                    }))
                }
                other => Err(usage_error(&format!("unsupported config action: {other}"))),
            }
        }
        "daemon" => {
            let config_path = parse_config_path(iter)?;
            Ok(CliCommand::Daemon(DaemonCommand { config_path }))
        }
        _ => Err(usage_error("unsupported command")),
    }
}

fn usage_error(message: &str) -> String {
    format!(
        "error: {message}\nusage:\n  pxeasy start <source-path> [--interface <iface>] [--bind <ip>] [--storage http|iscsi|nbd|nfs]\n  pxeasy config write <source-path> [--interface <iface>] [--bind <ip>] [--storage http|iscsi|nbd|nfs] [--config <path>]\n  pxeasy daemon [--config <path>]\nnote: set RUST_LOG=debug for verbose output"
    )
}

fn parse_start_command<I>(args: I) -> Result<StartCommand, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut iter = args.into_iter();
    let Some(source_path) = iter.next() else {
        return Err(usage_error("missing <boot-source>"));
    };
    parse_start_flags(PathBuf::from(source_path), iter)
}

fn parse_start_flags<I>(source_path: PathBuf, args: I) -> Result<StartCommand, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut interface = None;
    let mut bind_ip = None;
    let mut storage_mode = None;

    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        if flag == "--interface" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --interface"));
            };
            interface = Some(
                value
                    .into_string()
                    .map_err(|_| usage_error("interface name must be valid UTF-8"))?,
            );
            continue;
        }

        if flag == "--bind" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --bind"));
            };
            let value = value
                .into_string()
                .map_err(|_| usage_error("bind address must be valid UTF-8"))?;
            bind_ip = Some(
                value
                    .parse()
                    .map_err(|_| usage_error("bind address must be a valid IPv4 address"))?,
            );
            continue;
        }

        if flag == "--storage" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --storage"));
            };
            let value = value
                .into_string()
                .map_err(|_| usage_error("storage mode must be valid UTF-8"))?;
            storage_mode = Some(parse_storage_mode(&value)?);
            continue;
        }

        return Err(usage_error(&format!(
            "unexpected argument: {}",
            flag.to_string_lossy()
        )));
    }

    Ok(StartCommand {
        source_path,
        interface,
        bind_ip,
        storage_mode,
    })
}

fn parse_config_path<I>(args: I) -> Result<PathBuf, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut config_path = default_config_path()?;
    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        if flag == "--config" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --config"));
            };
            config_path = PathBuf::from(
                value
                    .into_string()
                    .map_err(|_| usage_error("config path must be valid UTF-8"))?,
            );
            continue;
        }

        return Err(usage_error(&format!(
            "unexpected argument: {}",
            flag.to_string_lossy()
        )));
    }

    Ok(config_path)
}

fn default_config_path() -> Result<PathBuf, String> {
    match env::var_os("HOME") {
        Some(home) => Ok(PathBuf::from(home).join(".config/pxeasy/config.toml")),
        None => Ok(PathBuf::from("/var/root/.config/pxeasy/config.toml")),
    }
}

fn default_storage_mode() -> StorageMode {
    #[cfg(target_os = "linux")]
    {
        StorageMode::Nbd
    }

    #[cfg(not(target_os = "linux"))]
    {
        StorageMode::Http
    }
}

fn parse_storage_mode(value: &str) -> Result<StorageMode, String> {
    match value {
        "http" => Ok(StorageMode::Http),
        "iscsi" => Ok(StorageMode::Iscsi),
        "nbd" => Ok(StorageMode::Nbd),
        "nfs" => Ok(StorageMode::Nfs),
        other => Err(usage_error(&format!("unsupported storage mode: {other}"))),
    }
}

fn parse_config_write_args<I>(args: I) -> Result<(PathBuf, StartCommand), String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut config_path = default_config_path()?;
    let mut iter = args.into_iter();
    let Some(source_path) = iter.next() else {
        return Err(usage_error("missing <boot-source>"));
    };

    let mut start = parse_start_flags(PathBuf::from(source_path), std::iter::empty())?;
    while let Some(flag) = iter.next() {
        if flag == "--config" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --config"));
            };
            config_path = PathBuf::from(
                value
                    .into_string()
                    .map_err(|_| usage_error("config path must be valid UTF-8"))?,
            );
            continue;
        }

        if flag == "--interface" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --interface"));
            };
            start.interface = Some(
                value
                    .into_string()
                    .map_err(|_| usage_error("interface name must be valid UTF-8"))?,
            );
            continue;
        }

        if flag == "--bind" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --bind"));
            };
            let value = value
                .into_string()
                .map_err(|_| usage_error("bind address must be valid UTF-8"))?;
            start.bind_ip = Some(
                value
                    .parse()
                    .map_err(|_| usage_error("bind address must be a valid IPv4 address"))?,
            );
            continue;
        }

        if flag == "--storage" {
            let Some(value) = iter.next() else {
                return Err(usage_error("missing value for --storage"));
            };
            let value = value
                .into_string()
                .map_err(|_| usage_error("storage mode must be valid UTF-8"))?;
            start.storage_mode = Some(parse_storage_mode(&value)?);
            continue;
        }

        return Err(usage_error(&format!(
            "unexpected argument: {}",
            flag.to_string_lossy()
        )));
    }

    Ok((config_path, start))
}

fn resolve_network(
    interface: Option<&str>,
    bind_ip: Option<Ipv4Addr>,
) -> Result<NetworkSelection, String> {
    let interfaces =
        get_if_addrs().map_err(|err| format!("error: failed to enumerate interfaces: {err}"))?;

    let mut matches = interfaces.into_iter().filter_map(|iface| {
        if iface.is_loopback() {
            return None;
        }

        let IfAddr::V4(addr) = iface.addr else {
            return None;
        };

        if let Some(expected_name) = interface {
            if iface.name != expected_name {
                return None;
            }
        }

        if let Some(expected_ip) = bind_ip {
            if addr.ip != expected_ip {
                return None;
            }
        }

        Some(NetworkSelection {
            name: iface.name,
            ip: addr.ip,
        })
    });

    if let Some(selection) = matches.next() {
        return Ok(selection);
    }

    match (interface, bind_ip) {
        (Some(name), Some(ip)) => Err(format!(
            "error: no IPv4 address {} found on interface {}; adjust --interface/--bind",
            ip, name
        )),
        (Some(name), None) => Err(format!(
            "error: interface {} has no usable IPv4 address",
            name
        )),
        (None, Some(ip)) => Err(format!(
            "error: bind address {} does not match any non-loopback interface",
            ip
        )),
        (None, None) => Err("error: no non-loopback interface found; use --interface".to_string()),
    }
}

fn is_iso(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("iso"))
}

fn profile_error(source_path: &Path, err: ProfileError) -> String {
    match err {
        ProfileError::SourceUnreadable(_, io_err) if io_err.kind() == io::ErrorKind::NotFound => {
            format!("error: ISO not found: {}", source_path.display())
        }
        ProfileError::UnknownDistro => {
            "error: no boot profile matched — unsupported ISO".to_string()
        }
        ProfileError::SourceUnreadable(_, io_err) => {
            format!("error: boot source unreadable: {}", io_err)
        }
        ProfileError::MissingFile { path } => {
            format!("error: boot source is missing required file: {}", path)
        }
    }
}

fn install_signal_handler(shutdown: &Arc<AtomicBool>) -> Result<(), String> {
    let shutdown = Arc::clone(shutdown);
    ctrlc::set_handler(move || {
        shutdown.store(true, Ordering::SeqCst);
    })
    .map_err(|err| format!("error: failed to install Ctrl-C handler: {err}"))
}

fn dhcp_bind_error(err: io::Error) -> String {
    if err.kind() == io::ErrorKind::AddrInUse {
        return "error: cannot bind DHCP port 67 — another DHCP server may be running".to_string();
    }

    format!(
        "error: cannot bind DHCP on {}:{}: {}",
        DEFAULT_DHCP_BIND_IP, DEFAULT_DHCP_PORT, err
    )
}

fn http_bind_error(err: io::Error) -> String {
    if err.kind() == io::ErrorKind::AddrInUse {
        return "error: cannot bind HTTP port 8080".to_string();
    }

    format!(
        "error: cannot bind HTTP on 0.0.0.0:{}: {}",
        DEFAULT_HTTP_PORT, err
    )
}

fn tftp_bind_error(err: io::Error) -> String {
    if err.kind() == io::ErrorKind::AddrInUse {
        return "error: cannot bind TFTP port 69".to_string();
    }

    format!(
        "error: cannot bind TFTP on {}:{}: {}",
        DEFAULT_DHCP_BIND_IP, DEFAULT_TFTP_PORT, err
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_config_loads_start_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("pxeasy.toml");
        std::fs::write(
            &config_path,
            r#"
source_path = "/tmp/ubuntu.iso"
interface = "en0"
bind_ip = "192.168.1.10"
"#,
        )
        .expect("write config");

        let start = load_start_command_from_config(&config_path).expect("load config");
        assert_eq!(start.source_path, PathBuf::from("/tmp/ubuntu.iso"));
        assert_eq!(start.interface, Some("en0".to_string()));
        assert_eq!(start.bind_ip, Some(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn daemon_config_writes_and_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join(".config/pxeasy/config.toml");
        let source_path = dir.path().join("ubuntu.iso");
        std::fs::write(&source_path, b"iso").expect("write iso");
        let resolved_source_path = source_path.canonicalize().expect("canonicalize");
        let start = StartCommand {
            source_path: resolved_source_path.clone(),
            interface: None,
            bind_ip: None,
            storage_mode: None,
        };

        write_daemon_config(&config_path, &start).expect("write config");
        let contents = std::fs::read_to_string(&config_path).expect("read config");
        assert!(contents.contains(&format!(
            "source_path = \"{}\"",
            resolved_source_path.display()
        )));

        let loaded = load_start_command_from_config(&config_path).expect("load config");
        assert_eq!(loaded.source_path, start.source_path);
        assert_eq!(loaded.interface, None);
        assert_eq!(loaded.bind_ip, None);
    }

    #[test]
    fn config_write_command_roundtrips_default_path_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join(".config/pxeasy/config.toml");
        let source_path = dir.path().join("debian.iso");
        std::fs::write(&source_path, b"iso").expect("write iso");
        let resolved_source_path = source_path.canonicalize().expect("canonicalize");
        let command = ConfigWriteCommand {
            config_path: config_path.clone(),
            start: StartCommand {
                source_path: resolved_source_path.clone(),
                interface: Some("en0".to_string()),
                bind_ip: Some(Ipv4Addr::new(10, 0, 0, 5)),
                storage_mode: Some(StorageMode::Iscsi),
            },
        };

        run_config_write(command).expect("write config command");
        let contents = std::fs::read_to_string(&config_path).expect("read config");
        assert!(contents.contains(&format!(
            "source_path = \"{}\"",
            resolved_source_path.display()
        )));
        assert!(contents.contains("interface = \"en0\""));
        assert!(contents.contains("bind_ip = \"10.0.0.5\""));
    }
}
