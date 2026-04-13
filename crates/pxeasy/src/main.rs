use std::{
    collections::HashMap,
    env, fs, io,
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
use pxe_profiles::{detect_profile, ProfileError};
use pxe_tftp::{TftpConfig, TftpServer};

const DEFAULT_DHCP_BIND_IP: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const DEFAULT_DHCP_PORT: u16 = 67;
const DEFAULT_TFTP_PORT: u16 = 69;
const FIRST_STAGE_BOOTFILE: &str = "ipxe.efi";
const SECOND_STAGE_BOOTFILE: &str = "boot.ipxe";
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

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
    let command = parse_args(env::args_os())?;
    let profile =
        detect_profile(&command.iso_path).map_err(|err| profile_error(&command.iso_path, err))?;
    let network = resolve_network(command.interface.as_deref(), command.bind_ip)?;
    let ipxe_binary = load_ipxe_binary()?;

    let mut file_map = HashMap::new();
    file_map.insert(FIRST_STAGE_BOOTFILE.to_string(), Bytes::from(ipxe_binary));
    file_map.insert(
        SECOND_STAGE_BOOTFILE.to_string(),
        Bytes::from(build_prompt_script()),
    );

    let tftp_server = TftpServer::bind(TftpConfig {
        bind_ip: network.ip,
        bind_port: DEFAULT_TFTP_PORT,
        file_map,
    })
    .map_err(|err| bind_error("TFTP", network.ip, DEFAULT_TFTP_PORT, err))?;

    let dhcp_server = ProxyDhcpServer::bind(DhcpConfig {
        bind_ip: DEFAULT_DHCP_BIND_IP,
        bind_port: DEFAULT_DHCP_PORT,
        server_ip: network.ip,
        first_stage_bootfile: FIRST_STAGE_BOOTFILE.to_string(),
        second_stage_bootfile: SECOND_STAGE_BOOTFILE.to_string(),
    })
    .map_err(dhcp_bind_error)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    let (event_tx, event_rx) = mpsc::channel();
    let tftp_addr = tftp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read TFTP socket address: {err}"))?;
    let dhcp_addr = dhcp_server
        .local_addr()
        .map_err(|err| format!("error: failed to read ProxyDHCP socket address: {err}"))?;

    let tftp_shutdown = Arc::clone(&shutdown);
    let tftp_tx = event_tx.clone();
    let tftp_handle = thread::spawn(move || {
        if let Err(err) = tftp_server.serve_until_shutdown(&tftp_shutdown) {
            let _ = tftp_tx.send(ServiceEvent::Failed("TFTP", err.to_string()));
        }
    });

    let dhcp_shutdown = Arc::clone(&shutdown);
    let dhcp_tx = event_tx.clone();
    let dhcp_handle = thread::spawn(move || {
        if let Err(err) = dhcp_server.serve_until_shutdown(&dhcp_shutdown) {
            let _ = dhcp_tx.send(ServiceEvent::Failed("ProxyDHCP", err.to_string()));
        }
    });

    println!("[pxeasy] Detected: {}", profile.label);
    println!("[pxeasy] Interface: {} ({})", network.name, network.ip);
    println!("[pxeasy] ProxyDHCP: listening on {}", dhcp_addr);
    println!("[pxeasy] TFTP:      listening on {}", tftp_addr);
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

    tftp_handle
        .join()
        .map_err(|_| "error: TFTP worker thread panicked".to_string())?;
    dhcp_handle
        .join()
        .map_err(|_| "error: ProxyDHCP worker thread panicked".to_string())?;

    if let Some(message) = failure {
        return Err(message);
    }

    Ok(())
}

struct StartCommand {
    iso_path: PathBuf,
    interface: Option<String>,
    bind_ip: Option<Ipv4Addr>,
}

struct NetworkSelection {
    name: String,
    ip: Ipv4Addr,
}

enum ServiceEvent {
    Failed(&'static str, String),
}

fn parse_args<I>(args: I) -> Result<StartCommand, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut iter = args.into_iter();
    let _program = iter.next();

    let Some(command) = iter.next() else {
        return Err(usage_error("missing command"));
    };
    if command != "start" {
        return Err(usage_error("unsupported command"));
    }

    let Some(iso_path) = iter.next() else {
        return Err(usage_error("missing <iso-path>"));
    };

    let mut interface = None;
    let mut bind_ip = None;

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

        return Err(usage_error(&format!(
            "unexpected argument: {}",
            flag.to_string_lossy()
        )));
    }

    Ok(StartCommand {
        iso_path: PathBuf::from(iso_path),
        interface,
        bind_ip,
    })
}

fn usage_error(message: &str) -> String {
    format!("error: {message}\nusage: pxeasy start <iso-path> [--interface <iface>] [--bind <ip>]")
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

fn load_ipxe_binary() -> Result<Vec<u8>, String> {
    if let Ok(path) = env::var("PXEASY_IPXE_EFI") {
        return fs::read(&path)
            .map_err(|err| format!("error: cannot read PXEASY_IPXE_EFI {}: {}", path, err));
    }

    for path in ipxe_candidates() {
        if path.is_file() {
            return fs::read(&path)
                .map_err(|err| format!("error: cannot read {}: {}", path.display(), err));
        }
    }

    Err(
        "error: ipxe.efi not found; set PXEASY_IPXE_EFI or place assets/ipxe.efi in the workspace"
            .to_string(),
    )
}

fn ipxe_candidates() -> Vec<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    vec![
        manifest_dir.join("assets").join(FIRST_STAGE_BOOTFILE),
        manifest_dir
            .parent()
            .and_then(Path::parent)
            .map(|path| path.join("assets").join(FIRST_STAGE_BOOTFILE))
            .unwrap_or_else(|| PathBuf::from("assets").join(FIRST_STAGE_BOOTFILE)),
        PathBuf::from("assets").join(FIRST_STAGE_BOOTFILE),
        PathBuf::from(FIRST_STAGE_BOOTFILE),
    ]
}

fn build_prompt_script() -> Vec<u8> {
    b"#!ipxe\nshell\n".to_vec()
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
        return "error: cannot bind proxyDHCP port 67 — another DHCP server may be running"
            .to_string();
    }

    bind_error("ProxyDHCP", DEFAULT_DHCP_BIND_IP, DEFAULT_DHCP_PORT, err)
}

fn bind_error(service: &str, ip: Ipv4Addr, port: u16, err: io::Error) -> String {
    format!("error: cannot bind {service} on {ip}:{port}: {err}")
}
