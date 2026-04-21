use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use pxe_dhcp::{DhcpConfig, ProxyDhcpServer};
use pxe_http::{HttpAsset, HttpConfig, HttpServer};
use pxe_tftp::{TftpConfig, TftpServer};

const DEFAULT_DHCP_BIND_IP: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const DEFAULT_DHCP_PORT: u16 = 67;
const DEFAULT_TFTP_PORT: u16 = 69;
const DEFAULT_HTTP_PORT: u16 = 8080;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub struct CoreServers {
    http: HttpServer,
    pub http_addr: SocketAddr,
    tftp: TftpServer,
    pub tftp_addr: SocketAddr,
    dhcp: ProxyDhcpServer,
    pub dhcp_addr: SocketAddr,
}

pub struct DhcpBoot {
    pub first_stage_bootfile: String,
    pub bios_bootfile: Option<String>,
    pub x64_uefi_bootfile: Option<String>,
    pub arm64_uefi_bootfile: Option<String>,
    pub ipxe_bootfile: Option<String>,
    pub root_path: Option<String>,
}

impl CoreServers {
    pub fn bind(
        network_ip: Ipv4Addr,
        assets: HashMap<String, HttpAsset>,
        tftp_files: HashMap<String, Bytes>,
        dhcp_boot: DhcpBoot,
    ) -> Result<Self, String> {
        let http = HttpServer::bind(HttpConfig {
            bind_ip: network_ip,
            bind_port: DEFAULT_HTTP_PORT,
            assets,
        })
        .map_err(http_bind_error)?;
        let http_addr = http
            .local_addr()
            .map_err(|e| format!("error: failed to read HTTP socket address: {e}"))?;

        let tftp = TftpServer::bind(TftpConfig {
            bind_ip: network_ip,
            bind_port: DEFAULT_TFTP_PORT,
            file_map: tftp_files,
        })
        .map_err(tftp_bind_error)?;
        let tftp_addr = tftp
            .local_addr()
            .map_err(|e| format!("error: failed to read TFTP socket address: {e}"))?;

        let dhcp = ProxyDhcpServer::bind(DhcpConfig {
            bind_ip: DEFAULT_DHCP_BIND_IP,
            bind_port: DEFAULT_DHCP_PORT,
            server_ip: network_ip,
            http_port: DEFAULT_HTTP_PORT,
            first_stage_bootfile: dhcp_boot.first_stage_bootfile,
            bios_bootfile: dhcp_boot.bios_bootfile,
            x64_uefi_bootfile: dhcp_boot.x64_uefi_bootfile,
            arm64_uefi_bootfile: dhcp_boot.arm64_uefi_bootfile,
            ipxe_bootfile: dhcp_boot.ipxe_bootfile,
            root_path: dhcp_boot.root_path,
        })
        .map_err(dhcp_bind_error)?;
        let dhcp_addr = dhcp
            .local_addr()
            .map_err(|e| format!("error: failed to read DHCP socket address: {e}"))?;

        Ok(Self {
            http,
            http_addr,
            tftp,
            tftp_addr,
            dhcp,
            dhcp_addr,
        })
    }

    pub fn spawn(self, runner: &mut ServiceRunner) {
        let Self {
            http, tftp, dhcp, ..
        } = self;
        runner.spawn("HTTP", move |sd| http.serve_until_shutdown(sd));
        runner.spawn("DHCP", move |sd| dhcp.serve_until_shutdown(sd));
        runner.spawn("TFTP", move |sd| tftp.serve_until_shutdown(sd));
    }
}

enum ServiceEvent {
    Failed(&'static str, String),
}

pub struct ServiceRunner {
    shutdown: Arc<AtomicBool>,
    event_tx: mpsc::Sender<ServiceEvent>,
    event_rx: mpsc::Receiver<ServiceEvent>,
    handles: Vec<(&'static str, thread::JoinHandle<()>)>,
}

impl ServiceRunner {
    pub fn new(shutdown: Arc<AtomicBool>) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            shutdown,
            event_tx,
            event_rx,
            handles: Vec::new(),
        }
    }

    pub fn spawn<F, E>(&mut self, name: &'static str, f: F)
    where
        F: FnOnce(&Arc<AtomicBool>) -> Result<(), E> + Send + 'static,
        E: std::fmt::Display,
    {
        let shutdown = Arc::clone(&self.shutdown);
        let tx = self.event_tx.clone();
        let handle = thread::spawn(move || {
            if let Err(err) = f(&shutdown) {
                let _ = tx.send(ServiceEvent::Failed(name, err.to_string()));
            }
        });
        self.handles.push((name, handle));
    }

    pub fn run(self) -> Result<(), String> {
        let mut failure = None;
        while !self.shutdown.load(Ordering::SeqCst) {
            match self.event_rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
                Ok(ServiceEvent::Failed(service, err)) => {
                    self.shutdown.store(true, Ordering::SeqCst);
                    failure = Some(format!("error: {service} server failed: {err}"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        for (name, handle) in self.handles {
            handle
                .join()
                .map_err(|_| format!("error: {name} worker thread panicked"))?;
        }

        failure.map_or(Ok(()), Err)
    }
}

fn dhcp_bind_error(err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => {
            "error: failed to bind DHCP socket on UDP port 67; re-run as root".to_string()
        }
        std::io::ErrorKind::AddrInUse => {
            "error: UDP port 67 is already in use; stop the existing DHCP service".to_string()
        }
        _ => format!("error: failed to bind DHCP socket: {err}"),
    }
}

fn tftp_bind_error(err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => {
            "error: failed to bind TFTP socket on UDP port 69; re-run as root".to_string()
        }
        std::io::ErrorKind::AddrInUse => {
            "error: UDP port 69 is already in use; stop the existing TFTP service".to_string()
        }
        _ => format!("error: failed to bind TFTP socket: {err}"),
    }
}

fn http_bind_error(err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::AddrInUse => {
            "error: TCP port 8080 is already in use; stop the existing HTTP service".to_string()
        }
        _ => format!("error: failed to bind HTTP socket: {err}"),
    }
}
