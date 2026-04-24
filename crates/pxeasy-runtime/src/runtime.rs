use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

pub use pxe_profiles::{Architecture, BootSourceKind};

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
    pub info: RuntimeInfo,
    pub shutdown: Arc<AtomicBool>,
    pub worker: Option<thread::JoinHandle<Result<(), String>>>,
}

impl RuntimeSession {
    pub fn new(
        info: RuntimeInfo,
        shutdown: Arc<AtomicBool>,
        worker: thread::JoinHandle<Result<(), String>>,
    ) -> Self {
        Self {
            info,
            shutdown,
            worker: Some(worker),
        }
    }

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

#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub label: String,
    pub architecture: Architecture,
    pub source_kind: BootSourceKind,
}

#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub source_path: PathBuf,
    pub interface: Option<String>,
    pub bind_ip: Option<Ipv4Addr>,
    pub ipxe_boot_file: Option<String>,
}
