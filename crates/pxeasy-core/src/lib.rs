use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchitectureSummary {
    Unknown,
    Amd64,
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKindSummary {
    UbuntuLiveIso,
    DebianInstallerIso,
    DebianNetboot,
    FreeBSDBootOnly,
    WindowsIso,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub label: String,
    pub architecture: ArchitectureSummary,
    pub source_kind: SourceKindSummary,
}

#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub source_path: PathBuf,
    pub interface: Option<String>,
    pub bind_ip: Option<Ipv4Addr>,
    pub ipxe_boot_file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
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

#[derive(Debug, Clone)]
pub enum SessionState {
    Running(Box<SessionInfo>),
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    StateChanged(SessionState),
}

pub struct AppController;

impl Default for AppController {
    fn default() -> Self {
        Self::new()
    }
}

impl AppController {
    pub fn new() -> Self {
        Self
    }

    pub fn inspect_source(&self, source_path: &Path) -> Result<ResolvedSource, String> {
        let resolved = pxeasy_runtime::inspect_source(source_path)?;
        Ok(ResolvedSource {
            label: resolved.label,
            architecture: match resolved.architecture {
                pxeasy_runtime::Architecture::Unknown => ArchitectureSummary::Unknown,
                pxeasy_runtime::Architecture::Amd64 => ArchitectureSummary::Amd64,
                pxeasy_runtime::Architecture::Arm64 => ArchitectureSummary::Arm64,
            },
            source_kind: match resolved.source_kind {
                pxeasy_runtime::BootSourceKind::UbuntuLiveIso => SourceKindSummary::UbuntuLiveIso,
                pxeasy_runtime::BootSourceKind::DebianInstallerIso => {
                    SourceKindSummary::DebianInstallerIso
                }
                pxeasy_runtime::BootSourceKind::DebianNetboot => SourceKindSummary::DebianNetboot,
                pxeasy_runtime::BootSourceKind::FreeBSDBootOnly => {
                    SourceKindSummary::FreeBSDBootOnly
                }
                pxeasy_runtime::BootSourceKind::WindowsIso => SourceKindSummary::WindowsIso,
                pxeasy_runtime::BootSourceKind::Unknown => SourceKindSummary::Unknown,
            },
        })
    }

    pub fn start(&self, request: LaunchRequest) -> Result<SessionHandle, String> {
        let runtime_session = pxeasy_runtime::start(pxeasy_runtime::LaunchRequest {
            source_path: request.source_path,
            interface: request.interface,
            bind_ip: request.bind_ip,
            ipxe_boot_file: request.ipxe_boot_file,
        })?;

        let running_state =
            SessionState::Running(Box::new(SessionInfo::from(runtime_session.info())));
        let state = Arc::new(Mutex::new(running_state.clone()));
        let (event_tx, event_rx) = mpsc::channel();
        let _ = event_tx.send(AppEvent::StateChanged(running_state));

        let shutdown = runtime_session.shutdown_handle();
        let monitor_state = Arc::clone(&state);
        let monitor = thread::spawn(move || {
            let next_state = match runtime_session.wait() {
                Ok(()) => SessionState::Stopped,
                Err(err) => SessionState::Failed(err),
            };

            if let Ok(mut state) = monitor_state.lock() {
                *state = next_state.clone();
            }
            let _ = event_tx.send(AppEvent::StateChanged(next_state));
        });

        Ok(SessionHandle {
            state,
            event_rx,
            shutdown,
            monitor: Some(monitor),
        })
    }
}

pub struct SessionHandle {
    state: Arc<Mutex<SessionState>>,
    event_rx: mpsc::Receiver<AppEvent>,
    shutdown: Arc<AtomicBool>,
    monitor: Option<thread::JoinHandle<()>>,
}

impl SessionHandle {
    pub fn snapshot(&self) -> SessionState {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_else(|_| SessionState::Failed("error: session state poisoned".to_string()))
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn try_recv_event(&self) -> Result<AppEvent, mpsc::TryRecvError> {
        self.event_rx.try_recv()
    }

    pub fn recv_event_timeout(
        &self,
        timeout: Duration,
    ) -> Result<AppEvent, mpsc::RecvTimeoutError> {
        self.event_rx.recv_timeout(timeout)
    }

    pub fn wait(mut self) {
        self.stop();
        if let Some(handle) = self.monitor.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl From<&pxeasy_runtime::RuntimeInfo> for SessionInfo {
    fn from(info: &pxeasy_runtime::RuntimeInfo) -> Self {
        Self {
            label: info.label.clone(),
            interface: info.interface.clone(),
            ip: info.ip,
            dhcp_addr: info.dhcp_addr,
            tftp_addr: info.tftp_addr,
            http_addr: info.http_addr,
            nfs_addr: info.nfs_addr,
            smb_addr: info.smb_addr,
            smb_share_name: info.smb_share_name.clone(),
        }
    }
}

pub use pxeasy_runtime::{Architecture, BootSourceKind};
