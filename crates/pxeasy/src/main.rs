mod cli;

use std::{
    env,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use cli::{parse_args, CliCommand, DaemonCommand, StartCommand};
use pxeasy_core::{AppController, AppEvent, LaunchRequest, SessionInfo, SessionState};

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
        CliCommand::Daemon(command) => run_daemon(command),
    }
}

fn run_start(command: StartCommand) -> Result<(), String> {
    let controller = AppController::new();
    let session = controller.start(LaunchRequest {
        source_path: command.source_path,
        interface: command.interface,
        bind_ip: command.bind_ip,
        ipxe_boot_file: command.ipxe_boot_file,
    })?;

    let mut printed = false;
    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            session.stop();
        }

        match session.recv_event_timeout(Duration::from_millis(100)) {
            Ok(AppEvent::StateChanged(SessionState::Running(info))) => {
                if !printed {
                    print_session_info(&info);
                    printed = true;
                }
            }
            Ok(AppEvent::StateChanged(SessionState::Stopped)) => {
                session.wait();
                return Ok(());
            }
            Ok(AppEvent::StateChanged(SessionState::Failed(message))) => {
                session.wait();
                return Err(message);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let result = match session.snapshot() {
                    SessionState::Failed(message) => Err(message),
                    SessionState::Stopped => Ok(()),
                    SessionState::Running(_) => Ok(()),
                };
                session.wait();
                return result;
            }
        }
    }
}

fn run_daemon(command: DaemonCommand) -> Result<(), String> {
    run_start(StartCommand {
        source_path: command.source_path,
        interface: command.interface,
        bind_ip: command.bind_ip,
        ipxe_boot_file: command.ipxe_boot_file,
    })
}

fn install_signal_handler(shutdown: &Arc<AtomicBool>) -> Result<(), String> {
    let shutdown = Arc::clone(shutdown);
    ctrlc::set_handler(move || {
        shutdown.store(true, Ordering::SeqCst);
    })
    .map_err(|err| format!("error: failed to install Ctrl-C handler: {err}"))
}

fn print_session_info(info: &SessionInfo) {
    println!("[pxeasy] Detected: {}", info.label);
    println!("[pxeasy] Interface: {} ({})", info.interface, info.ip);
    println!("[pxeasy] DHCP:      listening on {}", info.dhcp_addr);
    println!("[pxeasy] TFTP:      listening on {}", info.tftp_addr);
    println!("[pxeasy] HTTP:      http://{}", info.http_addr);
    if let Some(nfs) = info.nfs_addr {
        println!("[pxeasy] NFS:       listening on {}", nfs);
    }
    if let (Some(smb), Some(share_name)) = (info.smb_addr, info.smb_share_name.as_deref()) {
        println!("[pxeasy] SMB:       \\\\{}\\{}", smb.ip(), share_name);
    }
    println!("[pxeasy] Ready — waiting for PXE clients");
}
