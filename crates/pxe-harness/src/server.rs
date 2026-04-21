use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

const READY_PATTERN: &str = "Ready — waiting for PXE clients";
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_LOG_LINES: usize = 400;

pub struct ServerHandle {
    child: Child,
    tail: Arc<Mutex<VecDeque<String>>>,
    lines_rx: mpsc::Receiver<String>,
}

impl ServerHandle {
    pub fn start_with_sudo(
        pxeasy_bin: &Path,
        source_path: &Path,
        extra_env: &[(&str, &str)],
        interrupted: &Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut command = Command::new("sudo");
        command.arg("-n").arg("env").arg(format!(
            "RUST_LOG={}",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".to_string())
        ));
        for (key, value) in extra_env {
            command.arg(format!("{key}={value}"));
        }
        command
            .arg(pxeasy_bin)
            .arg("start")
            .arg(source_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to start pxeasy via sudo -n: {}",
                pxeasy_bin.display()
            )
        })?;

        let stdout = child.stdout.take().context("pxeasy stdout not captured")?;
        let stderr = child.stderr.take().context("pxeasy stderr not captured")?;
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES)));
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (lines_tx, lines_rx) = mpsc::channel::<String>();

        stream_reader(
            stdout,
            "[server]",
            Arc::clone(&tail),
            Some(ready_tx.clone()),
            lines_tx.clone(),
        );
        stream_reader(
            stderr,
            "[server/err]",
            Arc::clone(&tail),
            Some(ready_tx),
            lines_tx,
        );

        let mut handle = Self {
            child,
            tail,
            lines_rx,
        };
        let start = std::time::Instant::now();
        loop {
            if interrupted.load(Ordering::SeqCst) {
                let _ = handle.stop();
                anyhow::bail!("interrupted while waiting for pxeasy to become ready");
            }
            match ready_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(()) => return Ok(handle),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if start.elapsed() >= READY_TIMEOUT {
                        let _ = handle.stop();
                        eprintln!("[pxe-harness] server log tail:");
                        for line in handle.log_tail() {
                            eprintln!("{line}");
                        }
                        anyhow::bail!(
                            "pxeasy did not become ready within {:?}; sudo may need prior authorization",
                            READY_TIMEOUT
                        );
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = handle.stop();
                    eprintln!("[pxe-harness] server log tail:");
                    for line in handle.log_tail() {
                        eprintln!("{line}");
                    }
                    anyhow::bail!("pxeasy exited before becoming ready");
                }
            }
        }
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        Ok(())
    }

    pub fn log_tail(&self) -> Vec<String> {
        self.tail
            .lock()
            .map(|tail| tail.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn recv_log_timeout(&mut self, timeout: Duration) -> Result<Option<String>> {
        match self.lines_rx.recv_timeout(timeout) {
            Ok(line) => Ok(Some(line)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(status) = self.child.try_wait()? {
                    anyhow::bail!("pxeasy exited unexpectedly with status {status}");
                }
                Ok(None)
            }
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn stream_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    prefix: &'static str,
    tail: Arc<Mutex<VecDeque<String>>>,
    ready_tx: Option<mpsc::Sender<()>>,
    lines_tx: mpsc::Sender<String>,
) {
    thread::spawn(move || {
        let mut ready_tx = ready_tx;
        for line in BufReader::new(reader).lines().map_while(|line| line.ok()) {
            let formatted = format!("{prefix} {line}");
            eprintln!("{formatted}");
            push_log(&tail, formatted);
            let _ = lines_tx.send(line.clone());
            if line.contains(READY_PATTERN) {
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(());
                }
            }
        }
    });
}

fn push_log(tail: &Arc<Mutex<VecDeque<String>>>, line: String) {
    if let Ok(mut tail) = tail.lock() {
        if tail.len() == MAX_LOG_LINES {
            tail.pop_front();
        }
        tail.push_back(line);
    }
}
