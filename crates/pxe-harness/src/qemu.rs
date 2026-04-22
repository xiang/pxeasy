use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pxe_qemu::{create_uefi_boot_disk, fetch_ipxe_disk_efi, QemuBuilder};

const DEFAULT_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_LOG_LINES: usize = 400;

#[derive(Clone, Copy)]
pub enum QemuScenario {
    Arm64Uefi,
}

pub struct GuestReport {
    pub duration: Duration,
}

pub fn run_guest(
    scenario: QemuScenario,
    success_pattern: &str,
    timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<GuestReport> {
    match scenario {
        QemuScenario::Arm64Uefi => run_arm64_uefi(success_pattern, timeout, interrupted),
    }
}

pub fn run_windows_arm64_manual(
    disk_path: &Path,
    interrupted: Arc<AtomicBool>,
) -> Result<GuestReport> {
    ensure_windows_disk(disk_path)?;

    let firmware = arm64_firmware()?;
    let ipxe_efi = fetch_ipxe_disk_efi("arm64")?;
    let ipxe_disk = create_uefi_boot_disk(&ipxe_efi)?;
    let vars_file = fresh_vars()?;

    let qemu_bin =
        std::env::var("PXE_HARNESS_QEMU_BIN").unwrap_or_else(|_| "qemu-system-aarch64".to_string());
    let qemu_sudo = std::env::var("PXE_HARNESS_QEMU_SUDO")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let netdev = std::env::var("PXE_HARNESS_QEMU_NETDEV")
        .unwrap_or_else(|_| "vmnet-bridged,id=net0,ifname=en0".to_string());
    let qemu_log = disk_path.with_extension("qemu.log");

    let mut cmd = if qemu_sudo {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg(&qemu_bin);
        cmd
    } else {
        Command::new(&qemu_bin)
    };
    cmd.args([
        "-machine",
        "virt",
        "-cpu",
        "host",
        "-accel",
        "hvf",
        "-smp",
        "cpus=8,sockets=1,cores=8,threads=1",
        "-m",
        "8G",
        "-boot",
        "n",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "virtio-net-pci,netdev=net0,romfile=",
        "-netdev",
        "-device",
        "qemu-xhci,id=usb-bus",
        "-device",
        "usb-tablet,bus=usb-bus.0",
        "-device",
        "usb-kbd,bus=usb-bus.0",
    ]);
    cmd.arg(&netdev);
    if cfg!(target_os = "macos") {
        cmd.args(["-display", "cocoa"]);
    } else {
        cmd.args(["-display", "gtk"]);
    }
    cmd.args(["-serial", "stdio"]);
    cmd.arg("-drive").arg(format!(
        "if=pflash,format=raw,unit=0,file={},readonly=on",
        firmware.display()
    ));
    cmd.arg("-drive").arg(format!(
        "if=pflash,format=raw,unit=1,file={}",
        vars_file.path().display()
    ));
    cmd.arg("-drive").arg(format!(
        "if=virtio,format=raw,file={}",
        ipxe_disk.path().display()
    ));
    cmd.arg("-drive").arg(format!(
        "if=none,id=installdisk,format=raw,file={}",
        disk_path.display()
    ));
    cmd.args(["-device", "nvme,serial=pxeasy0,drive=installdisk"]);
    cmd.arg("-D").arg(&qemu_log).args(["-d", "guest_errors"]);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    eprintln!(
        "[pxe-harness] launching Windows ARM64 QEMU with disk {}",
        disk_path.display()
    );
    eprintln!("[pxe-harness] qemu binary: {qemu_bin}");
    eprintln!("[pxe-harness] qemu sudo: {qemu_sudo}");
    eprintln!("[pxe-harness] qemu netdev: {netdev}");
    eprintln!("[pxe-harness] qemu debug log: {}", qemu_log.display());
    eprintln!("[pxe-harness] stop with Ctrl-C");

    let mut child = cmd
        .spawn()
        .context("failed to launch qemu-system-aarch64 via sudo -n")?;
    let start = Instant::now();

    loop {
        if interrupted.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow::anyhow!("interrupted"));
        }

        if let Some(status) = child.try_wait()? {
            anyhow::ensure!(status.success(), "QEMU exited with status {status}");
            return Ok(GuestReport {
                duration: start.elapsed(),
            });
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn run_arm64_uefi(
    success_pattern: &str,
    timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<GuestReport> {
    let firmware = arm64_firmware()?;
    let ipxe_efi = fetch_ipxe_disk_efi("arm64")?;
    let ipxe_disk = create_uefi_boot_disk(&ipxe_efi)?;
    let vars_file = fresh_vars()?;

    let qemu = attach_ipxe_disk(
        QemuBuilder::new("qemu-system-aarch64", firmware)
            .vars(vars_file.path())
            .memory("8G")
            .sudo(true)
            .args(["-machine", "virt", "-cpu", "host", "-accel", "hvf"]),
        &ipxe_disk,
    );

    run_qemu_boot(qemu, success_pattern, timeout, interrupted)
}

fn arm64_firmware() -> Result<PathBuf> {
    let homebrew_fw = PathBuf::from("/opt/homebrew/share/qemu/edk2-aarch64-code.fd");
    if homebrew_fw.exists() {
        return Ok(homebrew_fw);
    }

    let asset_fw = workspace_root().join("assets/RELEASEAARCH64_QEMU_EFI.fd");
    if asset_fw.exists() {
        return Ok(asset_fw);
    }

    anyhow::bail!(
        "no AARCH64 UEFI firmware found at {} or {}",
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "assets/RELEASEAARCH64_QEMU_EFI.fd"
    )
}

fn fresh_vars() -> Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    let buf = vec![0xFFu8; 64 * 1024 * 1024];
    file.write_all(&buf)?;
    Ok(file)
}

fn ensure_windows_disk(path: &Path) -> Result<()> {
    const DISK_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("failed to create disk image {}", path.display()))?;
    if file.metadata()?.len() < DISK_SIZE_BYTES {
        file.set_len(DISK_SIZE_BYTES)?;
    }
    Ok(())
}

fn attach_ipxe_disk(qemu: QemuBuilder, ipxe_disk: &tempfile::NamedTempFile) -> QemuBuilder {
    if cfg!(target_os = "macos") {
        qemu.arg("-netdev")
            .arg("vmnet-bridged,id=net0,ifname=en0")
            .arg("-device")
            .arg("virtio-net-pci,netdev=net0,romfile=")
            .args([
                "-drive",
                &format!("if=virtio,format=raw,file={}", ipxe_disk.path().display()),
            ])
    } else {
        qemu.arg("-netdev")
            .arg("user,id=net0")
            .arg("-device")
            .arg("virtio-net-pci,netdev=net0,romfile=")
            .args([
                "-drive",
                &format!("if=virtio,format=raw,file={}", ipxe_disk.path().display()),
            ])
    }
}

fn run_qemu_boot(
    qemu: QemuBuilder,
    success_pattern: &str,
    timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<GuestReport> {
    let mut qemu_child = qemu.spawn()?;
    let stdout = qemu_child
        .stdout
        .take()
        .context("QEMU stdout not captured")?;
    let stderr = qemu_child
        .stderr
        .take()
        .context("QEMU stderr not captured")?;

    let (tx, rx) = mpsc::channel::<String>();
    let tail = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES)));

    let tail_stdout = Arc::clone(&tail);
    let tx_stdout = tx.clone();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
            push_log(&tail_stdout, format!("[guest] {line}"));
            let _ = tx_stdout.send(line);
        }
    });

    let tail_stderr = Arc::clone(&tail);
    let tx_stderr = tx.clone();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(|line| line.ok()) {
            push_log(&tail_stderr, format!("[guest/err] {line}"));
            let _ = tx_stderr.send(line);
        }
    });
    drop(tx);

    let start = Instant::now();
    let mut last_activity = Instant::now();
    let inactivity_timeout = env_duration_secs(
        "PXE_QEMU_INACTIVITY_TIMEOUT_SECS",
        DEFAULT_INACTIVITY_TIMEOUT,
    );

    let hard_failures: &[(&str, &str)] = &[
        (
            "No bootable option or device was found",
            "UEFI: no bootable device",
        ),
        ("BootManagerMenuApp", "UEFI: dropped to Boot Manager menu"),
        (
            "UEFI Interactive Shell",
            "UEFI: dropped to interactive shell",
        ),
        ("Shell>", "UEFI: dropped to EFI shell prompt"),
        (
            "EFI Internal Shell",
            "UEFI: falling back to EFI internal shell",
        ),
        ("Press ESC in", "UEFI: startup.nsh countdown"),
        ("No mapping found", "UEFI shell: no devices found"),
        ("PXE-E", "iPXE/PXE error"),
        ("No configuration methods", "iPXE: DHCP failed"),
        ("Unable to obtain", "iPXE: network init failed"),
        ("Connection timed out", "iPXE: connection timeout"),
        ("Error 0x", "iPXE: fatal error"),
    ];

    let result = loop {
        if interrupted.load(Ordering::SeqCst) {
            break Err(anyhow::anyhow!("interrupted"));
        }

        if start.elapsed() >= timeout {
            break Err(anyhow::anyhow!(
                "timeout: pattern {:?} not seen within {:?}",
                success_pattern,
                timeout
            ));
        }

        if let Ok(Some(status)) = qemu_child.try_wait() {
            break Err(anyhow::anyhow!(
                "QEMU exited unexpectedly with status {status}"
            ));
        }

        if last_activity.elapsed() > inactivity_timeout {
            break Err(anyhow::anyhow!(
                "no guest output for {:?}",
                inactivity_timeout
            ));
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                last_activity = Instant::now();
                eprintln!("[guest] {line}");

                if line.contains(success_pattern) {
                    break Ok(GuestReport {
                        duration: start.elapsed(),
                    });
                }

                if let Some((pattern, reason)) = hard_failures
                    .iter()
                    .find(|(pattern, _)| line.contains(pattern))
                {
                    let message = format!("{reason} — matched {pattern:?}");
                    break Err(anyhow::anyhow!(message));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(anyhow::anyhow!("guest output stream closed before success"));
            }
        }
    };

    let _ = qemu_child.kill();
    let _ = qemu_child.wait();

    match result {
        Ok(report) => Ok(report),
        Err(err) => {
            eprintln!("[pxe-harness] guest log tail:");
            for line in drain_tail(&tail) {
                eprintln!("{line}");
            }
            Err(err)
        }
    }
}

fn push_log(tail: &Arc<Mutex<VecDeque<String>>>, line: String) {
    if let Ok(mut tail) = tail.lock() {
        if tail.len() == MAX_LOG_LINES {
            tail.pop_front();
        }
        tail.push_back(line);
    }
}

fn drain_tail(tail: &Arc<Mutex<VecDeque<String>>>) -> Vec<String> {
    tail.lock()
        .map(|tail| tail.iter().cloned().collect())
        .unwrap_or_default()
}

fn env_duration_secs(name: &str, default: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .unwrap_or(manifest_dir)
}
