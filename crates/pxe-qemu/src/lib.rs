use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Expected size of UEFI pflash firmware images (64 MiB).
const UEFI_FD_SIZE: u64 = 64 * 1024 * 1024;

/// Default time to wait with no VM output before declaring a stall.
/// Must be long enough to survive installer package downloads, which can be
/// silent on the serial console for a while.
const DEFAULT_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120);

/// Downloads the full iPXE EFI binary (with built-in NIC drivers) for `arch`
/// ("arm64" or "amd64") and caches it in `/tmp/pxeasy-ipxe/`. Returns the path.
///
/// Use this binary when creating a UEFI boot disk — unlike `snponly.efi`,
/// it contains its own NIC drivers and does not require UEFI SNP.
pub fn fetch_ipxe_disk_efi(arch: &str) -> anyhow::Result<PathBuf> {
    let url = match arch {
        "amd64" | "x86_64" => "https://boot.ipxe.org/ipxe.efi",
        "arm64" | "aarch64" => "https://boot.ipxe.org/arm64-efi/ipxe.efi",
        other => anyhow::bail!("unsupported iPXE architecture: {other}"),
    };

    let cache_dir = std::env::temp_dir().join("pxeasy-ipxe");
    std::fs::create_dir_all(&cache_dir)?;
    let local_path = cache_dir.join(format!("ipxe-full-{arch}.efi"));

    if !local_path.exists() {
        let status = Command::new("curl")
            .args(["-sL", url, "-o", local_path.to_str().unwrap()])
            .status()?;
        anyhow::ensure!(status.success(), "curl failed to download iPXE from {url}");
    }

    Ok(local_path)
}

/// Creates a UEFI-bootable FAT32 disk image with `efi_app` installed as
/// `EFI/BOOT/BOOTAA64.EFI`. Returns a `NamedTempFile`; the caller must keep
/// it alive for the lifetime of the QEMU process.
///
/// Requires `mformat`, `mmd`, and `mcopy` from mtools to be on PATH.
pub fn create_uefi_boot_disk(efi_app: &Path) -> anyhow::Result<tempfile::NamedTempFile> {
    let disk = tempfile::Builder::new().suffix(".img").tempfile()?;

    // 64 MiB raw image
    let status = Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", disk.path().display()),
            "bs=512",
            "count=131072",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(status.success(), "dd failed creating disk image");

    let img = disk.path().to_str().unwrap();

    let status = Command::new("mformat").args(["-i", img, "::"]).status()?;
    anyhow::ensure!(status.success(), "mformat failed");

    for dir in &["::EFI", "::EFI/BOOT"] {
        let status = Command::new("mmd").args(["-i", img, dir]).status()?;
        anyhow::ensure!(status.success(), "mmd failed for {dir}");
    }

    let status = Command::new("mcopy")
        .args([
            "-i",
            img,
            efi_app.to_str().unwrap(),
            "::EFI/BOOT/BOOTAA64.EFI",
        ])
        .status()?;
    anyhow::ensure!(status.success(), "mcopy failed");

    Ok(disk)
}

pub struct QemuBuilder {
    bin: String,
    firmware: PathBuf,
    vars: Option<PathBuf>,
    memory: String,
    sudo: bool,
    args: Vec<String>,
}

impl QemuBuilder {
    pub fn new(bin: &str, firmware: impl Into<PathBuf>) -> Self {
        Self {
            bin: bin.to_string(),
            firmware: firmware.into(),
            vars: None,
            memory: "1G".to_string(),
            sudo: false,
            args: Vec::new(),
        }
    }

    pub fn vars(mut self, path: impl Into<PathBuf>) -> Self {
        self.vars = Some(path.into());
        self
    }

    pub fn memory(mut self, mem: &str) -> Self {
        self.memory = mem.to_string();
        self
    }

    pub fn sudo(mut self, enabled: bool) -> Self {
        self.sudo = enabled;
        self
    }

    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self.args.push(arg.as_ref().to_string());
        }
        self
    }

    /// Pads `path` to `UEFI_FD_SIZE` using `0xFF` (erased flash state) if needed.
    fn pad_if_needed(path: &Path, id: &str) -> anyhow::Result<PathBuf> {
        let src = std::fs::read(path)?;
        if src.len() as u64 == UEFI_FD_SIZE {
            return Ok(path.to_path_buf());
        }
        anyhow::ensure!(
            src.len() as u64 <= UEFI_FD_SIZE,
            "firmware file {} is larger than expected 64 MiB",
            path.display()
        );
        let padded_path = std::env::temp_dir().join(format!("pxe_harness_padded_{}.fd", id));
        let mut data = vec![0xFFu8; UEFI_FD_SIZE as usize];
        data[..src.len()].copy_from_slice(&src);
        std::fs::write(&padded_path, &data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&padded_path)?.permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&padded_path, perms)?;
        }
        Ok(padded_path)
    }

    pub fn spawn(&self) -> anyhow::Result<Child> {
        let mut cmd = if self.sudo {
            let mut cmd = Command::new("sudo");
            cmd.arg("-n").arg(&self.bin);
            cmd
        } else {
            Command::new(&self.bin)
        };

        // Custom args first (machine type, CPU, network, etc.)
        cmd.args(&self.args);

        // Harness invariants: without these, the harness cannot read or monitor the VM.
        cmd.args([
            "-display",
            "none",
            "-serial",
            "stdio",
            "-m",
            &self.memory,
            "-boot",
            "n",
        ]);

        let firmware_path = Self::pad_if_needed(&self.firmware, "code")?;
        cmd.arg("-drive").arg(format!(
            "if=pflash,format=raw,unit=0,file={},readonly=on",
            firmware_path.display()
        ));

        if let Some(ref vars) = self.vars {
            let vars_path = Self::pad_if_needed(vars, "vars")?;
            cmd.arg("-drive").arg(format!(
                "if=pflash,format=raw,unit=1,file={}",
                vars_path.display()
            ));
        }

        Ok(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?)
    }
}

pub fn run_guest_boot_test(
    qemu: QemuBuilder,
    success_pattern: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    run_qemu_boot(qemu, success_pattern, timeout)
}

fn run_qemu_boot(
    qemu: QemuBuilder,
    success_pattern: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut qemu_child = qemu.spawn()?;
    let stdout = qemu_child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("QEMU stdout not captured"))?;
    let stderr = qemu_child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("QEMU stderr not captured"))?;

    let (tx, rx) = mpsc::channel::<String>();

    let tx_stdout = tx.clone();
    thread::spawn(move || {
        for l in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
            let _ = tx_stdout.send(format!("[STDOUT] {}", l));
        }
    });

    let tx_stderr = tx.clone();
    thread::spawn(move || {
        for l in BufReader::new(stderr).lines().map_while(|line| line.ok()) {
            let _ = tx_stderr.send(format!("[STDERR] {}", l));
        }
    });

    // Drop the original sender so the channel closes when both reader threads finish.
    drop(tx);

    let start = Instant::now();
    let mut last_activity = Instant::now();
    let inactivity_timeout = env_duration_secs(
        "PXE_QEMU_INACTIVITY_TIMEOUT_SECS",
        DEFAULT_INACTIVITY_TIMEOUT,
    );
    let mut failure_reason = None;

    // Bail immediately on any of these — they indicate the boot has stalled
    // or entered an interactive state that will never self-resolve.
    let hard_failures: &[(&str, &str)] = &[
        (
            "No bootable option or device was found",
            "UEFI: no bootable device (PXE offer not received)",
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
        (
            "Press ESC in",
            "UEFI: startup.nsh countdown (shell, not booting)",
        ),
        ("No mapping found", "UEFI shell: no devices found"),
        ("PXE-E", "iPXE/PXE error code"),
        ("No configuration methods", "iPXE: DHCP failed"),
        ("Unable to obtain", "iPXE: network init failed"),
        ("Connection timed out", "iPXE: connection timeout"),
        ("Error 0x", "iPXE: fatal error"),
    ];

    eprintln!(
        "[pxe-qemu] Monitoring boot (timeout: {:?}, inactivity: {:?})",
        timeout, inactivity_timeout
    );

    'outer: while start.elapsed() < timeout {
        if let Ok(Some(status)) = qemu_child.try_wait() {
            failure_reason = Some(format!("QEMU exited unexpectedly with status: {}", status));
            break;
        }

        if last_activity.elapsed() > inactivity_timeout {
            failure_reason = Some(format!(
                "No output for {:?} — VM stalled or waiting for input",
                inactivity_timeout
            ));
            break;
        }

        if let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
            last_activity = Instant::now();
            let _ = writeln!(std::io::stderr(), "{}", line);

            if line.contains(success_pattern) {
                eprintln!("[pxe-qemu] Success pattern matched.");
                let _ = qemu_child.kill();
                return Ok(());
            }

            for (pattern, reason) in hard_failures {
                if line.contains(pattern) {
                    failure_reason = Some(format!("{reason} — matched: {pattern:?}"));
                    break 'outer;
                }
            }
        }
    }

    let _ = qemu_child.kill();

    let err = failure_reason.unwrap_or_else(|| {
        format!(
            "Timeout: pattern {:?} not seen within {:?}",
            success_pattern, timeout
        )
    });
    anyhow::bail!("PXE test failed: {}", err)
}

fn env_duration_secs(name: &str, default: Duration) -> Duration {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or(default),
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn pad_if_needed_pads_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firmware.fd");
        fs::write(&path, b"tiny").unwrap();

        let result = QemuBuilder::pad_if_needed(&path, "test_small").unwrap();
        assert_ne!(result, path, "should return a new padded path");
        let data = fs::read(&result).unwrap();
        assert_eq!(data.len() as u64, UEFI_FD_SIZE);
        // Source bytes preserved at the start.
        assert_eq!(&data[..4], b"tiny");
        // Remainder is 0xFF (erased flash).
        assert!(data[4..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn pad_if_needed_no_copy_when_exact_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firmware.fd");
        fs::write(&path, vec![0u8; UEFI_FD_SIZE as usize]).unwrap();

        let result = QemuBuilder::pad_if_needed(&path, "test_exact").unwrap();
        assert_eq!(result, path, "should return original path unchanged");
    }
}
