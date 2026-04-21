use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::qemu::run_guest;
use crate::scenarios::{Scenario, SourceBuildDef};
use crate::server::ServerHandle;

pub struct RunOptions {
    pub build: bool,
    pub repo_root: PathBuf,
    pub target_dir: PathBuf,
}

pub fn run_smoke(scenario: Scenario, options: RunOptions) -> Result<()> {
    ensure_scenario_source(&scenario, &options.repo_root)?;
    scenario.validate()?;

    if options.build {
        build_pxeasy(&options.repo_root, &options.target_dir)?;
    }

    let pxeasy_bin = options.target_dir.join("debug/pxeasy");
    if !pxeasy_bin.exists() {
        anyhow::bail!("missing built pxeasy binary at {}", pxeasy_bin.display());
    }

    let interrupted = Arc::new(AtomicBool::new(false));
    install_ctrlc(Arc::clone(&interrupted))?;

    let mut server = ServerHandle::start_with_sudo(
        &pxeasy_bin,
        &scenario.source_path,
        scenario.server_env,
        &interrupted,
    )?;
    if interrupted.load(Ordering::SeqCst) {
        anyhow::bail!("interrupted before guest launch");
    }

    let result = run_guest(
        scenario.guest,
        scenario.guest_success_pattern,
        scenario.timeout,
        Arc::clone(&interrupted),
    );
    let result = match result {
        Ok(report) => {
            if let Some(pattern) = scenario.server_success_pattern {
                wait_for_server_pattern(
                    &mut server,
                    pattern,
                    scenario.timeout.saturating_sub(report.duration),
                    &interrupted,
                )?;
            }
            Ok(report)
        }
        Err(err) => Err(err),
    };
    let _ = server.stop();

    match result {
        Ok(report) => {
            println!(
                "[pxe-harness] scenario {} passed in {:?}",
                scenario.name, report.duration
            );
            Ok(())
        }
        Err(err) => {
            eprintln!("[pxe-harness] server log tail:");
            for line in server.log_tail() {
                eprintln!("{line}");
            }
            Err(err).with_context(|| format!("scenario {} failed", scenario.name))
        }
    }
}

fn ensure_scenario_source(scenario: &Scenario, repo_root: &Path) -> Result<()> {
    if scenario.source_path.exists() {
        return Ok(());
    }

    let Some(source_build) = scenario.source_build else {
        return Ok(());
    };

    build_scenario_source(repo_root, &scenario.source_path, source_build)
}

fn build_scenario_source(
    repo_root: &Path,
    output_path: &Path,
    source_build: SourceBuildDef,
) -> Result<()> {
    let script_path = repo_root.join(source_build.script_relative_path);
    let input_path = repo_root.join(source_build.input_relative_path);

    anyhow::ensure!(
        script_path.exists(),
        "missing source build script: {}",
        script_path.display()
    );
    anyhow::ensure!(
        input_path.exists(),
        "missing source build input: {}",
        input_path.display()
    );

    let status = Command::new("sh")
        .current_dir(repo_root)
        .arg(&script_path)
        .arg(&input_path)
        .arg(output_path)
        .status()
        .with_context(|| {
            format!(
                "failed to build scenario source via {}",
                script_path.display()
            )
        })?;

    anyhow::ensure!(
        status.success(),
        "source build script failed: {}",
        script_path.display()
    );
    Ok(())
}

fn wait_for_server_pattern(
    server: &mut ServerHandle,
    pattern: &str,
    timeout: Duration,
    interrupted: &Arc<AtomicBool>,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if interrupted.load(Ordering::SeqCst) {
            anyhow::bail!("interrupted while waiting for server pattern");
        }
        if let Some(line) = server.recv_log_timeout(Duration::from_millis(200))? {
            if line.contains(pattern) {
                return Ok(());
            }
        } else {
            thread::yield_now();
        }
    }
    anyhow::bail!("server pattern {:?} not seen within {:?}", pattern, timeout);
}

fn build_pxeasy(repo_root: &Path, target_dir: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .arg("build")
        .arg("-p")
        .arg("pxeasy")
        .arg("--target-dir")
        .arg(target_dir)
        .status()
        .context("failed to run cargo build")?;

    anyhow::ensure!(status.success(), "cargo build -p pxeasy failed");
    Ok(())
}

fn install_ctrlc(interrupted: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || {
        interrupted.store(true, Ordering::SeqCst);
    })
    .context("failed to install ctrl-c handler")
}
