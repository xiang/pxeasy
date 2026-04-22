mod qemu;
mod runner;
mod scenarios;
mod server;

use std::path::PathBuf;

use anyhow::{Context, Result};
use pico_args::Arguments;

use runner::{run_smoke, run_windows_arm64_manual_with_server, RunOptions};
use scenarios::{all_scenarios, scenario_by_name};

enum Command {
    List,
    Smoke {
        name: String,
        no_build: bool,
    },
    WindowsArm64 {
        source_path: PathBuf,
        disk_path: Option<PathBuf>,
        no_build: bool,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Arguments::from_env();
    let command = parse_command(args)?;
    let repo_root = workspace_root()?;

    match command {
        Command::List => {
            for scenario in all_scenarios(&repo_root) {
                println!("{}", scenario.name);
            }
            Ok(())
        }
        Command::Smoke { name, no_build } => {
            let scenario = scenario_by_name(&repo_root, &name)
                .ok_or_else(|| anyhow::anyhow!("unknown scenario: {name}"))?;
            let target_dir = repo_root.join("target/pxe-harness");
            run_smoke(
                scenario,
                RunOptions {
                    build: !no_build,
                    repo_root,
                    target_dir,
                },
            )
        }
        Command::WindowsArm64 {
            source_path,
            disk_path,
            no_build,
        } => {
            let target_dir = repo_root.join("target/pxe-harness");
            let disk_path =
                disk_path.unwrap_or_else(|| target_dir.join("windows-arm64-installer.raw"));
            run_windows_arm64_manual_with_server(
                source_path,
                disk_path,
                RunOptions {
                    build: !no_build,
                    repo_root,
                    target_dir,
                },
            )
        }
    }
}

fn parse_command(mut args: Arguments) -> Result<Command> {
    let command = args.subcommand()?.unwrap_or_else(|| "smoke".to_string());

    let parsed = match command.as_str() {
        "list" => Command::List,
        "smoke" => {
            let no_build = args.contains("--no-build");
            let name = args
                .free_from_str::<String>()
                .context("usage: pxe-harness smoke <scenario> [--no-build]")?;
            Command::Smoke { name, no_build }
        }
        "windows-arm64" => {
            let no_build = args.contains("--no-build");
            let disk_path = args.opt_value_from_str::<_, PathBuf>("--disk")?;
            let source_path = args.free_from_str::<PathBuf>().context(
                "usage: pxe-harness windows-arm64 <iso-path> [--disk <raw-disk>] [--no-build]",
            )?;
            Command::WindowsArm64 {
                source_path,
                disk_path,
                no_build,
            }
        }
        other => anyhow::bail!("unknown command: {other}"),
    };

    args.finish()
        .into_iter()
        .next()
        .map_or(Ok(parsed), |extra| {
            Err(anyhow::anyhow!(
                "unexpected argument: {}",
                extra.to_string_lossy()
            ))
        })
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .context("failed to resolve workspace root")
}
