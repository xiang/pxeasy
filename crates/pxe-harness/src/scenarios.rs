use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::qemu::QemuScenario;

#[derive(Clone, Copy)]
pub struct SourceBuildDef {
    pub script_relative_path: &'static str,
    pub input_relative_path: &'static str,
}

#[derive(Clone, Copy)]
pub struct ScenarioDef {
    pub name: &'static str,
    pub source_relative_path: &'static str,
    pub source_build: Option<SourceBuildDef>,
    pub guest_success_pattern: &'static str,
    pub server_success_pattern: Option<&'static str>,
    pub timeout: Duration,
    pub guest: QemuScenario,
    pub server_env: &'static [(&'static str, &'static str)],
}

#[derive(Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub source_path: PathBuf,
    pub source_build: Option<SourceBuildDef>,
    pub guest_success_pattern: &'static str,
    pub server_success_pattern: Option<&'static str>,
    pub timeout: Duration,
    pub guest: QemuScenario,
    pub server_env: &'static [(&'static str, &'static str)],
}

const SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        name: "ubuntu-arm64-nfs",
        source_relative_path: "assets/ubuntu/ubuntu-24.04.4-live-server-arm64.iso",
        source_build: None,
        guest_success_pattern: "Welcome to Ubuntu",
        server_success_pattern: None,
        timeout: Duration::from_secs(600),
        guest: QemuScenario::Arm64Uefi,
        server_env: &[],
    },
    ScenarioDef {
        name: "debian-arm64-netboot",
        source_relative_path: "assets/debian/netboot.tar.gz",
        source_build: None,
        guest_success_pattern: "Starting debian-installer",
        server_success_pattern: None,
        timeout: Duration::from_secs(300),
        guest: QemuScenario::Arm64Uefi,
        server_env: &[],
    },
    ScenarioDef {
        name: "freebsd-arm64-sanboot-mfs-memstick",
        source_relative_path: "assets/freebsd/FreeBSD-15.0-RELEASE-arm64-aarch64-mini.img",
        source_build: Some(SourceBuildDef {
            script_relative_path: "scripts/build-freebsd.sh",
            input_relative_path: "assets/freebsd/FreeBSD-15.0-RELEASE-arm64-aarch64-bootonly.iso",
        }),
        guest_success_pattern: "Welcome to FreeBSD!",
        server_success_pattern: Some("GET /disk.img"),
        timeout: Duration::from_secs(300),
        guest: QemuScenario::Arm64Uefi,
        server_env: &[],
    },
];

pub fn all_scenarios(repo_root: &Path) -> Vec<Scenario> {
    SCENARIOS
        .iter()
        .map(|scenario| Scenario {
            name: scenario.name,
            source_path: repo_root.join(scenario.source_relative_path),
            source_build: scenario.source_build,
            guest_success_pattern: scenario.guest_success_pattern,
            server_success_pattern: scenario.server_success_pattern,
            timeout: scenario.timeout,
            guest: scenario.guest,
            server_env: scenario.server_env,
        })
        .collect()
}

pub fn scenario_by_name(repo_root: &Path, name: &str) -> Option<Scenario> {
    all_scenarios(repo_root)
        .into_iter()
        .find(|scenario| scenario.name == name)
}

impl Scenario {
    pub fn validate(&self) -> Result<()> {
        if self.source_path.exists() {
            Ok(())
        } else {
            Err(anyhow!(
                "missing scenario source: {}",
                self.source_path.display()
            ))
        }
    }
}
