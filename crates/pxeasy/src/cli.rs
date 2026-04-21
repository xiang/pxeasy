use std::{
    env,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use config::{Config, File, FileFormat};
use pico_args::Arguments;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ConfigOverrides {
    interface: Option<String>,
    bind_ip: Option<Ipv4Addr>,
    ipxe_boot_file: Option<String>,
}

pub struct StartCommand {
    pub source_path: PathBuf,
    pub interface: Option<String>,
    pub bind_ip: Option<Ipv4Addr>,
    pub ipxe_boot_file: Option<String>,
}

pub struct DaemonCommand {
    pub source_path: PathBuf,
    pub interface: Option<String>,
    pub bind_ip: Option<Ipv4Addr>,
    pub ipxe_boot_file: Option<String>,
}

pub enum CliCommand {
    Start(StartCommand),
    Daemon(DaemonCommand),
}

pub fn parse_args<I>(args: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let argv: Vec<std::ffi::OsString> = args.into_iter().skip(1).collect();
    let mut pargs = Arguments::from_vec(argv);

    let subcommand: String = pargs
        .free_from_str()
        .map_err(|_| usage_error("missing command"))?;

    match subcommand.as_str() {
        "start" => parse_command(pargs).map(CliCommand::Start),
        "daemon" => parse_command(pargs).map(|command| {
            CliCommand::Daemon(DaemonCommand {
                source_path: command.source_path,
                interface: command.interface,
                bind_ip: command.bind_ip,
                ipxe_boot_file: command.ipxe_boot_file,
            })
        }),
        other => Err(usage_error(&format!("unsupported command: {other}"))),
    }
}

fn parse_command(mut pargs: Arguments) -> Result<StartCommand, String> {
    let source_path: PathBuf = pargs
        .free_from_str()
        .map_err(|_| usage_error("missing <boot-source>"))?;
    let config_path = pargs
        .opt_value_from_str("--config")
        .map_err(|e| usage_error(&e.to_string()))?
        .unwrap_or_else(default_config_path);
    let cli_overrides = parse_cli_overrides(&mut pargs)?;

    reject_remaining(pargs)?;

    let file_overrides = load_config_overrides(&config_path)?;
    Ok(apply_overrides(source_path, file_overrides, cli_overrides))
}

fn parse_cli_overrides(pargs: &mut Arguments) -> Result<ConfigOverrides, String> {
    let interface = pargs
        .opt_value_from_str("--interface")
        .map_err(|e| usage_error(&e.to_string()))?;
    let bind_ip = pargs
        .opt_value_from_str::<_, Ipv4Addr>("--bind")
        .map_err(|_| usage_error("--bind requires a valid IPv4 address"))?;

    Ok(ConfigOverrides {
        interface,
        bind_ip,
        ipxe_boot_file: None,
    })
}

fn load_config_overrides(config_path: &Path) -> Result<ConfigOverrides, String> {
    Config::builder()
        .add_source(
            File::from(config_path)
                .format(FileFormat::Toml)
                .required(false),
        )
        .build()
        .map_err(|err| {
            format!(
                "error: failed to load config {}: {err}",
                config_path.display()
            )
        })?
        .try_deserialize()
        .map_err(|err| {
            format!(
                "error: failed to parse config {}: {err}",
                config_path.display()
            )
        })
}

fn apply_overrides(
    source_path: PathBuf,
    file_overrides: ConfigOverrides,
    cli_overrides: ConfigOverrides,
) -> StartCommand {
    StartCommand {
        source_path,
        interface: cli_overrides.interface.or(file_overrides.interface),
        bind_ip: cli_overrides.bind_ip.or(file_overrides.bind_ip),
        ipxe_boot_file: file_overrides.ipxe_boot_file,
    }
}

fn reject_remaining(pargs: Arguments) -> Result<(), String> {
    let remaining = pargs.finish();
    if let Some(arg) = remaining.first() {
        return Err(usage_error(&format!(
            "unexpected argument: {}",
            arg.to_string_lossy()
        )));
    }
    Ok(())
}

fn default_config_path() -> PathBuf {
    match env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".pxeasy/config.toml"),
        None => PathBuf::from("/var/root/.pxeasy/config.toml"),
    }
}

fn usage_error(message: &str) -> String {
    format!(
        "error: {message}\nusage:\n  pxeasy start <source-path> [--config <path>] [--interface <iface>] [--bind <ip>]\n  pxeasy daemon <source-path> [--config <path>] [--interface <iface>] [--bind <ip>]\nnote: config is TOML-only and provides defaults/overrides for these options"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_overrides_load_from_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("pxeasy.toml");
        std::fs::write(
            &config_path,
            r#"
interface = "en0"
bind_ip = "192.168.1.10"
ipxe_boot_file = "custom.ipxe"
"#,
        )
        .expect("write config");

        let overrides = load_config_overrides(&config_path).expect("load config");
        assert_eq!(
            overrides,
            ConfigOverrides {
                interface: Some("en0".to_string()),
                bind_ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
                ipxe_boot_file: Some("custom.ipxe".to_string()),
            }
        );
    }

    #[test]
    fn missing_config_file_is_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("missing.toml");

        let overrides = load_config_overrides(&config_path).expect("load config");
        assert_eq!(overrides, ConfigOverrides::default());
    }

    #[test]
    fn cli_values_override_config_defaults() {
        let start = apply_overrides(
            PathBuf::from("/tmp/ubuntu.iso"),
            ConfigOverrides {
                interface: Some("en0".to_string()),
                bind_ip: Some(Ipv4Addr::new(10, 0, 0, 5)),
                ipxe_boot_file: Some("boot-from-config.ipxe".to_string()),
            },
            ConfigOverrides {
                interface: Some("en7".to_string()),
                bind_ip: None,
                ipxe_boot_file: None,
            },
        );

        assert_eq!(start.source_path, PathBuf::from("/tmp/ubuntu.iso"));
        assert_eq!(start.interface, Some("en7".to_string()));
        assert_eq!(start.bind_ip, Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(
            start.ipxe_boot_file,
            Some("boot-from-config.ipxe".to_string())
        );
    }
}
