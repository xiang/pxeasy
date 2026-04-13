use std::{
    io::{self, Read},
    path::{Path, PathBuf},
};

use cdfs::{DirectoryEntry, ISO9660};

pub use error::ProfileError;
mod error;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The detected Linux distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Distro {
    Ubuntu,
    Debian,
    Unknown,
}

/// A boot profile derived from inspecting an ISO image.
#[derive(Debug, Clone)]
pub struct BootProfile {
    pub distro: Distro,
    /// Path to the kernel within the ISO.
    pub kernel_path: String,
    /// Path to the initrd within the ISO.
    pub initrd_path: String,
    /// Kernel command-line parameters (may be empty).
    pub boot_params: String,
    /// Human-readable label, e.g. "Ubuntu 24.04 LTS".
    pub label: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inspect `iso_path` and return a `BootProfile` for the first matched distro.
///
/// # Errors
///
/// - [`ProfileError::IsoUnreadable`] — file cannot be opened or is not a valid ISO 9660 image.
/// - [`ProfileError::UnknownDistro`] — no supported distro was detected.
/// - [`ProfileError::MissingFile`] — a required file is absent from the detected distro layout.
pub fn detect_profile(iso_path: &Path) -> Result<BootProfile, ProfileError> {
    let file = std::fs::File::open(iso_path)
        .map_err(|e| ProfileError::IsoUnreadable(iso_path.to_path_buf(), e))?;
    let iso = ISO9660::new(file).map_err(|e| {
        ProfileError::IsoUnreadable(
            iso_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;
    detect_from_fs(&CdfsIso {
        iso,
        path: iso_path.to_path_buf(),
    })
}

/// Generate an iPXE boot script for the given profile.
///
/// The output uses LF-only line endings and has no trailing whitespace on any line.
pub fn generate_ipxe_script(profile: &BootProfile, server_ip: &str, port: u16) -> String {
    let slug = distro_slug(&profile.distro);
    let kernel_line = if profile.boot_params.is_empty() {
        format!("kernel http://{}:{}/boot/{}/vmlinuz", server_ip, port, slug)
    } else {
        format!(
            "kernel http://{}:{}/boot/{}/vmlinuz {}",
            server_ip, port, slug, profile.boot_params
        )
    };
    format!(
        "#!ipxe\n{}\ninitrd http://{}:{}/boot/{}/initrd\nboot\n",
        kernel_line, server_ip, port, slug
    )
}

fn distro_slug(distro: &Distro) -> &'static str {
    match distro {
        Distro::Ubuntu => "ubuntu",
        Distro::Debian => "debian",
        Distro::Unknown => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Internal ISO abstraction — allows unit-testing without a real ISO image
// ---------------------------------------------------------------------------

trait IsoFs {
    /// Read the full contents of a file at `path`, or `None` if the path does
    /// not exist or is not a file.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError>;
    /// Return `true` if `path` exists (file *or* directory).
    fn path_exists(&self, path: &str) -> Result<bool, ProfileError>;
}

struct CdfsIso<R: cdfs::ISO9660Reader> {
    iso: ISO9660<R>,
    path: PathBuf,
}

impl<R: cdfs::ISO9660Reader> IsoFs for CdfsIso<R> {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
        match self.iso.open(path).map_err(|e| {
            ProfileError::IsoUnreadable(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })? {
            Some(DirectoryEntry::File(f)) => {
                let mut buf = Vec::new();
                f.read()
                    .read_to_end(&mut buf)
                    .map_err(|e| ProfileError::IsoUnreadable(self.path.clone(), e))?;
                Ok(Some(buf))
            }
            _ => Ok(None),
        }
    }

    fn path_exists(&self, path: &str) -> Result<bool, ProfileError> {
        self.iso
            .open(path)
            .map(|entry| entry.is_some())
            .map_err(|e| {
                ProfileError::IsoUnreadable(
                    self.path.clone(),
                    io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Detection logic
// ---------------------------------------------------------------------------

fn detect_from_fs(iso: &dyn IsoFs) -> Result<BootProfile, ProfileError> {
    // Ubuntu: /.disk/info contains "Ubuntu"
    if let Some(info_bytes) = iso.read_file("/.disk/info")? {
        if String::from_utf8_lossy(&info_bytes).contains("Ubuntu") {
            let label = String::from_utf8_lossy(&info_bytes)
                .lines()
                .next()
                .unwrap_or("Ubuntu")
                .trim()
                .to_string();

            for path in ["/casper/vmlinuz", "/casper/initrd"] {
                if !iso.path_exists(path)? {
                    return Err(ProfileError::MissingFile {
                        path: path.to_string(),
                    });
                }
            }

            return Ok(BootProfile {
                distro: Distro::Ubuntu,
                kernel_path: "/casper/vmlinuz".to_string(),
                initrd_path: "/casper/initrd".to_string(),
                boot_params: String::new(),
                label,
            });
        }
    }

    // Debian: /debian directory is present
    if iso.path_exists("/debian")? {
        for path in ["/install.amd/vmlinuz", "/install.amd/initrd.gz"] {
            if !iso.path_exists(path)? {
                return Err(ProfileError::MissingFile {
                    path: path.to_string(),
                });
            }
        }

        return Ok(BootProfile {
            distro: Distro::Debian,
            kernel_path: "/install.amd/vmlinuz".to_string(),
            initrd_path: "/install.amd/initrd.gz".to_string(),
            boot_params: String::new(),
            label: "Debian".to_string(),
        });
    }

    Err(ProfileError::UnknownDistro)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // --- Mock ISO ---

    struct MockIso {
        files: HashMap<&'static str, Vec<u8>>,
        dirs: Vec<&'static str>,
    }

    impl MockIso {
        fn new() -> Self {
            MockIso {
                files: HashMap::new(),
                dirs: Vec::new(),
            }
        }

        fn with_file(mut self, path: &'static str, content: &[u8]) -> Self {
            self.files.insert(path, content.to_vec());
            self
        }

        fn with_dir(mut self, path: &'static str) -> Self {
            self.dirs.push(path);
            self
        }
    }

    impl IsoFs for MockIso {
        fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
            Ok(self.files.get(path).cloned())
        }

        fn path_exists(&self, path: &str) -> Result<bool, ProfileError> {
            Ok(self.files.contains_key(path) || self.dirs.iter().any(|&d| d == path))
        }
    }

    // --- Ubuntu detection ---

    #[test]
    fn ubuntu_detected_from_disk_info() {
        let iso = MockIso::new()
            .with_file(
                "/.disk/info",
                b"Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240821)",
            )
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"");

        let profile = detect_from_fs(&iso).unwrap();
        assert_eq!(profile.distro, Distro::Ubuntu);
        assert_eq!(profile.kernel_path, "/casper/vmlinuz");
        assert_eq!(profile.initrd_path, "/casper/initrd");
        assert_eq!(
            profile.label,
            "Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240821)"
        );
    }

    #[test]
    fn ubuntu_boot_params_empty_by_default() {
        let iso = MockIso::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"");

        let profile = detect_from_fs(&iso).unwrap();
        assert!(profile.boot_params.is_empty());
    }

    #[test]
    fn ubuntu_missing_kernel_returns_missing_file_error() {
        let iso = MockIso::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            // /casper/vmlinuz absent
            .with_file("/casper/initrd", b"");

        let err = detect_from_fs(&iso).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/casper/vmlinuz"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    #[test]
    fn ubuntu_missing_initrd_returns_missing_file_error() {
        let iso = MockIso::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            .with_file("/casper/vmlinuz", b"");
        // /casper/initrd absent

        let err = detect_from_fs(&iso).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/casper/initrd"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    // --- Debian detection ---

    #[test]
    fn debian_detected_from_debian_dir() {
        let iso = MockIso::new()
            .with_dir("/debian")
            .with_file("/install.amd/vmlinuz", b"")
            .with_file("/install.amd/initrd.gz", b"");

        let profile = detect_from_fs(&iso).unwrap();
        assert_eq!(profile.distro, Distro::Debian);
        assert_eq!(profile.kernel_path, "/install.amd/vmlinuz");
        assert_eq!(profile.initrd_path, "/install.amd/initrd.gz");
        assert_eq!(profile.label, "Debian");
    }

    #[test]
    fn debian_missing_kernel_returns_missing_file_error() {
        let iso = MockIso::new()
            .with_dir("/debian")
            // /install.amd/vmlinuz absent
            .with_file("/install.amd/initrd.gz", b"");

        let err = detect_from_fs(&iso).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/install.amd/vmlinuz"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    // --- UnknownDistro ---

    #[test]
    fn unknown_distro_when_no_markers_present() {
        let iso = MockIso::new();
        let err = detect_from_fs(&iso).unwrap_err();
        assert!(matches!(err, ProfileError::UnknownDistro));
    }

    // --- Detection order ---

    #[test]
    fn ubuntu_takes_precedence_over_debian_markers() {
        let iso = MockIso::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"")
            .with_dir("/debian");

        let profile = detect_from_fs(&iso).unwrap();
        assert_eq!(profile.distro, Distro::Ubuntu);
    }

    // --- iPXE script generation ---

    #[test]
    fn ipxe_script_ubuntu_no_boot_params() {
        let profile = BootProfile {
            distro: Distro::Ubuntu,
            kernel_path: "/casper/vmlinuz".to_string(),
            initrd_path: "/casper/initrd".to_string(),
            boot_params: String::new(),
            label: "Ubuntu 24.04 LTS".to_string(),
        };
        let script = generate_ipxe_script(&profile, "192.168.1.1", 8080);
        assert_eq!(
            script,
            "#!ipxe\nkernel http://192.168.1.1:8080/boot/ubuntu/vmlinuz\ninitrd http://192.168.1.1:8080/boot/ubuntu/initrd\nboot\n"
        );
    }

    #[test]
    fn ipxe_script_ubuntu_with_boot_params() {
        let profile = BootProfile {
            distro: Distro::Ubuntu,
            kernel_path: "/casper/vmlinuz".to_string(),
            initrd_path: "/casper/initrd".to_string(),
            boot_params: "quiet splash".to_string(),
            label: "Ubuntu 24.04 LTS".to_string(),
        };
        let script = generate_ipxe_script(&profile, "10.0.0.1", 80);
        assert_eq!(
            script,
            "#!ipxe\nkernel http://10.0.0.1:80/boot/ubuntu/vmlinuz quiet splash\ninitrd http://10.0.0.1:80/boot/ubuntu/initrd\nboot\n"
        );
    }

    #[test]
    fn ipxe_script_no_trailing_whitespace_on_any_line() {
        let profile = BootProfile {
            distro: Distro::Debian,
            kernel_path: "/install.amd/vmlinuz".to_string(),
            initrd_path: "/install.amd/initrd.gz".to_string(),
            boot_params: String::new(),
            label: "Debian".to_string(),
        };
        let script = generate_ipxe_script(&profile, "192.168.1.1", 8080);
        for line in script.lines() {
            assert!(
                !line.ends_with(' '),
                "trailing whitespace on line: {line:?}"
            );
        }
    }

    #[test]
    fn ipxe_script_lf_only_no_crlf() {
        let profile = BootProfile {
            distro: Distro::Ubuntu,
            kernel_path: "/casper/vmlinuz".to_string(),
            initrd_path: "/casper/initrd".to_string(),
            boot_params: String::new(),
            label: "Ubuntu".to_string(),
        };
        let script = generate_ipxe_script(&profile, "192.168.1.1", 8080);
        assert!(!script.contains('\r'), "script must use LF-only line endings");
    }
}
