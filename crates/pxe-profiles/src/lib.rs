use std::{
    collections::{HashMap, HashSet},
    io::{self, Read},
    path::{Path, PathBuf},
};

use cdfs::{DirectoryEntry, ISO9660};
use flate2::read::GzDecoder;
use tar::Archive;

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

/// Inspect `source_path` and return a `BootProfile` for the first matched distro.
///
/// # Errors
///
/// - [`ProfileError::SourceUnreadable`] — file cannot be opened or parsed as a supported source.
/// - [`ProfileError::UnknownDistro`] — no supported distro was detected.
/// - [`ProfileError::MissingFile`] — a required file is absent from the detected distro layout.
pub fn detect_profile(source_path: &Path) -> Result<BootProfile, ProfileError> {
    if is_tar_gz(source_path) {
        detect_from_tar_gz(source_path)
    } else {
        detect_from_iso(source_path)
    }
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

trait SourceFs {
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

impl<R: cdfs::ISO9660Reader> SourceFs for CdfsIso<R> {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
        match self.iso.open(path).map_err(|e| {
            ProfileError::SourceUnreadable(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })? {
            Some(DirectoryEntry::File(f)) => {
                let mut buf = Vec::new();
                f.read()
                    .read_to_end(&mut buf)
                    .map_err(|e| ProfileError::SourceUnreadable(self.path.clone(), e))?;
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
                ProfileError::SourceUnreadable(
                    self.path.clone(),
                    io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
                )
            })
    }
}

struct MemorySourceFs {
    files: HashMap<String, Vec<u8>>,
    dirs: HashSet<String>,
}

impl MemorySourceFs {
    fn new() -> Self {
        Self {
            files: HashMap::new(),
            dirs: HashSet::new(),
        }
    }

    #[cfg(test)]
    fn with_dir(mut self, path: &str) -> Self {
        self.insert_dir(path);
        self
    }

    #[cfg(test)]
    fn with_file(mut self, path: &str, content: &[u8]) -> Self {
        self.insert_file(path, content.to_vec());
        self
    }

    fn insert_dir(&mut self, path: &str) {
        self.dirs.insert(normalize_path(path));
    }

    fn insert_file(&mut self, path: &str, contents: Vec<u8>) {
        let normalized = normalize_path(path);
        self.files.insert(normalized.clone(), contents);

        let mut current = normalized.as_str();
        while let Some((parent, _)) = current.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            self.dirs.insert(parent.to_string());
            current = parent;
        }
    }
}

impl SourceFs for MemorySourceFs {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
        Ok(self.files.get(&normalize_path(path)).cloned())
    }

    fn path_exists(&self, path: &str) -> Result<bool, ProfileError> {
        let normalized = normalize_path(path);
        Ok(self.files.contains_key(&normalized) || self.dirs.contains(&normalized))
    }
}

// ---------------------------------------------------------------------------
// Detection logic
// ---------------------------------------------------------------------------

fn detect_from_iso(iso_path: &Path) -> Result<BootProfile, ProfileError> {
    let file = std::fs::File::open(iso_path)
        .map_err(|e| ProfileError::SourceUnreadable(iso_path.to_path_buf(), e))?;
    let iso = ISO9660::new(file).map_err(|e| {
        ProfileError::SourceUnreadable(
            iso_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    detect_from_fs(&CdfsIso {
        iso,
        path: iso_path.to_path_buf(),
    })
}

fn detect_from_tar_gz(source_path: &Path) -> Result<BootProfile, ProfileError> {
    let file = std::fs::File::open(source_path)
        .map_err(|e| ProfileError::SourceUnreadable(source_path.to_path_buf(), e))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let mut source = MemorySourceFs::new();
    let entries = archive.entries().map_err(|e| {
        ProfileError::SourceUnreadable(
            source_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| {
            ProfileError::SourceUnreadable(
                source_path.to_path_buf(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;
        let path = entry.path().map_err(|e| {
            ProfileError::SourceUnreadable(
                source_path.to_path_buf(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;
        let normalized = normalize_path(path.to_string_lossy().as_ref());

        if entry.header().entry_type().is_dir() {
            source.insert_dir(&normalized);
            continue;
        }

        if !entry.header().entry_type().is_file() {
            continue;
        }

        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|e| ProfileError::SourceUnreadable(source_path.to_path_buf(), e))?;
        source.insert_file(&normalized, contents);
    }

    detect_from_fs(&source)
}

fn detect_from_fs(source: &dyn SourceFs) -> Result<BootProfile, ProfileError> {
    // Ubuntu: /.disk/info contains "Ubuntu"
    if let Some(info_bytes) = source.read_file("/.disk/info")? {
        if String::from_utf8_lossy(&info_bytes).contains("Ubuntu") {
            let label = String::from_utf8_lossy(&info_bytes)
                .lines()
                .next()
                .unwrap_or("Ubuntu")
                .trim()
                .to_string();

            for path in ["/casper/vmlinuz", "/casper/initrd"] {
                if !source.path_exists(path)? {
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
    if source.path_exists("/debian")? {
        for path in ["/install.amd/vmlinuz", "/install.amd/initrd.gz"] {
            if !source.path_exists(path)? {
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

    if source.path_exists("/ubuntu-installer/amd64")? {
        for path in [
            "/ubuntu-installer/amd64/linux",
            "/ubuntu-installer/amd64/initrd.gz",
        ] {
            if !source.path_exists(path)? {
                return Err(ProfileError::MissingFile {
                    path: path.to_string(),
                });
            }
        }

        return Ok(BootProfile {
            distro: Distro::Ubuntu,
            kernel_path: "/ubuntu-installer/amd64/linux".to_string(),
            initrd_path: "/ubuntu-installer/amd64/initrd.gz".to_string(),
            boot_params: String::new(),
            label: "Ubuntu Netboot".to_string(),
        });
    }

    if source.path_exists("/debian-installer/amd64")? {
        for path in [
            "/debian-installer/amd64/linux",
            "/debian-installer/amd64/initrd.gz",
        ] {
            if !source.path_exists(path)? {
                return Err(ProfileError::MissingFile {
                    path: path.to_string(),
                });
            }
        }

        return Ok(BootProfile {
            distro: Distro::Debian,
            kernel_path: "/debian-installer/amd64/linux".to_string(),
            initrd_path: "/debian-installer/amd64/initrd.gz".to_string(),
            boot_params: String::new(),
            label: "Debian Netboot".to_string(),
        });
    }

    Err(ProfileError::UnknownDistro)
}

fn is_tar_gz(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".tar.gz") || name.ends_with(".tgz"))
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_start_matches("./").trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_end_matches('/'))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // --- Mock ISO ---

    type MockSource = MemorySourceFs;

    // --- Ubuntu detection ---

    #[test]
    fn ubuntu_detected_from_disk_info() {
        let iso = MockSource::new()
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
        let iso = MockSource::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"");

        let profile = detect_from_fs(&iso).unwrap();
        assert!(profile.boot_params.is_empty());
    }

    #[test]
    fn ubuntu_missing_kernel_returns_missing_file_error() {
        let iso = MockSource::new()
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
        let iso = MockSource::new()
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
        let iso = MockSource::new()
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
        let iso = MockSource::new()
            .with_dir("/debian")
            // /install.amd/vmlinuz absent
            .with_file("/install.amd/initrd.gz", b"");

        let err = detect_from_fs(&iso).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/install.amd/vmlinuz"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    // --- Netboot archive detection ---

    #[test]
    fn ubuntu_netboot_detected_from_installer_tree() {
        let source = MockSource::new()
            .with_dir("/ubuntu-installer/amd64")
            .with_file("/ubuntu-installer/amd64/linux", b"")
            .with_file("/ubuntu-installer/amd64/initrd.gz", b"");

        let profile = detect_from_fs(&source).unwrap();
        assert_eq!(profile.distro, Distro::Ubuntu);
        assert_eq!(profile.kernel_path, "/ubuntu-installer/amd64/linux");
        assert_eq!(profile.initrd_path, "/ubuntu-installer/amd64/initrd.gz");
        assert_eq!(profile.label, "Ubuntu Netboot");
    }

    #[test]
    fn debian_netboot_detected_from_installer_tree() {
        let source = MockSource::new()
            .with_dir("/debian-installer/amd64")
            .with_file("/debian-installer/amd64/linux", b"")
            .with_file("/debian-installer/amd64/initrd.gz", b"");

        let profile = detect_from_fs(&source).unwrap();
        assert_eq!(profile.distro, Distro::Debian);
        assert_eq!(profile.kernel_path, "/debian-installer/amd64/linux");
        assert_eq!(profile.initrd_path, "/debian-installer/amd64/initrd.gz");
        assert_eq!(profile.label, "Debian Netboot");
    }

    #[test]
    fn ubuntu_netboot_missing_initrd_returns_missing_file_error() {
        let source = MockSource::new()
            .with_dir("/ubuntu-installer/amd64")
            .with_file("/ubuntu-installer/amd64/linux", b"");

        let err = detect_from_fs(&source).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => {
                assert_eq!(path, "/ubuntu-installer/amd64/initrd.gz")
            }
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    // --- UnknownDistro ---

    #[test]
    fn unknown_distro_when_no_markers_present() {
        let source = MockSource::new();
        let err = detect_from_fs(&source).unwrap_err();
        assert!(matches!(err, ProfileError::UnknownDistro));
    }

    // --- Detection order ---

    #[test]
    fn ubuntu_takes_precedence_over_debian_markers() {
        let iso = MockSource::new()
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
        assert!(
            !script.contains('\r'),
            "script must use LF-only line endings"
        );
    }

    #[test]
    fn normalize_path_handles_tar_entry_variants() {
        assert_eq!(
            normalize_path("./debian-installer/amd64/linux"),
            "/debian-installer/amd64/linux"
        );
        assert_eq!(
            normalize_path("debian-installer/amd64/linux/"),
            "/debian-installer/amd64/linux"
        );
        assert_eq!(
            normalize_path("/debian-installer/amd64/linux"),
            "/debian-installer/amd64/linux"
        );
    }
}
