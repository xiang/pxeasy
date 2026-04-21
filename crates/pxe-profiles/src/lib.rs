use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use cdfs::{DirectoryEntry, ExtraAttributes, ISO9660};
use flate2::read::GzDecoder;
use tar::Archive;

pub use error::ProfileError;
mod error;
mod freebsd;
pub mod ubuntu;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The detected distribution / OS family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Distro {
    Ubuntu,
    Debian,
    FreeBSD,
    Windows,
    Unknown,
}

/// The detected source layout / boot flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSourceKind {
    UbuntuLiveIso,
    DebianInstallerIso,
    DebianNetboot,
    FreeBSDBootOnly,
    WindowsIso,
    Unknown,
}

/// The boot architecture inferred from source metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    Unknown,
    Amd64,
    Arm64,
}

impl Architecture {
    pub fn slug(self) -> Option<&'static str> {
        match self {
            Self::Unknown => None,
            Self::Amd64 => Some("amd64"),
            Self::Arm64 => Some("arm64"),
        }
    }

    pub fn serial_console(self) -> Option<&'static str> {
        match self {
            Self::Unknown => None,
            Self::Amd64 => Some("ttyS0"),
            Self::Arm64 => Some("ttyAMA0"),
        }
    }
}

/// Boot-source-specific metadata, discriminated by OS type.
#[derive(Debug, Clone)]
pub enum BootSource {
    Linux {
        kernel_path: String,
        initrd_path: String,
        boot_params: String,
    },
    Windows {
        bootmgr_path: String,
        bcd_path: String,
        boot_sdi_path: String,
        boot_wim_path: String,
        install_wim_path: String,
    },
}

/// A boot profile derived from inspecting an ISO image.
#[derive(Debug, Clone)]
pub struct BootProfile {
    pub distro: Distro,
    pub source_kind: BootSourceKind,
    pub architecture: Architecture,
    pub source: BootSource,
    /// Path to the EFI loader within the ISO (if any).
    pub efi_path: Option<String>,
    /// Human-readable label, e.g. "Ubuntu 24.04 LTS".
    pub label: String,
}

/// Byte range of a file stored inside an ISO image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoSlice {
    pub offset: u64,
    pub length: u64,
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
    if let Some(profile) = freebsd::detect_profile(source_path) {
        return Ok(profile);
    }

    if is_tar_gz(source_path) {
        detect_from_tar_gz(source_path)
    } else {
        detect_from_iso(source_path)
    }
}

/// Load a file from the detected boot source.
pub fn load_file(source_path: &Path, file_path: &str) -> Result<Vec<u8>, ProfileError> {
    if is_tar_gz(source_path) {
        load_file_from_tar_gz(source_path, file_path)
    } else {
        load_file_from_iso(source_path, file_path)
    }
}

/// Return the byte offset and length of a file inside an ISO image.
pub fn load_file_slice(source_path: &Path, file_path: &str) -> Result<IsoSlice, ProfileError> {
    if is_tar_gz(source_path) {
        return Err(ProfileError::SourceUnreadable(
            source_path.to_path_buf(),
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("file slices are only supported for ISO sources: {file_path}"),
            ),
        ));
    }

    load_file_slice_from_iso(source_path, file_path)
}

/// List all files in the detected boot source that start with `prefix`.
pub fn list_files(source_path: &Path, prefix: &str) -> Result<Vec<String>, ProfileError> {
    if is_tar_gz(source_path) {
        let source = load_tar_gz_source(source_path)?;
        source.list_files(prefix)
    } else {
        let file = std::fs::File::open(source_path)
            .map_err(|e| ProfileError::SourceUnreadable(source_path.to_path_buf(), e))?;
        let iso = ISO9660::new(file).map_err(|e| {
            ProfileError::SourceUnreadable(
                source_path.to_path_buf(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;
        let source = CdfsIso {
            iso,
            path: source_path.to_path_buf(),
        };
        source.list_files(prefix)
    }
}

/// Load all files from the detected boot source into memory.
pub fn load_all_files(source_path: &Path) -> Result<HashMap<String, Vec<u8>>, ProfileError> {
    if is_tar_gz(source_path) {
        let source = load_tar_gz_source(source_path)?;
        Ok(source.files)
    } else {
        let file = std::fs::File::open(source_path)
            .map_err(|e| ProfileError::SourceUnreadable(source_path.to_path_buf(), e))?;
        let iso = ISO9660::new(file).map_err(|e| {
            ProfileError::SourceUnreadable(
                source_path.to_path_buf(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;
        let source = CdfsIso {
            iso,
            path: source_path.to_path_buf(),
        };

        let mut out = HashMap::new();
        let paths = source.list_files("/")?;
        for path in paths {
            if let Ok(Some(content)) = source.read_file(&path) {
                out.insert(path, content);
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal ISO abstraction — allows unit-testing without a real ISO image
// ---------------------------------------------------------------------------

pub(crate) trait SourceFs {
    /// Read the full contents of a file at `path`, or `None` if the path does
    /// not exist or is not a file.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError>;
    /// Return the byte range of a file at `path`, or `None` if the path does
    /// not exist or is not a regular file.
    fn file_slice(&self, path: &str) -> Result<Option<IsoSlice>, ProfileError> {
        let _ = path;
        Ok(None)
    }
    /// Return `true` if `path` exists (file *or* directory).
    fn path_exists(&self, path: &str) -> Result<bool, ProfileError>;
    /// Return all file paths starting with `prefix`.
    fn list_files(&self, prefix: &str) -> Result<Vec<String>, ProfileError>;
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

    fn file_slice(&self, path: &str) -> Result<Option<IsoSlice>, ProfileError> {
        match self.iso.open(path).map_err(|e| {
            ProfileError::SourceUnreadable(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })? {
            Some(DirectoryEntry::File(file)) => {
                let header = file.header();
                Ok(Some(IsoSlice {
                    offset: u64::from(header.extent_loc) * u64::from(cdfs::BLOCK_SIZE),
                    length: u64::from(header.extent_length),
                }))
            }
            _ => Ok(None),
        }
    }

    fn list_files(&self, prefix: &str) -> Result<Vec<String>, ProfileError> {
        let mut out = Vec::new();
        let prefix = normalize_path(prefix);
        self.walk_dir("/", &prefix, &mut out)?;
        Ok(out)
    }
}

impl<R: cdfs::ISO9660Reader> CdfsIso<R> {
    fn walk_dir(
        &self,
        path: &str,
        prefix: &str,
        out: &mut Vec<String>,
    ) -> Result<(), ProfileError> {
        let entry = self.iso.open(path).map_err(|e| {
            ProfileError::SourceUnreadable(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;

        if let Some(DirectoryEntry::Directory(dir)) = entry {
            for entry_result in dir.contents() {
                let entry = entry_result.map_err(|e| {
                    ProfileError::SourceUnreadable(
                        self.path.clone(),
                        io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
                    )
                })?;

                let name = entry.identifier();
                if name == "." || name == ".." {
                    continue;
                }

                let full_path = if path == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", path, name)
                };

                if full_path.starts_with(prefix) {
                    if let DirectoryEntry::File(_) = entry {
                        out.push(full_path.clone());
                    }
                }

                if let DirectoryEntry::Directory(_) = entry {
                    self.walk_dir(&full_path, prefix, out)?;
                }
            }
        }
        Ok(())
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

    fn list_files(&self, prefix: &str) -> Result<Vec<String>, ProfileError> {
        let prefix = normalize_path(prefix);
        let mut out: Vec<_> = self
            .files
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        out.sort();
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Detection logic
// ---------------------------------------------------------------------------

fn detect_from_iso(iso_path: &Path) -> Result<BootProfile, ProfileError> {
    let volume_label = read_iso_volume_label(iso_path);
    let file = std::fs::File::open(iso_path)
        .map_err(|e| ProfileError::SourceUnreadable(iso_path.to_path_buf(), e))?;
    let iso = ISO9660::new(file).map_err(|e| {
        ProfileError::SourceUnreadable(
            iso_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    let filename = iso_path.file_name().and_then(|n| n.to_str());
    detect_from_source(
        &CdfsIso {
            iso,
            path: iso_path.to_path_buf(),
        },
        filename,
        volume_label.as_deref(),
    )
}

fn read_iso_volume_label(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    // ISO 9660 PVD at sector 16 (offset 32768), volume identifier at offset 40 within PVD
    file.seek(SeekFrom::Start(32768 + 40)).ok()?;
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf).ok()?;
    let label = std::str::from_utf8(&buf)
        .ok()?
        .trim_end()
        .trim()
        .to_string();
    if label.is_empty() {
        None
    } else {
        Some(label)
    }
}

fn load_file_from_iso(iso_path: &Path, file_path: &str) -> Result<Vec<u8>, ProfileError> {
    let file = std::fs::File::open(iso_path)
        .map_err(|e| ProfileError::SourceUnreadable(iso_path.to_path_buf(), e))?;
    let iso = ISO9660::new(file).map_err(|e| {
        ProfileError::SourceUnreadable(
            iso_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    let source = CdfsIso {
        iso,
        path: iso_path.to_path_buf(),
    };
    source
        .read_file(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn load_file_slice_from_iso(source_path: &Path, file_path: &str) -> Result<IsoSlice, ProfileError> {
    let file = std::fs::File::open(source_path)
        .map_err(|e| ProfileError::SourceUnreadable(source_path.to_path_buf(), e))?;
    let iso = ISO9660::new(file).map_err(|e| {
        ProfileError::SourceUnreadable(
            source_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;
    let source = CdfsIso {
        iso,
        path: source_path.to_path_buf(),
    };

    source
        .file_slice(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn detect_from_tar_gz(source_path: &Path) -> Result<BootProfile, ProfileError> {
    let source = load_tar_gz_source(source_path)?;
    let filename = source_path.file_name().and_then(|n| n.to_str());
    detect_from_source(&source, filename, None)
}

fn load_file_from_tar_gz(source_path: &Path, file_path: &str) -> Result<Vec<u8>, ProfileError> {
    load_tar_gz_source(source_path)?
        .read_file(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn load_tar_gz_source(source_path: &Path) -> Result<MemorySourceFs, ProfileError> {
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

    Ok(source)
}

fn detect_from_source(
    source: &dyn SourceFs,
    filename: Option<&str>,
    volume_label: Option<&str>,
) -> Result<BootProfile, ProfileError> {
    if let Some(profile) = freebsd::detect_from_source(source, filename)? {
        return Ok(profile);
    }

    // Windows: sources/install.wim or sources/install.esd present
    let install_wim = if source.path_exists("/sources/install.wim")? {
        Some("/sources/install.wim".to_string())
    } else if source.path_exists("/sources/install.esd")? {
        Some("/sources/install.esd".to_string())
    } else {
        None
    };

    if let Some(install_wim_path) = install_wim {
        for required in [
            "/bootmgr",
            "/boot/bcd",
            "/boot/boot.sdi",
            "/sources/boot.wim",
        ] {
            if !source.path_exists(required)? {
                return Err(ProfileError::MissingFile {
                    path: required.to_string(),
                });
            }
        }

        let efi_path = select_first_existing_path(
            source,
            &["/efi/boot/bootx64.efi", "/efi/boot/bootaa64.efi"],
        )?;

        let architecture = if source.path_exists("/efi/boot/bootx64.efi")? {
            Architecture::Amd64
        } else if source.path_exists("/efi/boot/bootaa64.efi")? {
            Architecture::Arm64
        } else {
            Architecture::Amd64
        };

        let label = volume_label
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Windows (detected)".to_string());

        return Ok(BootProfile {
            distro: Distro::Windows,
            source_kind: BootSourceKind::WindowsIso,
            architecture,
            source: BootSource::Windows {
                bootmgr_path: "/bootmgr".to_string(),
                bcd_path: "/boot/bcd".to_string(),
                boot_sdi_path: "/boot/boot.sdi".to_string(),
                boot_wim_path: "/sources/boot.wim".to_string(),
                install_wim_path,
            },
            efi_path,
            label,
        });
    }

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

            let efi_path = select_first_existing_path(
                source,
                &[
                    "/EFI/BOOT/BOOTX64.EFI",
                    "/EFI/BOOT/BOOTAA64.EFI",
                    "/EFI/BOOT/shimx64.efi",
                    "/EFI/BOOT/shimaa64.efi",
                    "/EFI/BOOT/grubx64.efi",
                    "/EFI/BOOT/grubaa64.efi",
                    "/EFI/ubuntu/shimx64.efi",
                    "/EFI/ubuntu/grubx64.efi",
                    "/EFI/debian/shimx64.efi",
                    "/EFI/debian/grubx64.efi",
                ],
            )?;

            return Ok(BootProfile {
                distro: Distro::Ubuntu,
                source_kind: BootSourceKind::UbuntuLiveIso,
                architecture: detect_architecture(source, &[&label], &efi_path, &["/casper"])?,
                source: BootSource::Linux {
                    kernel_path: "/casper/vmlinuz".to_string(),
                    initrd_path: "/casper/initrd".to_string(),
                    boot_params: String::new(),
                },
                efi_path,
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

        let efi_path = select_first_existing_path(
            source,
            &[
                "/EFI/BOOT/BOOTX64.EFI",
                "/EFI/BOOT/BOOTAA64.EFI",
                "/EFI/BOOT/shimx64.efi",
                "/EFI/BOOT/shimaa64.efi",
                "/EFI/BOOT/grubx64.efi",
                "/EFI/BOOT/grubaa64.efi",
                "/EFI/ubuntu/shimx64.efi",
                "/EFI/ubuntu/grubx64.efi",
                "/EFI/debian/shimx64.efi",
                "/EFI/debian/grubx64.efi",
            ],
        )?;

        return Ok(BootProfile {
            distro: Distro::Debian,
            source_kind: BootSourceKind::DebianInstallerIso,
            architecture: detect_architecture(source, &["Debian"], &efi_path, &["/install.amd"])?,
            source: BootSource::Linux {
                kernel_path: "/install.amd/vmlinuz".to_string(),
                initrd_path: "/install.amd/initrd.gz".to_string(),
                boot_params: String::new(),
            },
            efi_path,
            label: "Debian".to_string(),
        });
    }

    for arch in ["amd64", "arm64"] {
        let kernel_path = format!("/debian-installer/{arch}/linux");
        let initrd_path = format!("/debian-installer/{arch}/initrd.gz");

        if source.path_exists(&kernel_path)? || source.path_exists(&initrd_path)? {
            for path in [&kernel_path, &initrd_path] {
                if !source.path_exists(path)? {
                    return Err(ProfileError::MissingFile { path: path.clone() });
                }
            }

            let efi_path = select_first_existing_path(
                source,
                &[
                    &format!("/debian-installer/{arch}/bootnetaa64.efi"),
                    &format!("/debian-installer/{arch}/grubaa64.efi"),
                    &format!("/debian-installer/{arch}/bootnetx64.efi"),
                    &format!("/debian-installer/{arch}/grubx64.efi"),
                    "/EFI/BOOT/BOOTX64.EFI",
                    "/EFI/BOOT/BOOTAA64.EFI",
                    "/EFI/BOOT/shimx64.efi",
                    "/EFI/BOOT/shimaa64.efi",
                    "/EFI/BOOT/grubx64.efi",
                    "/EFI/BOOT/grubaa64.efi",
                ],
            )?;

            return Ok(BootProfile {
                distro: Distro::Debian,
                source_kind: BootSourceKind::DebianNetboot,
                architecture: match arch {
                    "amd64" => Architecture::Amd64,
                    "arm64" => Architecture::Arm64,
                    _ => return Err(ProfileError::UnknownDistro),
                },
                source: BootSource::Linux {
                    kernel_path,
                    initrd_path,
                    boot_params: String::new(),
                },
                efi_path,
                label: format!("Debian Netboot ({arch})"),
            });
        }
    }

    Err(ProfileError::UnknownDistro)
}

fn select_first_existing_path(
    source: &dyn SourceFs,
    candidates: &[&str],
) -> Result<Option<String>, ProfileError> {
    for path in candidates {
        if source.path_exists(path)? {
            return Ok(Some((*path).to_string()));
        }
    }

    Ok(None)
}

pub(crate) fn detect_architecture(
    source: &dyn SourceFs,
    text_hints: &[&str],
    efi_path: &Option<String>,
    path_hints: &[&str],
) -> Result<Architecture, ProfileError> {
    for hint in text_hints {
        if let Some(arch) = architecture_from_text(hint) {
            return Ok(arch);
        }
    }

    if let Some(path) = efi_path.as_deref() {
        if let Some(arch) = architecture_from_path(path) {
            return Ok(arch);
        }
    }

    for hint in path_hints {
        if let Some(arch) = architecture_from_path(hint) {
            return Ok(arch);
        }
    }

    if source.path_exists("/EFI/BOOT/BOOTAA64.EFI")?
        || source.path_exists("/EFI/BOOT/grubaa64.efi")?
        || source.path_exists("/EFI/BOOT/shimaa64.efi")?
    {
        return Ok(Architecture::Arm64);
    }

    if source.path_exists("/EFI/BOOT/BOOTX64.EFI")?
        || source.path_exists("/EFI/BOOT/grubx64.efi")?
        || source.path_exists("/EFI/BOOT/shimx64.efi")?
    {
        return Ok(Architecture::Amd64);
    }

    Ok(Architecture::Unknown)
}

fn architecture_from_text(value: &str) -> Option<Architecture> {
    let value = value.to_ascii_lowercase();
    if value.contains("arm64") || value.contains("aarch64") || value.contains("aa64") {
        Some(Architecture::Arm64)
    } else if value.contains("amd64") || value.contains("x86_64") || value.contains("x64") {
        Some(Architecture::Amd64)
    } else {
        None
    }
}

pub(crate) fn architecture_from_path(path: &str) -> Option<Architecture> {
    let path = path.to_ascii_lowercase();
    if path.contains("bootaa64.efi")
        || path.contains("grubaa64.efi")
        || path.contains("shimaa64.efi")
        || path.contains("/arm64/")
        || path.contains("aarch64")
    {
        Some(Architecture::Arm64)
    } else if path.contains("bootx64.efi")
        || path.contains("grubx64.efi")
        || path.contains("shimx64.efi")
        || path.contains("/amd64/")
        || path.contains("/install.amd/")
        || path.contains("x86_64")
    {
        Some(Architecture::Amd64)
    } else {
        None
    }
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

    fn linux_source(profile: &BootProfile) -> (&str, &str, &str) {
        match &profile.source {
            BootSource::Linux {
                kernel_path,
                initrd_path,
                boot_params,
            } => (
                kernel_path.as_str(),
                initrd_path.as_str(),
                boot_params.as_str(),
            ),
            _ => panic!("expected BootSource::Linux"),
        }
    }

    #[test]
    fn ubuntu_detected_from_disk_info() {
        let iso = MockSource::new()
            .with_file(
                "/.disk/info",
                b"Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240821)",
            )
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"")
            .with_file("/EFI/BOOT/BOOTX64.EFI", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        assert_eq!(profile.distro, Distro::Ubuntu);
        assert_eq!(profile.source_kind, BootSourceKind::UbuntuLiveIso);
        assert_eq!(profile.architecture, Architecture::Amd64);
        let (kp, ip, _) = linux_source(&profile);
        assert_eq!(kp, "/casper/vmlinuz");
        assert_eq!(ip, "/casper/initrd");
        assert_eq!(profile.efi_path, Some("/EFI/BOOT/BOOTX64.EFI".to_string()));
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

        let profile = detect_from_source(&iso, None, None).unwrap();
        let (_, _, bp) = linux_source(&profile);
        assert!(bp.is_empty());
        assert_eq!(profile.architecture, Architecture::Unknown);
    }

    #[test]
    fn ubuntu_missing_kernel_returns_missing_file_error() {
        let iso = MockSource::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            // /casper/vmlinuz absent
            .with_file("/casper/initrd", b"");

        let err = detect_from_source(&iso, None, None).unwrap_err();
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

        let err = detect_from_source(&iso, None, None).unwrap_err();
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
            .with_file("/install.amd/initrd.gz", b"")
            .with_file("/EFI/BOOT/BOOTX64.EFI", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        assert_eq!(profile.distro, Distro::Debian);
        assert_eq!(profile.source_kind, BootSourceKind::DebianInstallerIso);
        assert_eq!(profile.architecture, Architecture::Amd64);
        let (kp, ip, _) = linux_source(&profile);
        assert_eq!(kp, "/install.amd/vmlinuz");
        assert_eq!(ip, "/install.amd/initrd.gz");
        assert_eq!(profile.efi_path, Some("/EFI/BOOT/BOOTX64.EFI".to_string()));
        assert_eq!(profile.label, "Debian");
    }

    #[test]
    fn debian_missing_kernel_returns_missing_file_error() {
        let iso = MockSource::new()
            .with_dir("/debian")
            // /install.amd/vmlinuz absent
            .with_file("/install.amd/initrd.gz", b"");

        let err = detect_from_source(&iso, None, None).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/install.amd/vmlinuz"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    // --- Netboot archive detection ---

    #[test]
    fn debian_netboot_detected_from_installer_tree() {
        let source = MockSource::new()
            .with_dir("/debian-installer/arm64")
            .with_file("/debian-installer/arm64/linux", b"")
            .with_file("/debian-installer/arm64/initrd.gz", b"")
            .with_file("/debian-installer/arm64/grubaa64.efi", b"");

        let profile = detect_from_source(&source, None, None).unwrap();
        assert_eq!(profile.distro, Distro::Debian);
        assert_eq!(profile.source_kind, BootSourceKind::DebianNetboot);
        assert_eq!(profile.architecture, Architecture::Arm64);
        let (kp, ip, bp) = linux_source(&profile);
        assert_eq!(kp, "/debian-installer/arm64/linux");
        assert_eq!(ip, "/debian-installer/arm64/initrd.gz");
        assert_eq!(
            profile.efi_path,
            Some("/debian-installer/arm64/grubaa64.efi".to_string())
        );
        assert_eq!(profile.label, "Debian Netboot (arm64)");
        assert!(bp.is_empty());
    }

    // --- UnknownDistro ---

    #[test]
    fn unknown_distro_when_no_markers_present() {
        let source = MockSource::new();
        let err = detect_from_source(&source, None, None).unwrap_err();
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

        let profile = detect_from_source(&iso, None, None).unwrap();
        assert_eq!(profile.distro, Distro::Ubuntu);
        assert_eq!(profile.architecture, Architecture::Unknown);
    }

    #[test]
    fn ubuntu_arm64_arch_detected_from_disk_info_without_efi_path() {
        let iso = MockSource::new()
            .with_file("/.disk/info", b"Ubuntu 24.04.1 LTS - Release arm64")
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        assert_eq!(profile.architecture, Architecture::Arm64);
    }

    #[test]
    fn ubuntu_arm64_arch_detected_from_efi_filename_when_label_is_generic() {
        let iso = MockSource::new()
            .with_file("/.disk/info", b"Ubuntu 24.04 LTS")
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"")
            .with_file("/EFI/BOOT/BOOTAA64.EFI", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        assert_eq!(profile.architecture, Architecture::Arm64);
    }

    #[test]
    fn ubuntu_netboot_tarball_is_rejected() {
        let iso = MockSource::new()
            .with_dir("/arm64")
            .with_dir("/arm64/grub")
            .with_file("/arm64/linux", b"")
            .with_file("/arm64/initrd", b"")
            .with_file("/arm64/bootaa64.efi", b"")
            .with_file(
                "/arm64/grub/grub.cfg",
                b"menuentry \"Install Ubuntu Server\" {\n linux linux iso-url=http://example.invalid/ubuntu.iso ip=dhcp ---\n initrd initrd\n}\n",
            );

        let err = detect_from_source(&iso, None, None).unwrap_err();
        assert!(matches!(err, ProfileError::UnknownDistro));
    }

    // --- FreeBSD detection ---

    #[test]
    fn freebsd_detected_from_boot_kernel_and_loader() {
        let iso = MockSource::new()
            .with_file("/boot/kernel/kernel", b"")
            .with_file("/boot/loader.efi", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        assert_eq!(profile.distro, Distro::FreeBSD);
        assert_eq!(profile.source_kind, BootSourceKind::FreeBSDBootOnly);
        let (kp, _, _) = linux_source(&profile);
        assert_eq!(kp, "/boot/loader.efi");
        assert_eq!(profile.efi_path, Some("/boot/loader.efi".to_string()));
        assert_eq!(profile.label, "FreeBSD");
    }

    #[test]
    fn freebsd_profile_detected_from_mini_img_filename() {
        let profile = detect_profile(Path::new("FreeBSD-15.0-RELEASE-arm64-aarch64-mini.img"))
            .expect("freebsd mini img profile");

        assert_eq!(profile.distro, Distro::FreeBSD);
        assert_eq!(profile.source_kind, BootSourceKind::FreeBSDBootOnly);
        assert_eq!(profile.architecture, Architecture::Arm64);
        assert_eq!(profile.efi_path, Some("/boot/loader.efi".to_string()));
    }

    // --- Windows detection ---

    #[test]
    fn windows_detected_from_install_wim() {
        let source = MockSource::new()
            .with_file("/bootmgr", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.wim", b"")
            .with_file("/sources/boot.wim", b"")
            .with_file("/boot/bcd", b"")
            .with_file("/efi/boot/bootx64.efi", b"");

        let profile = detect_from_source(&source, None, Some("CCCOMA_X64FRE_EN-US_DV9")).unwrap();
        assert_eq!(profile.distro, Distro::Windows);
        assert_eq!(profile.source_kind, BootSourceKind::WindowsIso);
        assert_eq!(profile.architecture, Architecture::Amd64);
        assert_eq!(profile.label, "CCCOMA_X64FRE_EN-US_DV9");
        match &profile.source {
            BootSource::Windows {
                install_wim_path,
                boot_wim_path,
                bcd_path,
                ..
            } => {
                assert_eq!(install_wim_path, "/sources/install.wim");
                assert_eq!(boot_wim_path, "/sources/boot.wim");
                assert_eq!(bcd_path, "/boot/bcd");
            }
            _ => panic!("expected BootSource::Windows"),
        }
    }

    #[test]
    fn windows_detected_from_install_esd() {
        let source = MockSource::new()
            .with_file("/bootmgr", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.esd", b"")
            .with_file("/sources/boot.wim", b"")
            .with_file("/boot/bcd", b"");

        let profile = detect_from_source(&source, None, None).unwrap();
        assert_eq!(profile.distro, Distro::Windows);
        match &profile.source {
            BootSource::Windows {
                install_wim_path, ..
            } => {
                assert_eq!(install_wim_path, "/sources/install.esd");
            }
            _ => panic!("expected BootSource::Windows"),
        }
    }

    #[test]
    fn windows_fallback_label_when_volume_label_absent() {
        let source = MockSource::new()
            .with_file("/bootmgr", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.wim", b"")
            .with_file("/sources/boot.wim", b"")
            .with_file("/boot/bcd", b"");

        let profile = detect_from_source(&source, None, None).unwrap();
        assert_eq!(profile.label, "Windows (detected)");
    }

    #[test]
    fn windows_missing_boot_wim_returns_error() {
        let source = MockSource::new()
            .with_file("/bootmgr", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.wim", b"")
            // /sources/boot.wim absent
            .with_file("/boot/bcd", b"");

        let err = detect_from_source(&source, None, None).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/sources/boot.wim"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    #[test]
    fn windows_missing_bcd_returns_error() {
        let source = MockSource::new()
            .with_file("/bootmgr", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.wim", b"")
            .with_file("/sources/boot.wim", b"");
        // /boot/bcd absent

        let err = detect_from_source(&source, None, None).unwrap_err();
        match err {
            ProfileError::MissingFile { path } => assert_eq!(path, "/boot/bcd"),
            other => panic!("expected MissingFile, got {other}"),
        }
    }

    #[test]
    fn windows_amd64_default_when_no_efi_markers() {
        let source = MockSource::new()
            .with_file("/bootmgr", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.wim", b"")
            .with_file("/sources/boot.wim", b"")
            .with_file("/boot/bcd", b"");

        let profile = detect_from_source(&source, None, None).unwrap();
        assert_eq!(profile.architecture, Architecture::Amd64);
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
