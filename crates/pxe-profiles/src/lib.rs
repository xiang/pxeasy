use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
};

pub use pxe_iso::{normalize_path, CdfsIso, IsoError, IsoSlice, SourceFs, UdfIso};

pub use error::ProfileError;
mod error;
mod freebsd;
pub mod ubuntu;
mod windows;

impl From<IsoError> for ProfileError {
    fn from(err: IsoError) -> Self {
        match err {
            IsoError::Io(e) => ProfileError::SourceUnreadable(PathBuf::from("<iso>"), e),
            IsoError::InvalidData(s) => ProfileError::SourceUnreadable(
                PathBuf::from("<iso>"),
                io::Error::new(io::ErrorKind::InvalidData, s),
            ),
            IsoError::NotFound(s) => ProfileError::MissingFile { path: s },
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The detected platform / OS family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
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

#[derive(Debug, Clone)]
pub struct LinuxProfile {
    pub platform: Platform,
    pub source_kind: BootSourceKind,
    pub architecture: Architecture,
    pub efi_path: Option<String>,
    pub label: String,
    pub kernel_path: String,
    pub initrd_path: String,
    pub boot_params: String,
}

#[derive(Debug, Clone)]
pub struct WindowsProfile {
    pub source_kind: BootSourceKind,
    pub architecture: Architecture,
    pub efi_path: Option<String>,
    pub label: String,
    pub bootmgr_path: String,
    pub bcd_path: String,
    pub boot_sdi_path: String,
    pub boot_wim_path: String,
    pub install_wim_path: String,
}

#[derive(Debug, Clone)]
pub enum BootProfile {
    Linux(LinuxProfile),
    Windows(WindowsProfile),
}

impl BootProfile {
    pub fn source_kind(&self) -> BootSourceKind {
        match self {
            Self::Linux(profile) => profile.source_kind,
            Self::Windows(profile) => profile.source_kind,
        }
    }

    pub fn architecture(&self) -> Architecture {
        match self {
            Self::Linux(profile) => profile.architecture,
            Self::Windows(profile) => profile.architecture,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Linux(profile) => &profile.label,
            Self::Windows(profile) => &profile.label,
        }
    }

    pub fn efi_path(&self) -> Option<&str> {
        match self {
            Self::Linux(profile) => profile.efi_path.as_deref(),
            Self::Windows(profile) => profile.efi_path.as_deref(),
        }
    }
}

/// Lightweight metadata for a single entry in a boot source image.
#[derive(Debug, Clone)]
pub struct IsoEntryMeta {
    pub is_dir: bool,
    pub size: u64,
    /// Byte offset of the file's data within the ISO image, if known.
    pub iso_offset: Option<u64>,
    /// Original-case leaf filename (not the full path).
    pub display_name: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inspect `source_path` and return a `BootProfile` for the first matched platform.
pub fn detect_profile(source_path: &Path) -> Result<BootProfile, ProfileError> {
    if let Some(profile) = freebsd::detect_profile(source_path) {
        return Ok(BootProfile::Linux(profile));
    }

    detect_from_iso(source_path)
}

/// Load a file from the detected boot source.
pub fn load_file(source_path: &Path, file_path: &str) -> Result<Vec<u8>, ProfileError> {
    load_file_from_iso(source_path, file_path)
}

/// Return the byte offset and length of a file inside an ISO image.
pub fn load_file_slice(source_path: &Path, file_path: &str) -> Result<IsoSlice, ProfileError> {
    load_file_slice_from_iso(source_path, file_path)
}

/// Load a byte range from a file in the detected boot source.
pub fn load_file_range(
    source_path: &Path,
    file_path: &str,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(source_path)?),
    };

    if let Some(content) = source.read_file_range(file_path, offset, length)? {
        return Ok(content);
    }

    Err(ProfileError::MissingFile {
        path: file_path.to_string(),
    })
}

/// List all files in the detected boot source that start with `prefix`.
pub fn list_dir(source_path: &Path, dir_path: &str) -> Result<Vec<(String, bool)>, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(source_path)?),
    };
    Ok(source.list_dir(dir_path)?)
}

pub fn list_files(source_path: &Path, prefix: &str) -> Result<Vec<String>, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(source_path)?),
    };
    Ok(source.list_files(prefix)?)
}

pub fn build_metadata_map(
    source_path: &Path,
) -> Result<HashMap<String, IsoEntryMeta>, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(source_path)?),
    };

    build_metadata_map_from_source(source.as_ref())
}

fn build_metadata_map_from_source(
    source: &dyn SourceFs,
) -> Result<HashMap<String, IsoEntryMeta>, ProfileError> {
    let mut map = HashMap::new();
    map.insert(
        "/".to_string(),
        IsoEntryMeta {
            is_dir: true,
            size: 0,
            iso_offset: None,
            display_name: String::new(),
        },
    );

    add_metadata_entries(source, "/", &mut map)?;

    Ok(map)
}

fn add_metadata_entries(
    source: &dyn SourceFs,
    dir_path: &str,
    map: &mut HashMap<String, IsoEntryMeta>,
) -> Result<(), ProfileError> {
    for (name, is_dir) in source.list_dir(dir_path)? {
        let path = if dir_path == "/" {
            format!("/{name}")
        } else {
            format!("{dir_path}/{name}")
        };
        let normalized = normalize_path(&path);

        if is_dir {
            map.insert(
                normalized.to_ascii_lowercase(),
                IsoEntryMeta {
                    is_dir: true,
                    size: 0,
                    iso_offset: None,
                    display_name: name,
                },
            );
            add_metadata_entries(source, &normalized, map)?;
        } else {
            let slice = source.file_slice(&normalized)?;
            let size = source
                .file_size(&normalized)?
                .or_else(|| slice.as_ref().map(|s| s.length))
                .unwrap_or(0);
            map.insert(
                normalized.to_ascii_lowercase(),
                IsoEntryMeta {
                    is_dir: false,
                    size,
                    iso_offset: slice.as_ref().map(|s| s.offset),
                    display_name: name,
                },
            );
        }
    }

    Ok(())
}

pub fn load_all_files(source_path: &Path) -> Result<HashMap<String, Vec<u8>>, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(source_path)?),
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

#[cfg(test)]
use std::collections::HashSet;

#[cfg(test)]
struct MemorySourceFs {
    files: HashMap<String, Vec<u8>>,
    dirs: HashSet<String>,
}

#[cfg(test)]
impl MemorySourceFs {
    fn new() -> Self {
        Self {
            files: HashMap::new(),
            dirs: HashSet::new(),
        }
    }

    fn with_dir(mut self, path: &str) -> Self {
        self.insert_dir(path);
        self
    }

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

#[cfg(test)]
impl SourceFs for MemorySourceFs {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, IsoError> {
        Ok(self.files.get(&normalize_path(path)).cloned())
    }

    fn read_file_range(
        &self,
        path: &str,
        offset: u64,
        length: usize,
    ) -> Result<Option<Vec<u8>>, IsoError> {
        let Some(content) = self.files.get(&normalize_path(path)) else {
            return Ok(None);
        };
        let Ok(start) = usize::try_from(offset) else {
            return Ok(Some(Vec::new()));
        };
        if start >= content.len() {
            return Ok(Some(Vec::new()));
        }
        let end = start.saturating_add(length).min(content.len());
        Ok(Some(content[start..end].to_vec()))
    }

    fn path_exists(&self, path: &str) -> Result<bool, IsoError> {
        let normalized = normalize_path(path);
        Ok(self.files.contains_key(&normalized) || self.dirs.contains(&normalized))
    }

    fn list_files(&self, prefix: &str) -> Result<Vec<String>, IsoError> {
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

    fn list_dir(&self, dir_path: &str) -> Result<Vec<(String, bool)>, IsoError> {
        let prefix = normalize_path(dir_path);
        let mut result = Vec::new();
        let mut seen = HashSet::new();

        let dir_prefix = if prefix == "/" {
            "/".to_string()
        } else {
            format!("{}/", prefix)
        };

        for path in self.files.keys() {
            if let Some(rel) = path.strip_prefix(&dir_prefix) {
                let name = rel.split('/').next().unwrap_or("");
                if !name.is_empty() && seen.insert(name.to_string()) {
                    let is_dir = rel.contains('/');
                    result.push((name.to_string(), is_dir));
                }
            }
        }
        for path in &self.dirs {
            if let Some(rel) = path.strip_prefix(&dir_prefix) {
                let name = rel.split('/').next().unwrap_or("");
                if !name.is_empty() && seen.insert(name.to_string()) {
                    result.push((name.to_string(), true));
                }
            }
        }
        result.sort();
        Ok(result)
    }

    fn file_slice(&self, _path: &str) -> Result<Option<IsoSlice>, IsoError> {
        Ok(None)
    }

    fn file_size(&self, path: &str) -> Result<Option<u64>, IsoError> {
        Ok(self
            .files
            .get(&normalize_path(path))
            .map(|bytes| bytes.len() as u64))
    }

    fn volume_label(&self) -> Option<String> {
        None
    }
}

fn detect_from_iso(iso_path: &Path) -> Result<BootProfile, ProfileError> {
    let filename = iso_path.file_name().and_then(|n| n.to_str());

    let source: Box<dyn SourceFs> = match UdfIso::open(iso_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(iso_path)?),
    };

    detect_from_source(source.as_ref(), filename, source.volume_label().as_deref())
}

fn load_file_from_iso(iso_path: &Path, file_path: &str) -> Result<Vec<u8>, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(iso_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(iso_path)?),
    };

    source
        .read_file(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn load_file_slice_from_iso(source_path: &Path, file_path: &str) -> Result<IsoSlice, ProfileError> {
    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => Box::new(CdfsIso::open(source_path)?),
    };

    source
        .file_slice(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn detect_from_source(
    source: &dyn SourceFs,
    filename: Option<&str>,
    volume_label: Option<&str>,
) -> Result<BootProfile, ProfileError> {
    if let Some(profile) = freebsd::detect_from_source(source, filename)? {
        return Ok(BootProfile::Linux(profile));
    }

    if let Some(profile) = windows::detect_from_source(source, volume_label)? {
        return Ok(BootProfile::Windows(profile));
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

            return Ok(BootProfile::Linux(LinuxProfile {
                platform: Platform::Ubuntu,
                source_kind: BootSourceKind::UbuntuLiveIso,
                architecture: detect_architecture(source, &[&label], &efi_path, &["/casper"])?,
                efi_path,
                label,
                kernel_path: "/casper/vmlinuz".to_string(),
                initrd_path: "/casper/initrd".to_string(),
                boot_params: String::new(),
            }));
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

        return Ok(BootProfile::Linux(LinuxProfile {
            platform: Platform::Debian,
            source_kind: BootSourceKind::DebianInstallerIso,
            architecture: detect_architecture(source, &["Debian"], &efi_path, &["/install.amd"])?,
            efi_path,
            label: "Debian".to_string(),
            kernel_path: "/install.amd/vmlinuz".to_string(),
            initrd_path: "/install.amd/initrd.gz".to_string(),
            boot_params: String::new(),
        }));
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // --- Mock ISO ---

    type MockSource = MemorySourceFs;

    // --- Ubuntu detection ---

    fn linux_source(profile: &LinuxProfile) -> (&str, &str, &str) {
        (
            profile.kernel_path.as_str(),
            profile.initrd_path.as_str(),
            profile.boot_params.as_str(),
        )
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
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        assert_eq!(profile.platform, Platform::Ubuntu);
        assert_eq!(profile.source_kind, BootSourceKind::UbuntuLiveIso);
        assert_eq!(profile.architecture, Architecture::Amd64);
        let (kp, ip, _) = linux_source(profile);
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
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        let (_, _, bp) = linux_source(profile);
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
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        assert_eq!(profile.platform, Platform::Debian);
        assert_eq!(profile.source_kind, BootSourceKind::DebianInstallerIso);
        assert_eq!(profile.architecture, Architecture::Amd64);
        let (kp, ip, _) = linux_source(profile);
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
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        assert_eq!(profile.platform, Platform::Ubuntu);
        assert_eq!(profile.architecture, Architecture::Unknown);
    }

    #[test]
    fn ubuntu_arm64_arch_detected_from_disk_info_without_efi_path() {
        let iso = MockSource::new()
            .with_file("/.disk/info", b"Ubuntu 24.04.1 LTS - Release arm64")
            .with_file("/casper/vmlinuz", b"")
            .with_file("/casper/initrd", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
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
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        assert_eq!(profile.architecture, Architecture::Arm64);
    }

    // --- FreeBSD detection ---

    #[test]
    fn freebsd_detected_from_boot_kernel_and_loader() {
        let iso = MockSource::new()
            .with_file("/boot/kernel/kernel", b"")
            .with_file("/boot/loader.efi", b"");

        let profile = detect_from_source(&iso, None, None).unwrap();
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        assert_eq!(profile.platform, Platform::FreeBSD);
        assert_eq!(profile.source_kind, BootSourceKind::FreeBSDBootOnly);
        let (kp, _, _) = linux_source(profile);
        assert_eq!(kp, "/boot/loader.efi");
        assert_eq!(profile.efi_path, Some("/boot/loader.efi".to_string()));
        assert_eq!(profile.label, "FreeBSD");
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
        let BootProfile::Windows(profile) = &profile else {
            panic!("expected BootProfile::Windows");
        };
        assert_eq!(profile.architecture, Architecture::Amd64);
    }

    #[test]
    fn metadata_map_uses_file_size_when_slice_is_unavailable() {
        let source = MockSource::new().with_file("/setup.exe", b"not empty");

        let map = build_metadata_map_from_source(&source).unwrap();
        let meta = map.get("/setup.exe").unwrap();

        assert_eq!(meta.size, 9);
        assert_eq!(meta.iso_offset, None);
        assert_eq!(meta.display_name, "setup.exe");
    }

    #[test]
    fn metadata_map_contains_directories_for_nested_files() {
        let source = MockSource::new()
            .with_file("/setup.exe", b"")
            .with_file("/sources/setuphost.exe", b"host");

        let map = build_metadata_map_from_source(&source).unwrap();
        let dir = map.get("/sources").unwrap();
        let file = map.get("/sources/setuphost.exe").unwrap();

        assert!(dir.is_dir);
        assert_eq!(dir.display_name, "sources");
        assert!(!file.is_dir);
        assert_eq!(file.size, 4);
    }
}
