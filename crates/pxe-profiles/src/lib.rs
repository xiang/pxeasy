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
mod udf;
mod windows;

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

/// Byte range of a file stored inside an ISO image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoSlice {
    pub offset: u64,
    pub length: u64,
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
///
/// # Errors
///
/// - [`ProfileError::SourceUnreadable`] — file cannot be opened or parsed as a supported source.
/// - [`ProfileError::UnknownDistro`] — no supported platform was detected.
/// - [`ProfileError::MissingFile`] — a required file is absent from the detected distro layout.
pub fn detect_profile(source_path: &Path) -> Result<BootProfile, ProfileError> {
    if let Some(profile) = freebsd::detect_profile(source_path) {
        return Ok(BootProfile::Linux(profile));
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

/// Load a byte range from a file in the detected boot source.
pub fn load_file_range(
    source_path: &Path,
    file_path: &str,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, ProfileError> {
    if is_tar_gz(source_path) {
        let bytes = load_file_from_tar_gz(source_path, file_path)?;
        return slice_loaded_file(file_path, &bytes, offset, length);
    }

    if let Ok(source) = udf::UdfIso::open(source_path) {
        return source.read_file_range(file_path, offset, length);
    }

    let slice = load_file_slice_from_iso(source_path, file_path)?;
    if offset > slice.length {
        return Err(ProfileError::MissingFile {
            path: file_path.to_string(),
        });
    }
    let available = slice.length - offset;
    let to_read = length.min(available as usize);
    let mut file = std::fs::File::open(source_path)
        .map_err(|err| ProfileError::SourceUnreadable(source_path.to_path_buf(), err))?;
    file.seek(SeekFrom::Start(slice.offset + offset))
        .map_err(|err| ProfileError::SourceUnreadable(source_path.to_path_buf(), err))?;
    let mut bytes = vec![0u8; to_read];
    file.read_exact(&mut bytes)
        .map_err(|err| ProfileError::SourceUnreadable(source_path.to_path_buf(), err))?;
    Ok(bytes)
}

/// List all files in the detected boot source that start with `prefix`.
pub fn list_dir(source_path: &Path, dir_path: &str) -> Result<Vec<(String, bool)>, ProfileError> {
    if is_tar_gz(source_path) {
        let source = load_tar_gz_source(source_path)?;
        source.list_dir(dir_path)
    } else if let Ok(source) = udf::UdfIso::open(source_path) {
        source.list_dir(dir_path)
    } else {
        let source = load_iso9660_source(source_path)?;
        source.list_dir(dir_path)
    }
}

pub fn list_files(source_path: &Path, prefix: &str) -> Result<Vec<String>, ProfileError> {
    if is_tar_gz(source_path) {
        let source = load_tar_gz_source(source_path)?;
        source.list_files(prefix)
    } else {
        if let Ok(source) = udf::UdfIso::open(source_path) {
            source.list_files(prefix)
        } else {
            let source = load_iso9660_source(source_path)?;
            source.list_files(prefix)
        }
    }
}

/// Walk the entire source image once and return a map of lowercase-normalized
/// path → [`IsoEntryMeta`] for every file and directory.
///
/// Callers that need to serve many files from the same image should build this
/// map at startup and use it for O(1) lookups instead of re-opening the image
/// on every request.
pub fn build_metadata_map(
    source_path: &Path,
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

    if let Ok(source) = udf::UdfIso::open(source_path) {
        for (path, is_dir, size, iso_offset) in source.walk_all_entries()? {
            let normalized = normalize_path(&path);
            let display_name = normalized.rsplit('/').next().unwrap_or("").to_string();
            map.insert(
                normalized.to_ascii_lowercase(),
                IsoEntryMeta {
                    is_dir,
                    size,
                    iso_offset,
                    display_name,
                },
            );
        }
    } else if !is_tar_gz(source_path) {
        let source = load_iso9660_source(source_path)?;
        let mut raw = Vec::new();
        source.walk_dir_all("/", &mut raw)?;
        for (path, is_dir, size, iso_offset) in raw {
            let normalized = normalize_path(&path);
            let display_name = normalized.rsplit('/').next().unwrap_or("").to_string();
            map.insert(
                normalized.to_ascii_lowercase(),
                IsoEntryMeta {
                    is_dir,
                    size,
                    iso_offset,
                    display_name,
                },
            );
        }
    }

    Ok(map)
}

/// Load all files from the detected boot source into memory.
pub fn load_all_files(source_path: &Path) -> Result<HashMap<String, Vec<u8>>, ProfileError> {
    if is_tar_gz(source_path) {
        let source = load_tar_gz_source(source_path)?;
        Ok(source.files)
    } else {
        let source: Box<dyn SourceFs> = match udf::UdfIso::open(source_path) {
            Ok(source) => Box::new(source),
            Err(_) => Box::new(load_iso9660_source(source_path)?),
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
    /// Return immediate children of `dir_path` as (name, is_dir) pairs.
    fn list_dir(&self, dir_path: &str) -> Result<Vec<(String, bool)>, ProfileError> {
        let prefix = normalize_path(dir_path);
        let dir_prefix = if prefix == "/" {
            "/".to_string()
        } else {
            format!("{}/", prefix)
        };
        let files = self.list_files(&dir_prefix)?;
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for file_path in &files {
            let relative = file_path
                .strip_prefix(&dir_prefix)
                .unwrap_or(file_path.as_str());
            let immediate = relative.split('/').next().unwrap_or("");
            if immediate.is_empty() {
                continue;
            }
            if seen.insert(immediate.to_string()) {
                let is_dir = relative.contains('/');
                result.push((immediate.to_string(), is_dir));
            }
        }
        result.sort();
        Ok(result)
    }
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

    fn list_dir(&self, dir_path: &str) -> Result<Vec<(String, bool)>, ProfileError> {
        let entry = self.iso.open(dir_path).map_err(|e| {
            ProfileError::SourceUnreadable(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )
        })?;
        let Some(DirectoryEntry::Directory(dir)) = entry else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        for entry_result in dir.contents() {
            let entry = entry_result.map_err(|e| {
                ProfileError::SourceUnreadable(
                    self.path.clone(),
                    io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
                )
            })?;
            let name = entry.identifier().to_string();
            if name == "." || name == ".." {
                continue;
            }
            let is_dir = matches!(entry, DirectoryEntry::Directory(_));
            result.push((name, is_dir));
        }
        result.sort();
        Ok(result)
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

    /// Walk every entry in the image and collect (path, is_dir, size, iso_offset).
    pub(crate) fn walk_dir_all(
        &self,
        path: &str,
        out: &mut Vec<(String, bool, u64, Option<u64>)>,
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

                match entry {
                    DirectoryEntry::File(f) => {
                        let header = f.header();
                        let offset = u64::from(header.extent_loc) * u64::from(cdfs::BLOCK_SIZE);
                        let size = u64::from(header.extent_length);
                        out.push((full_path, false, size, Some(offset)));
                    }
                    DirectoryEntry::Directory(_) => {
                        out.push((full_path.clone(), true, 0, None));
                        self.walk_dir_all(&full_path, out)?;
                    }
                    DirectoryEntry::Symlink(_) => {}
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
    let filename = iso_path.file_name().and_then(|n| n.to_str());
    if let Ok(udf) = udf::UdfIso::open(iso_path) {
        match detect_from_source(&udf, filename, udf.volume_label()) {
            Ok(profile) => return Ok(profile),
            Err(ProfileError::UnknownDistro) => {}
            Err(err) => return Err(err),
        }
    }

    let volume_label = read_iso_volume_label(iso_path);
    let source = load_iso9660_source(iso_path)?;
    detect_from_source(&source, filename, volume_label.as_deref())
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
    if let Ok(source) = udf::UdfIso::open(iso_path) {
        if let Some(content) = source.read_file(file_path)? {
            return Ok(content);
        }
    }

    load_iso9660_source(iso_path)?
        .read_file(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn load_file_slice_from_iso(source_path: &Path, file_path: &str) -> Result<IsoSlice, ProfileError> {
    load_iso9660_source(source_path)?
        .file_slice(file_path)?
        .ok_or_else(|| ProfileError::MissingFile {
            path: file_path.to_string(),
        })
}

fn slice_loaded_file(
    file_path: &str,
    bytes: &[u8],
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, ProfileError> {
    let start = usize::try_from(offset).map_err(|_| ProfileError::MissingFile {
        path: file_path.to_string(),
    })?;
    if start > bytes.len() {
        return Err(ProfileError::MissingFile {
            path: file_path.to_string(),
        });
    }
    let end = start.saturating_add(length).min(bytes.len());
    Ok(bytes[start..end].to_vec())
}

fn load_iso9660_source(source_path: &Path) -> Result<CdfsIso<std::fs::File>, ProfileError> {
    let file = std::fs::File::open(source_path)
        .map_err(|e| ProfileError::SourceUnreadable(source_path.to_path_buf(), e))?;
    let iso = ISO9660::new(file).map_err(|e| {
        ProfileError::SourceUnreadable(
            source_path.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    Ok(CdfsIso {
        iso,
        path: source_path.to_path_buf(),
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

            return Ok(BootProfile::Linux(LinuxProfile {
                platform: Platform::Debian,
                source_kind: BootSourceKind::DebianNetboot,
                architecture: match arch {
                    "amd64" => Architecture::Amd64,
                    "arm64" => Architecture::Arm64,
                    _ => return Err(ProfileError::UnknownDistro),
                },
                efi_path,
                label: format!("Debian Netboot ({arch})"),
                kernel_path,
                initrd_path,
                boot_params: String::new(),
            }));
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

    #[test]
    fn debian_netboot_detected_from_installer_tree() {
        let source = MockSource::new()
            .with_dir("/debian-installer/arm64")
            .with_file("/debian-installer/arm64/linux", b"")
            .with_file("/debian-installer/arm64/initrd.gz", b"")
            .with_file("/debian-installer/arm64/grubaa64.efi", b"");

        let profile = detect_from_source(&source, None, None).unwrap();
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };
        assert_eq!(profile.platform, Platform::Debian);
        assert_eq!(profile.source_kind, BootSourceKind::DebianNetboot);
        assert_eq!(profile.architecture, Architecture::Arm64);
        let (kp, ip, bp) = linux_source(profile);
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
    fn freebsd_profile_detected_from_mini_img_filename() {
        let profile = detect_profile(Path::new("FreeBSD-15.0-RELEASE-arm64-aarch64-mini.img"))
            .expect("freebsd mini img profile");
        let BootProfile::Linux(profile) = &profile else {
            panic!("expected BootProfile::Linux");
        };

        assert_eq!(profile.platform, Platform::FreeBSD);
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
        let BootProfile::Windows(profile) = &profile else {
            panic!("expected BootProfile::Windows");
        };
        assert_eq!(profile.source_kind, BootSourceKind::WindowsIso);
        assert_eq!(profile.architecture, Architecture::Amd64);
        assert_eq!(profile.label, "CCCOMA_X64FRE_EN-US_DV9");
        assert_eq!(profile.install_wim_path, "/sources/install.wim");
        assert_eq!(profile.boot_wim_path, "/sources/boot.wim");
        assert_eq!(profile.bcd_path, "/boot/bcd");
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
        let BootProfile::Windows(profile) = &profile else {
            panic!("expected BootProfile::Windows");
        };
        assert_eq!(profile.install_wim_path, "/sources/install.esd");
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
        let BootProfile::Windows(profile) = &profile else {
            panic!("expected BootProfile::Windows");
        };
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
        let BootProfile::Windows(profile) = &profile else {
            panic!("expected BootProfile::Windows");
        };
        assert_eq!(profile.architecture, Architecture::Amd64);
    }

    #[test]
    fn windows_arm64_detected_from_uefi_layout() {
        let source = MockSource::new()
            .with_file("/bootmgr.efi", b"")
            .with_file("/boot/boot.sdi", b"")
            .with_file("/sources/install.wim", b"")
            .with_file("/sources/boot.wim", b"")
            .with_file("/efi/microsoft/boot/bcd", b"")
            .with_file("/efi/boot/bootaa64.efi", b"");

        let profile = detect_from_source(&source, None, Some("CCCOMA_A64FRE_EN-US_DV9")).unwrap();
        let BootProfile::Windows(profile) = &profile else {
            panic!("expected BootProfile::Windows");
        };
        assert_eq!(profile.architecture, Architecture::Arm64);
        assert_eq!(profile.bootmgr_path, "/bootmgr.efi");
        assert_eq!(profile.bcd_path, "/efi/microsoft/boot/bcd");
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
