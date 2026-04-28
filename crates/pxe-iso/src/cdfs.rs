use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use cdfs::{DirectoryEntry, ExtraAttributes, ISO9660};

use crate::{normalize_path, ExtractionProgress, IsoError, IsoSlice, SourceFs};

pub struct CdfsIso<R: cdfs::ISO9660Reader> {
    iso: ISO9660<R>,
    path: PathBuf,
}

impl CdfsIso<File> {
    pub fn open(path: &Path) -> Result<Self, IsoError> {
        let file = File::open(path)?;
        let iso = ISO9660::new(file).map_err(|e| IsoError::InvalidData(e.to_string()))?;
        Ok(Self {
            iso,
            path: path.to_path_buf(),
        })
    }
}

impl<R: cdfs::ISO9660Reader> SourceFs for CdfsIso<R> {
    fn extract_to(&self, dest: &Path) -> Result<(), IsoError> {
        let mut progress = ExtractionProgress::new();
        self.extract_dir(self.iso.root(), "/", dest, &mut progress)?;
        progress.finish();
        Ok(())
    }

    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, IsoError> {
        match self
            .iso
            .open(path)
            .map_err(|e| IsoError::InvalidData(e.to_string()))?
        {
            Some(DirectoryEntry::File(f)) => {
                let mut buf = Vec::new();
                f.read().read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
            _ => Ok(None),
        }
    }

    fn path_exists(&self, path: &str) -> Result<bool, IsoError> {
        self.iso
            .open(path)
            .map(|entry| entry.is_some())
            .map_err(|e| IsoError::InvalidData(e.to_string()))
    }

    fn list_files(&self, prefix: &str) -> Result<Vec<String>, IsoError> {
        let mut out = Vec::new();
        let prefix = normalize_path(prefix);
        self.walk_dir("/", &prefix, &mut out)?;
        out.sort();
        Ok(out)
    }

    fn list_dir(&self, dir_path: &str) -> Result<Vec<(String, bool)>, IsoError> {
        let entry = self
            .iso
            .open(dir_path)
            .map_err(|e| IsoError::InvalidData(e.to_string()))?;
        let Some(DirectoryEntry::Directory(dir)) = entry else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        for entry_result in dir.contents() {
            let entry = entry_result.map_err(|e| IsoError::InvalidData(e.to_string()))?;
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

    fn file_slice(&self, path: &str) -> Result<Option<IsoSlice>, IsoError> {
        match self
            .iso
            .open(path)
            .map_err(|e| IsoError::InvalidData(e.to_string()))?
        {
            Some(DirectoryEntry::File(f)) => {
                let header = f.header();
                Ok(Some(IsoSlice {
                    offset: u64::from(header.extent_loc) * 2048,
                    length: u64::from(header.extent_length),
                }))
            }
            _ => Ok(None),
        }
    }

    fn volume_label(&self) -> Option<String> {
        let mut file = File::open(&self.path).ok()?;
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
}

impl<R: cdfs::ISO9660Reader> CdfsIso<R> {
    fn extract_dir(
        &self,
        dir: &cdfs::ISODirectory<R>,
        dir_path: &str,
        dest: &Path,
        progress: &mut ExtractionProgress,
    ) -> Result<(), IsoError> {
        fs::create_dir_all(dest)?;
        progress.directory_created();

        for entry_result in dir.contents() {
            let entry = entry_result.map_err(|e| IsoError::InvalidData(e.to_string()))?;
            let name = entry.identifier();
            if name == "." || name == ".." {
                continue;
            }

            let child_path = if dir_path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", dir_path.trim_end_matches('/'), name)
            };
            let dest_path = dest.join(name);

            match entry {
                DirectoryEntry::Directory(child_dir) => {
                    self.extract_dir(&child_dir, &child_path, &dest_path, progress)?;
                }
                DirectoryEntry::File(file) => {
                    #[cfg(unix)]
                    let file_mode = file.mode().map(|m| m.bits() & 0o7777);
                    let mut reader = file.read();
                    let mut writer = File::create(&dest_path)?;
                    let written = io::copy(&mut reader, &mut writer)? as usize;
                    progress.file_written(&child_path, written);
                    #[cfg(unix)]
                    if let Some(mode_bits) = file_mode {
                        fs::set_permissions(&dest_path, fs::Permissions::from_mode(mode_bits))?;
                    }
                }
                DirectoryEntry::Symlink(link) => {
                    self.extract_symlink(&link, &dest_path)?;
                }
            }
        }

        #[cfg(unix)]
        if let Some(mode) = dir.mode() {
            let mode_bits = mode.bits() & 0o7777;
            fs::set_permissions(dest, fs::Permissions::from_mode(mode_bits))?;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn extract_symlink(&self, link: &cdfs::Symlink, dest: &Path) -> Result<(), IsoError> {
        let target = link.target().ok_or_else(|| {
            IsoError::InvalidData(format!("ISO symlink missing target: {}", link.identifier))
        })?;
        std::os::unix::fs::symlink(target, dest)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn extract_symlink(&self, link: &cdfs::Symlink, _dest: &Path) -> Result<(), IsoError> {
        Err(IsoError::InvalidData(format!(
            "ISO symlink extraction is unsupported on this platform: {}",
            link.identifier
        )))
    }

    fn walk_dir(&self, path: &str, prefix: &str, out: &mut Vec<String>) -> Result<(), IsoError> {
        let entry = self
            .iso
            .open(path)
            .map_err(|e| IsoError::InvalidData(e.to_string()))?;

        if let Some(DirectoryEntry::Directory(dir)) = entry {
            for entry_result in dir.contents() {
                let entry = entry_result.map_err(|e| IsoError::InvalidData(e.to_string()))?;

                let name = entry.identifier();
                if name == "." || name == ".." {
                    continue;
                }

                let full_path = if path == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", path.trim_end_matches('/'), name)
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
