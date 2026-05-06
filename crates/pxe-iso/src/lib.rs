use std::{
    io,
    path::Path,
    time::{Duration, Instant},
};

use log::info;
use thiserror::Error;

pub mod cdfs;
pub mod udf;

pub use cdfs::CdfsIso;
pub use udf::UdfIso;

#[derive(Debug, Error)]
pub enum IsoError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

pub struct IsoSlice {
    pub offset: u64,
    pub length: u64,
}

pub(crate) struct ExtractionProgress {
    files_written: u64,
    dirs_created: u64,
    bytes_written: u64,
    started_at: Instant,
    last_logged_at: Instant,
}

impl ExtractionProgress {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            files_written: 0,
            dirs_created: 0,
            bytes_written: 0,
            started_at: now,
            last_logged_at: now,
        }
    }

    pub(crate) fn directory_created(&mut self) {
        self.dirs_created += 1;
    }

    pub(crate) fn file_written(&mut self, path: &str, bytes: usize) {
        self.files_written += 1;
        self.bytes_written += bytes as u64;

        let elapsed = self.last_logged_at.elapsed();
        let should_log = self.files_written == 1
            || self.files_written.is_multiple_of(200)
            || self.bytes_written / (128 * 1024 * 1024)
                != (self.bytes_written.saturating_sub(bytes as u64)) / (128 * 1024 * 1024)
            || elapsed >= Duration::from_secs(5);

        if should_log {
            self.last_logged_at = Instant::now();
            info!(
                "ISO extraction progress: {} files, {} directories, {} written in {:.1}s (latest: {})",
                self.files_written,
                self.dirs_created,
                format_bytes(self.bytes_written),
                self.started_at.elapsed().as_secs_f32(),
                path
            );
        }
    }

    pub(crate) fn finish(&self) {
        info!(
            "ISO extraction finished: {} files, {} directories, {} written in {:.1}s",
            self.files_written,
            self.dirs_created,
            format_bytes(self.bytes_written),
            self.started_at.elapsed().as_secs_f32()
        );
    }
}

pub trait SourceFs {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, IsoError>;
    fn read_file_range(
        &self,
        path: &str,
        offset: u64,
        length: usize,
    ) -> Result<Option<Vec<u8>>, IsoError>;
    fn path_exists(&self, path: &str) -> Result<bool, IsoError>;
    fn list_files(&self, prefix: &str) -> Result<Vec<String>, IsoError>;
    fn list_dir(&self, dir_path: &str) -> Result<Vec<(String, bool)>, IsoError>;
    fn file_slice(&self, path: &str) -> Result<Option<IsoSlice>, IsoError>;
    fn file_size(&self, path: &str) -> Result<Option<u64>, IsoError> {
        Ok(self.file_slice(path)?.map(|slice| slice.length))
    }
    fn volume_label(&self) -> Option<String>;

    fn extract_to(&self, dest: &Path) -> Result<(), IsoError> {
        let mut progress = ExtractionProgress::new();
        extract_recursive(self, "/", dest, &mut progress)?;
        progress.finish();
        Ok(())
    }
}

fn extract_recursive<S: SourceFs + ?Sized>(
    source: &S,
    dir_path: &str,
    dest: &Path,
    progress: &mut ExtractionProgress,
) -> Result<(), IsoError> {
    std::fs::create_dir_all(dest)?;
    progress.directory_created();
    for (name, is_dir) in source.list_dir(dir_path)? {
        let src_path = if dir_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", dir_path.trim_end_matches('/'), name)
        };
        let dest_path = dest.join(&name);

        if is_dir {
            extract_recursive(source, &src_path, &dest_path, progress)?;
        } else if let Some(content) = source.read_file(&src_path)? {
            let bytes = content.len();
            std::fs::write(dest_path, content)?;
            progress.file_written(&src_path, bytes);
        }
    }
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        format!("{:.1} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.1} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.1} KiB", bytes_f / KIB)
    } else {
        format!("{bytes} B")
    }
}

pub fn normalize_path(path: &str) -> String {
    let p = path.replace('\\', "/");
    let mut normalized = p.trim_start_matches('/').trim_end_matches('/').to_string();
    normalized.insert(0, '/');
    if normalized == "//" {
        "/".to_string()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("foo"), "/foo");
        assert_eq!(normalize_path("/foo/"), "/foo");
        assert_eq!(normalize_path("\\foo\\bar"), "/foo/bar");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
    }
}
