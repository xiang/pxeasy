use pxe_iso::{CdfsIso, SourceFs, UdfIso};
use std::path::Path;
use tempfile::TempDir;

pub fn extract_iso(source_path: &Path) -> Result<TempDir, String> {
    let tempdir = tempfile::tempdir()
        .map_err(|e| format!("error: failed to create temporary directory: {e}"))?;

    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => Box::new(source),
        Err(_) => match CdfsIso::open(source_path) {
            Ok(source) => Box::new(source),
            Err(e) => {
                return Err(format!(
                    "error: failed to open ISO {}: {}",
                    source_path.display(),
                    e
                ))
            }
        },
    };

    source
        .extract_to(tempdir.path())
        .map_err(|e| format!("error: failed to extract ISO: {}", e))?;

    Ok(tempdir)
}
