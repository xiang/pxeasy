use log::{debug, info, warn};
use pxe_iso::{CdfsIso, SourceFs, UdfIso};
use std::{fs, path::Path};
use tempfile::TempDir;

pub fn extract_iso(source_path: &Path) -> Result<TempDir, String> {
    cleanup_stale_extract_dirs();

    let tempdir = tempfile::Builder::new()
        .prefix("pxeasy-iso-extract-")
        .tempdir()
        .map_err(|e| format!("error: failed to create temporary directory: {e}"))?;
    let extract_path = tempdir.path().to_path_buf();

    let source: Box<dyn SourceFs> = match UdfIso::open(source_path) {
        Ok(source) => {
            debug!("extracting ISO via UDF reader: {}", source_path.display());
            Box::new(source)
        }
        Err(udf_err) => match CdfsIso::open(source_path) {
            Ok(source) => {
                debug!("extracting ISO via CDFS reader: {}", source_path.display());
                Box::new(source)
            }
            Err(cdfs_err) => {
                return Err(format!(
                    "error: failed to open ISO {}. UDF error: {}, CDFS error: {}",
                    source_path.display(),
                    udf_err,
                    cdfs_err
                ))
            }
        },
    };

    info!(
        "extracting ISO {} to {}",
        source_path.display(),
        extract_path.display()
    );
    if let Err(err) = source.extract_to(tempdir.path()) {
        match tempdir.close() {
            Ok(()) => {}
            Err(close_err) => {
                warn!(
                    "failed to remove partial ISO extraction {}: {}",
                    extract_path.display(),
                    close_err
                );
            }
        }
        return Err(format!(
            "error: failed to extract ISO {} to {}: {}",
            source_path.display(),
            extract_path.display(),
            err
        ));
    }

    Ok(tempdir)
}

fn cleanup_stale_extract_dirs() {
    let temp_root = std::env::temp_dir();
    let entries = match fs::read_dir(&temp_root) {
        Ok(entries) => entries,
        Err(err) => {
            warn!(
                "failed to scan temp directory {} for stale ISO extracts: {}",
                temp_root.display(),
                err
            );
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("pxeasy-iso-extract-") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        if let Err(err) = fs::remove_dir_all(&path) {
            warn!(
                "failed to remove stale ISO extraction directory {}: {}",
                path.display(),
                err
            );
        } else {
            info!("removed stale ISO extraction directory {}", path.display());
        }
    }
}
