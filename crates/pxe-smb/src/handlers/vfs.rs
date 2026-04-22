use crate::session::{DirEntry, IsoEntry};
use pxe_profiles::{
    list_dir as list_source_dir, load_file, load_file_range, load_file_slice, IsoEntryMeta,
};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::Path;

pub fn resolve_iso_entry(
    source_path: &Path,
    iso_cache: Option<&HashMap<String, IsoEntryMeta>>,
    iso_path: &str,
) -> Option<IsoEntry> {
    if iso_path.is_empty() || iso_path == "\\" {
        return Some(IsoEntry {
            path: String::new(),
            is_dir: true,
            size: 0,
            iso_offset: None,
            children: None,
            enum_pattern: None,
            enum_pos: 0,
        });
    }

    if source_path.is_dir() {
        let p = iso_path.trim_start_matches('\\');
        let mut full = source_path.to_path_buf();
        if !p.is_empty() {
            full.push(p.replace('\\', "/"));
        }

        let meta = fs::metadata(&full).ok()?;
        return Some(IsoEntry {
            path: iso_path.to_string(),
            is_dir: meta.is_dir(),
            size: meta.len(),
            iso_offset: None,
            children: None,
            enum_pattern: None,
            enum_pos: 0,
        });
    }

    // O(1) cache lookup: avoids opening and parsing the ISO image per request.
    if let Some(cache) = iso_cache {
        let key = cache_key(iso_path);
        return cache.get(&key).map(|meta| IsoEntry {
            path: iso_path.to_string(),
            is_dir: meta.is_dir,
            size: meta.size,
            iso_offset: meta.iso_offset,
            children: None,
            enum_pattern: None,
            enum_pos: 0,
        });
    }

    // Fallback: re-parse the ISO (used when cache is unavailable, e.g. in tests).
    let normalized = normalize_iso_path(iso_path);
    if let Ok(entries) = list_source_dir(source_path, &normalized) {
        if !entries.is_empty() {
            return Some(IsoEntry {
                path: iso_path.to_string(),
                is_dir: true,
                size: 0,
                iso_offset: None,
                children: None,
                enum_pattern: None,
                enum_pos: 0,
            });
        }
    }

    if let Ok(slice) = load_file_slice(source_path, &normalized) {
        return Some(IsoEntry {
            path: iso_path.to_string(),
            is_dir: false,
            size: slice.length,
            iso_offset: Some(slice.offset),
            children: None,
            enum_pattern: None,
            enum_pos: 0,
        });
    }

    if let Ok(bytes) = load_file(source_path, &normalized) {
        return Some(IsoEntry {
            path: iso_path.to_string(),
            is_dir: false,
            size: bytes.len() as u64,
            iso_offset: None,
            children: None,
            enum_pattern: None,
            enum_pos: 0,
        });
    }

    None
}

fn cache_key(iso_path: &str) -> String {
    let p = iso_path.trim_start_matches('\\').replace('\\', "/");
    format!("/{}", p).to_ascii_lowercase()
}

pub fn list_iso_dir(
    source_path: &Path,
    dir_path: &str,
    _pattern: &str,
    iso_cache: Option<&HashMap<String, IsoEntryMeta>>,
) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    entries.push(DirEntry {
        name: ".".to_string(),
        name_utf16: crate::handlers::utils::encode_utf16_bytes("."),
        is_dir: true,
        size: 0,
    });
    entries.push(DirEntry {
        name: "..".to_string(),
        name_utf16: crate::handlers::utils::encode_utf16_bytes(".."),
        is_dir: true,
        size: 0,
    });

    if source_path.is_dir() {
        let p = dir_path.trim_start_matches('\\');
        let mut full = source_path.to_path_buf();
        if !p.is_empty() {
            full.push(p.replace('\\', "/"));
        }
        if let Ok(dir) = fs::read_dir(full) {
            for entry in dir.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let name_utf16 = crate::handlers::utils::encode_utf16_bytes(&name);
                    entries.push(DirEntry {
                        name,
                        name_utf16,
                        is_dir: meta.is_dir(),
                        size: meta.len(),
                    });
                }
            }
        }
        return entries;
    }

    if let Some(cache) = iso_cache {
        // Derive children from the in-memory cache — no UDF I/O.
        let dir_lower = if dir_path.is_empty() {
            "/".to_string()
        } else {
            let p = dir_path.trim_start_matches(['/', '\\']).replace('\\', "/");
            format!("/{}", p).to_ascii_lowercase()
        };
        let prefix: &str = if dir_lower == "/" {
            "/"
        } else {
            dir_lower.as_str()
        };

        for (key, meta) in cache {
            if key == "/" {
                continue;
            }
            let rest = match key.strip_prefix(prefix) {
                Some(r) if prefix == "/" => r,
                Some(r) if r.starts_with('/') => &r[1..],
                _ => continue,
            };
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            let name = if meta.display_name.is_empty() {
                rest.to_string()
            } else {
                meta.display_name.clone()
            };
            let name_utf16 = crate::handlers::utils::encode_utf16_bytes(&name);
            entries.push(DirEntry {
                name,
                name_utf16,
                is_dir: meta.is_dir,
                size: meta.size,
            });
        }
        entries[2..].sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        });
        return entries;
    }

    // Fallback: open and parse the ISO (no cache available).
    let normalized = normalize_iso_path(dir_path);
    if let Ok(dir_entries) = list_source_dir(source_path, &normalized) {
        for (name, is_dir) in dir_entries {
            let name_utf16 = crate::handlers::utils::encode_utf16_bytes(&name);
            entries.push(DirEntry {
                name,
                name_utf16,
                is_dir,
                size: 0,
            });
        }
    }
    entries
}

pub fn read_iso_range(
    source_path: &Path,
    iso_path: &str,
    cached_iso_offset: Option<u64>,
    iso_file: Option<&fs::File>,
    offset: u64,
    length: usize,
) -> io::Result<Vec<u8>> {
    if source_path.is_dir() {
        let p = iso_path.trim_start_matches('\\');
        let mut full = source_path.to_path_buf();
        if !p.is_empty() {
            full.push(p.replace('\\', "/"));
        }

        let mut f = fs::File::open(full)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length];
        f.read_exact(&mut buf)?;
        return Ok(buf);
    }

    let normalized = normalize_iso_path(iso_path);
    if let Ok(bytes) = load_file_range(source_path, &normalized, offset, length) {
        return Ok(bytes);
    }

    let iso_file_offset = if let Some(o) = cached_iso_offset {
        o
    } else if let Ok(slice) = load_file_slice(source_path, &normalized) {
        slice.offset
    } else {
        let bytes = load_file(source_path, &normalized)
            .map_err(|err| io::Error::new(io::ErrorKind::NotFound, err.to_string()))?;
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read length overflow"))?;
        if end > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond end of file",
            ));
        }
        return Ok(bytes[start..end].to_vec());
    };

    let abs_offset = iso_file_offset + offset;
    let mut buf = vec![0u8; length];

    if let Some(f) = iso_file {
        // pread(): position-independent, thread-safe, no open/close per call.
        f.read_at(&mut buf, abs_offset)?;
    } else {
        let mut f = fs::File::open(source_path)?;
        f.seek(SeekFrom::Start(abs_offset))?;
        f.read_exact(&mut buf)?;
    }

    Ok(buf)
}

pub fn stable_object_id(path: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut s = DefaultHasher::new();
    path.hash(&mut s);
    s.finish()
}

fn normalize_iso_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('\\');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", trimmed.replace('\\', "/"))
    }
}
