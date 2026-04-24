use crate::format::UFS_ROOTINO;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum EntryKind {
    File,
    Dir,
    Symlink(OsString),
    CharDev(u64),
    BlockDev(u64),
    Fifo,
    Socket,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub rel_path: PathBuf,
    pub ino: u32,
    pub parent_ino: u32,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: i64,
    pub mode: u16,
    pub children: Vec<u32>,
}

pub struct SourceTree {
    pub entries: Vec<FileEntry>,
    pub total_data_size: u64,
}

impl SourceTree {
    pub fn scan(root: &Path) -> Result<Self, String> {
        let mut entries = Vec::new();
        let mut queue = VecDeque::new();
        let mut total_data_size = 0;

        let root_meta = fs::metadata(root).map_err(|e| e.to_string())?;
        let root_entry = FileEntry {
            path: root.to_path_buf(),
            rel_path: PathBuf::from(""),
            ino: UFS_ROOTINO,
            parent_ino: UFS_ROOTINO,
            kind: EntryKind::Dir,
            size: 0,
            mtime: root_meta.mtime(),
            mode: root_meta.mode() as u16,
            children: Vec::new(),
        };
        entries.push(root_entry);
        queue.push_back(0);

        let mut next_ino = UFS_ROOTINO + 1;

        while let Some(parent_idx) = queue.pop_front() {
            let parent_path = entries[parent_idx].path.clone();
            let parent_ino = entries[parent_idx].ino;

            let mut children_entries = Vec::new();
            for entry in fs::read_dir(&parent_path).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                let file_type = entry.file_type().map_err(|e| e.to_string())?;
                let meta = entry.metadata().map_err(|e| e.to_string())?;
                let rel_path = path.strip_prefix(root).unwrap().to_path_buf();

                let kind = if file_type.is_dir() {
                    EntryKind::Dir
                } else if file_type.is_file() {
                    total_data_size += meta.len();
                    EntryKind::File
                } else if file_type.is_symlink() {
                    let target = fs::read_link(&path).map_err(|e| e.to_string())?;
                    EntryKind::Symlink(target.into_os_string())
                } else if file_type.is_char_device() {
                    EntryKind::CharDev(meta.rdev())
                } else if file_type.is_block_device() {
                    EntryKind::BlockDev(meta.rdev())
                } else if file_type.is_fifo() {
                    EntryKind::Fifo
                } else if file_type.is_socket() {
                    EntryKind::Socket
                } else {
                    return Err(format!("Unsupported file type at {:?}", path));
                };

                let child_idx = entries.len();
                let child_ino = next_ino;
                next_ino += 1;

                let child_entry = FileEntry {
                    path: path.clone(),
                    rel_path,
                    ino: child_ino,
                    parent_ino,
                    kind: kind.clone(),
                    size: meta.len(),
                    mtime: meta.mtime(),
                    mode: meta.mode() as u16,
                    children: Vec::new(),
                };
                entries.push(child_entry);
                children_entries.push(child_ino);

                if let EntryKind::Dir = kind {
                    queue.push_back(child_idx);
                }
            }
            entries[parent_idx].children = children_entries;
        }

        Ok(SourceTree {
            entries,
            total_data_size,
        })
    }
}
