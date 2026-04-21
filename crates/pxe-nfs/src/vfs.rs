use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use cdfs::{DirectoryEntry, ExtraAttributes, BLOCK_SIZE, ISO9660};

pub const ROOT_ID: u64 = 1;

pub struct FileAttr {
    pub id: u64,
    pub kind: NodeKind,
    pub size: u64,
    pub nlink: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum NodeKind {
    Dir,
    File,
    Symlink,
}

enum Node {
    Dir {
        children: HashMap<String, u64>,
    },
    File {
        /// Byte offset of file data within the ISO image.
        iso_offset: u64,
        size: u64,
    },
    Symlink {
        target: String,
    },
}

pub struct Vfs {
    nodes: HashMap<u64, Node>,
    iso_path: PathBuf,
    next_id: u64,
}

impl Vfs {
    /// Build a VFS tree by walking an ISO image with cdfs.
    pub fn from_iso(iso_path: &Path) -> io::Result<Self> {
        let file = File::open(iso_path)?;
        let iso = ISO9660::new(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut vfs = Vfs {
            nodes: HashMap::new(),
            iso_path: iso_path.to_path_buf(),
            next_id: ROOT_ID + 1,
        };

        let mut root_children = HashMap::new();
        vfs.walk(&iso, "/", &mut root_children)?;
        vfs.nodes.insert(
            ROOT_ID,
            Node::Dir {
                children: root_children,
            },
        );
        Ok(vfs)
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn walk(
        &mut self,
        iso: &ISO9660<File>,
        path: &str,
        children: &mut HashMap<String, u64>,
    ) -> io::Result<()> {
        let entry = iso
            .open(path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let dir = match entry {
            Some(DirectoryEntry::Directory(d)) => d,
            _ => return Ok(()),
        };

        for result in dir.contents() {
            let entry =
                result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let name = entry.identifier().to_string();
            if name == "." || name == ".." {
                continue;
            }

            let full_path = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };

            let id = self.alloc_id();
            children.insert(name, id);

            match entry {
                DirectoryEntry::File(f) => {
                    let h = f.header();
                    let iso_offset = u64::from(h.extent_loc) * u64::from(BLOCK_SIZE);
                    let size = u64::from(h.extent_length);
                    self.nodes.insert(id, Node::File { iso_offset, size });
                }
                DirectoryEntry::Symlink(s) => {
                    let target = s.target().cloned().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("symlink missing target: {full_path}"),
                        )
                    })?;
                    self.nodes.insert(id, Node::Symlink { target });
                }
                DirectoryEntry::Directory(_) => {
                    let mut sub = HashMap::new();
                    self.walk(iso, &full_path, &mut sub)?;
                    self.nodes.insert(id, Node::Dir { children: sub });
                }
            }
        }
        Ok(())
    }

    pub fn root_id(&self) -> u64 {
        ROOT_ID
    }

    /// Add an alias directory with file aliases under it.
    ///
    /// This is used to synthesize netboot-style trees on top of ISO-backed
    /// content without copying file data.
    pub fn add_alias_tree(
        &mut self,
        alias_root: &str,
        file_aliases: &[(&str, &str)],
    ) -> io::Result<u64> {
        let alias_root_id = self.ensure_dir_path(alias_root)?;
        for (alias_path, source_path) in file_aliases {
            self.add_file_alias(alias_path, source_path)?;
        }
        Ok(alias_root_id)
    }

    pub fn getattr(&self, id: u64) -> Option<FileAttr> {
        self.nodes.get(&id).map(|node| match node {
            Node::Dir { children } => FileAttr {
                id,
                kind: NodeKind::Dir,
                size: 4096,
                nlink: 2 + children.len() as u32,
            },
            Node::Symlink { target } => FileAttr {
                id,
                kind: NodeKind::Symlink,
                size: target.len() as u64,
                nlink: 1,
            },
            Node::File { size, .. } => FileAttr {
                id,
                kind: NodeKind::File,
                size: *size,
                nlink: 1,
            },
        })
    }

    pub fn lookup(&self, dir_id: u64, name: &str) -> Option<u64> {
        if let Some(Node::Dir { children }) = self.nodes.get(&dir_id) {
            children.get(name).copied()
        } else {
            None
        }
    }

    fn ensure_dir_path(&mut self, path: &str) -> io::Result<u64> {
        let normalized = normalize_path(path);
        if normalized == "/" {
            return Ok(ROOT_ID);
        }

        let mut current_id = ROOT_ID;
        let mut current_path = String::new();

        for part in normalized.trim_start_matches('/').split('/') {
            current_path.push('/');
            current_path.push_str(part);

            let next_id = if let Some(existing) = self.lookup(current_id, part) {
                existing
            } else {
                let id = self.alloc_id();
                self.nodes.insert(
                    id,
                    Node::Dir {
                        children: HashMap::new(),
                    },
                );
                let parent = self.nodes.get_mut(&current_id).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "parent directory missing")
                })?;
                match parent {
                    Node::Dir { children } => {
                        children.insert(part.to_string(), id);
                    }
                    Node::File { .. } => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("path component is not a directory: {}", current_path),
                        ));
                    }
                    Node::Symlink { .. } => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("path component is not a directory: {}", current_path),
                        ));
                    }
                }
                id
            };

            current_id = next_id;
        }

        Ok(current_id)
    }

    fn add_file_alias(&mut self, alias_path: &str, source_path: &str) -> io::Result<()> {
        let (iso_offset, size) = match self.file_node(source_path)? {
            Some((iso_offset, size)) => (iso_offset, size),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("source file missing for alias: {source_path}"),
                ))
            }
        };

        let normalized = normalize_path(alias_path);
        let (parent_path, file_name) = normalized.rsplit_once('/').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid alias path: {alias_path}"),
            )
        })?;
        let parent_id = self.ensure_dir_path(parent_path)?;
        let file_id = self.alloc_id();
        self.nodes.insert(file_id, Node::File { iso_offset, size });
        let parent = self
            .nodes
            .get_mut(&parent_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "alias parent missing"))?;
        match parent {
            Node::Dir { children } => {
                let file_name = file_name.to_owned();
                children.insert(file_name, file_id);
                Ok(())
            }
            Node::File { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("alias parent is not a directory: {parent_path}"),
            )),
            Node::Symlink { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("alias parent is not a directory: {parent_path}"),
            )),
        }
    }

    fn file_node(&self, path: &str) -> io::Result<Option<(u64, u64)>> {
        let normalized = normalize_path(path);
        if normalized == "/" {
            return Ok(None);
        }

        let mut current_id = ROOT_ID;
        for part in normalized.trim_start_matches('/').split('/') {
            let next_id = match self.lookup(current_id, part) {
                Some(id) => id,
                None => return Ok(None),
            };
            current_id = next_id;
        }

        Ok(match self.nodes.get(&current_id) {
            Some(Node::File { iso_offset, size }) => Some((*iso_offset, *size)),
            _ => None,
        })
    }

    pub fn readlink(&self, id: u64) -> Option<&str> {
        match self.nodes.get(&id) {
            Some(Node::Symlink { target }) => Some(target.as_str()),
            _ => None,
        }
    }

    /// Returns sorted (name, child_id) pairs starting at `cookie` index.
    pub fn readdir(&self, dir_id: u64, cookie: usize) -> Option<Vec<(String, u64)>> {
        if let Some(Node::Dir { children }) = self.nodes.get(&dir_id) {
            let mut entries: Vec<_> = children
                .iter()
                .map(|(name, &id)| (name.clone(), id))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Some(entries.into_iter().skip(cookie).collect())
        } else {
            None
        }
    }

    /// Total file count — used for FSSTAT.
    pub fn node_count(&self) -> u64 {
        self.nodes.len() as u64
    }

    /// Read `count` bytes from file `id` at `offset`.
    /// Returns (data, eof).
    pub fn read_file(&self, id: u64, offset: u64, count: u32) -> io::Result<(Vec<u8>, bool)> {
        let (iso_offset, size) = match self.nodes.get(&id) {
            Some(Node::File { iso_offset, size }) => (*iso_offset, *size),
            Some(Node::Dir { .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "is a directory",
                ))
            }
            Some(Node::Symlink { .. }) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "is a symlink"))
            }
            None => return Err(io::Error::new(io::ErrorKind::NotFound, "unknown fh")),
        };

        if offset >= size {
            return Ok((vec![], true));
        }
        let remaining = size - offset;
        let to_read = (count as u64).min(remaining) as usize;
        let mut buf = vec![0u8; to_read];

        let mut f = File::open(&self.iso_path)?;
        f.seek(SeekFrom::Start(iso_offset + offset))?;
        f.read_exact(&mut buf)?;

        let eof = offset + to_read as u64 >= size;
        Ok((buf, eof))
    }
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_start_matches("./").trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_end_matches('/'))
    }
}
