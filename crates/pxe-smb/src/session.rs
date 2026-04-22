#![allow(dead_code)]

use std::collections::HashMap;

#[derive(Debug)]
pub struct Session {
    pub session_id: u64,
    pub auth_state: AuthState,
    pub trees: HashMap<u32, TreeKind>,
    pub next_tree_id: u32,
    // SMB handle id -> IsoEntry
    pub open_files: HashMap<u64, IsoEntry>,
    pub next_file_id: u64,
    pub root_create_count: u32,
    pub session_key: Option<[u8; 16]>,
    pub challenge: [u8; 8],
    pub is_signing_required: bool,
    pub client_guid: [u8; 16],
    pub client_capabilities: u32,
    pub client_security_mode: u16,
    pub negotiated_dialect: u16,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            session_id: 0,
            auth_state: AuthState::Initial,
            trees: HashMap::new(),
            next_tree_id: 1,
            open_files: HashMap::new(),
            next_file_id: 1,
            root_create_count: 0,
            session_key: None,
            challenge: [0u8; 8],
            is_signing_required: false,
            client_guid: [0u8; 16],
            client_capabilities: 0,
            client_security_mode: 0,
            negotiated_dialect: 0,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthState {
    #[default]
    Initial,
    ChallengeSent,
    Authenticated,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeKind {
    #[default]
    Data,
    Ipc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoEntry {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Byte offset of this file within the ISO image; cached at open time to
    /// avoid re-parsing the ISO directory tree on every READ.
    pub iso_offset: Option<u64>,
    // Cached directory enumeration for one search pattern.
    pub children: Option<Vec<DirEntry>>,
    pub enum_pattern: Option<String>,
    // Enumeration position
    pub enum_pos: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub name_utf16: Vec<u8>,
    pub is_dir: bool,
    pub size: u64,
}
