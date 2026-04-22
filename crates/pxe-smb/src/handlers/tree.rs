use crate::constants::*;
use crate::proto::{error_response, Smb2Header};
use crate::session::*;
use crate::SmbConfig;

pub fn handle_tree_connect(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> Vec<u8> {
    if body.len() < 8 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }
    let path_offset = u16::from_le_bytes(body[4..6].try_into().unwrap_or_default()) as usize;
    let path_len = u16::from_le_bytes(body[6..8].try_into().unwrap_or_default()) as usize;

    let path = if path_offset >= 64 && path_offset + path_len <= 64 + body.len() {
        let utf16: Vec<u16> = body[path_offset - 64..path_offset - 64 + path_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else {
        String::new()
    };

    log::debug!("TREE_CONNECT path={:?}", path);

    let tree_id = session.next_tree_id;
    session.next_tree_id += 1;

    let share_name = path.rsplit('\\').next().unwrap_or("");
    let is_ipc = share_name.eq_ignore_ascii_case("IPC$");
    if !is_ipc && !share_name.eq_ignore_ascii_case(&config.share_name) {
        return error_response(hdr, STATUS_BAD_NETWORK_NAME);
    }

    let kind = if is_ipc {
        TreeKind::Ipc
    } else {
        TreeKind::Data
    };
    session.trees.insert(tree_id, kind);

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_TREE_CONNECT);
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());

    let mut resp = vec![0u8; 16];
    resp[0..2].copy_from_slice(&16u16.to_le_bytes()); // StructureSize = 16
    resp[2] = if is_ipc { 0x02 } else { 0x01 }; // ShareType: DISK or PIPE
    resp[4..8].copy_from_slice(&0u32.to_le_bytes()); // ShareFlags
    resp[8..12].copy_from_slice(&0u32.to_le_bytes()); // ShareCapabilities
    resp[12..16].copy_from_slice(&0x001F_01FFu32.to_le_bytes()); // MaximalAccess (full)
    h.append(&mut resp);
    h
}

pub fn handle_tree_disconnect(hdr: &Smb2Header, session: &mut Session) -> Vec<u8> {
    session.trees.remove(&hdr.tree_id);
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_TREE_DISCONNECT);
    let mut body = vec![0u8; 4];
    body[0..2].copy_from_slice(&4u16.to_le_bytes()); // StructureSize = 4
    h.append(&mut body);
    h
}

pub fn session_tree_kind(session: &Session, tree_id: u32) -> TreeKind {
    session
        .trees
        .get(&tree_id)
        .cloned()
        .unwrap_or(TreeKind::Data)
}
