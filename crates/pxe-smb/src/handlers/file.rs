use crate::constants::*;
use crate::handlers::tree::session_tree_kind;
use crate::handlers::utils::{system_time_filetime, wildcard_match};
use crate::handlers::vfs::{list_iso_dir, read_iso_range, resolve_iso_entry, stable_object_id};
use crate::proto::{error_response, Smb2Header};
use crate::session::*;
use crate::SmbConfig;
use std::io;

fn display_path(path: &str) -> &str {
    if path.is_empty() {
        "<root>"
    } else {
        path
    }
}

pub fn handle_create(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> Vec<u8> {
    if body.len() < 56 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }
    if session_tree_kind(session, hdr.tree_id) == TreeKind::Ipc {
        return error_response(hdr, STATUS_SUCCESS); // IPC creates succeed
    }

    let name_offset = u16::from_le_bytes(body[44..46].try_into().unwrap_or_default()) as usize;
    let name_len = u16::from_le_bytes(body[46..48].try_into().unwrap_or_default()) as usize;
    let create_ctx_offset =
        u32::from_le_bytes(body[48..52].try_into().unwrap_or_default()) as usize;
    let create_ctx_length =
        u32::from_le_bytes(body[52..56].try_into().unwrap_or_default()) as usize;

    let mut name = if name_offset >= 64 && name_offset + name_len <= 64 + body.len() {
        let utf16: Vec<u16> = body[name_offset - 64..name_offset - 64 + name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&utf16)
    } else {
        String::new()
    };
    if name.starts_with('\\') {
        name = name[1..].to_string();
    }

    log::debug!("CREATE name={}", display_path(&name));

    let entry = match resolve_iso_entry(&config.source_path, config.iso_cache.as_deref(), &name) {
        Some(e) => e,
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };
    if entry.path.is_empty() {
        session.root_create_count += 1;
    }

    let file_id = allocate_wire_file_id(session, &entry.path);
    session.next_file_id += 1;
    session.open_files.insert(file_id, entry.clone());

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_CREATE);
    let mut resp = vec![0u8; 88];
    resp[0..2].copy_from_slice(&89u16.to_le_bytes()); // StructureSize = 89
    resp[2] = 0; // OplockLevel
    resp[3] = 0; // ResponseFlags
    resp[4..8].copy_from_slice(&1u32.to_le_bytes()); // CreateAction (1 = opened)
    let now = system_time_filetime();
    resp[8..16].copy_from_slice(&now.to_le_bytes()); // CreationTime
    resp[16..24].copy_from_slice(&now.to_le_bytes()); // LastAccessTime
    resp[24..32].copy_from_slice(&now.to_le_bytes()); // LastWriteTime
    resp[32..40].copy_from_slice(&now.to_le_bytes()); // ChangeTime
    let file_size = if entry.is_dir { 0 } else { entry.size };
    let attrs = if entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    resp[40..48].copy_from_slice(&file_size.to_le_bytes()); // AllocationSize
    resp[48..56].copy_from_slice(&file_size.to_le_bytes()); // EndOfFile
    resp[56..60].copy_from_slice(&attrs.to_le_bytes());
    resp[64..72].copy_from_slice(&file_id.to_le_bytes()); // FileId.Persistent
    resp[72..80].copy_from_slice(&file_id.to_le_bytes()); // FileId.Volatile

    let tags = parse_create_context_tags(body, create_ctx_offset, create_ctx_length);
    let (oplock_level, ctx_data) = build_create_context_response(&tags, &entry.path);
    resp[2] = oplock_level;

    if !ctx_data.is_empty() {
        resp[80..84].copy_from_slice(&(160u32).to_le_bytes()); // CreateContextsOffset = 64 + 96 = 160
        resp[84..88].copy_from_slice(&(ctx_data.len() as u32).to_le_bytes());
    }

    h.append(&mut resp);
    // Pad to 160 bytes total (64 header + 88 body + 8 padding)
    h.extend_from_slice(&[0u8; 8]);
    if !ctx_data.is_empty() {
        h.extend_from_slice(&ctx_data);
    }
    h
}

pub fn handle_close(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    last_file_id: Option<u64>,
) -> Vec<u8> {
    if body.len() < 24 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }

    let file_id = resolve_file_id(body, 8, 16, last_file_id, hdr.tree_id, hdr.session_id);
    session.open_files.remove(&file_id);

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_CLOSE);
    let mut resp = vec![0u8; 60];
    resp[0..2].copy_from_slice(&60u16.to_le_bytes()); // StructureSize = 60
    let now = system_time_filetime();
    resp[8..16].copy_from_slice(&now.to_le_bytes());
    resp[16..24].copy_from_slice(&now.to_le_bytes());
    resp[24..32].copy_from_slice(&now.to_le_bytes());
    resp[32..40].copy_from_slice(&now.to_le_bytes());
    h.append(&mut resp);
    h
}

pub fn handle_lock(
    hdr: &Smb2Header,
    body: &[u8],
    session: &Session,
    last_file_id: Option<u64>,
) -> Vec<u8> {
    if body.len() < 24 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }

    let file_id = resolve_file_id(body, 8, 16, last_file_id, hdr.tree_id, hdr.session_id);
    if !session.open_files.contains_key(&file_id) {
        return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND);
    }

    log::debug!("LOCK file_id=0x{file_id:016x}");

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_LOCK);
    let mut resp = vec![0u8; 4];
    resp[0..2].copy_from_slice(&4u16.to_le_bytes()); // StructureSize = 4
    h.append(&mut resp);
    h
}

pub fn handle_read(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
    last_file_id: Option<u64>,
) -> io::Result<Option<Vec<u8>>> {
    if body.len() < 49 {
        return Ok(Some(error_response(hdr, STATUS_ACCESS_DENIED)));
    }

    if session_tree_kind(session, hdr.tree_id) == TreeKind::Ipc {
        return Ok(Some(error_response(hdr, STATUS_FS_DRIVER_REQUIRED)));
    }

    let read_length = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default()) as usize;
    let read_offset = u64::from_le_bytes(body[8..16].try_into().unwrap_or_default());
    let file_id = resolve_file_id(body, 16, 24, last_file_id, hdr.tree_id, hdr.session_id);

    let entry = match session.open_files.get(&file_id) {
        Some(e) => e,
        None => return Ok(Some(error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND))),
    };

    if entry.is_dir {
        return Ok(Some(error_response(hdr, STATUS_ACCESS_DENIED)));
    }

    if read_offset >= entry.size {
        return Ok(Some(error_response(hdr, STATUS_END_OF_FILE)));
    }

    let to_read = read_length.min((entry.size - read_offset) as usize);
    let data = match read_iso_range(
        &config.source_path,
        &entry.path,
        entry.iso_offset,
        config.iso_file.as_deref(),
        read_offset,
        to_read,
    ) {
        Ok(d) => d,
        Err(_) => return Ok(Some(error_response(hdr, STATUS_ACCESS_DENIED))),
    };

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_READ);
    let mut resp = vec![0u8; 16];
    resp[0..2].copy_from_slice(&17u16.to_le_bytes()); // StructureSize = 17
    resp[2] = 0x50; // DataOffset = 64 + 16 = 80
    resp[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    h.append(&mut resp);
    h.extend_from_slice(&data);
    Ok(Some(h))
}

pub fn handle_echo(hdr: &Smb2Header) -> Vec<u8> {
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_ECHO);
    let mut body = vec![0u8; 4];
    body[0..2].copy_from_slice(&4u16.to_le_bytes()); // StructureSize = 4
    h.append(&mut body);
    h
}

pub fn handle_query_info(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
    last_file_id: Option<u64>,
) -> Vec<u8> {
    if body.len() < 40 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    // MS-SMB2 2.2.37: QUERY_INFO Request
    let info_type = body[2];
    let file_info_class = body[3];
    let output_buffer_length = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default());
    let file_id = resolve_file_id(body, 24, 32, last_file_id, hdr.tree_id, hdr.session_id);

    let entry = match session.open_files.get(&file_id) {
        Some(e) => e,
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };

    log::debug!(
        "QUERY_INFO type={info_type} class={file_info_class} out_len={output_buffer_length} path={}",
        display_path(&entry.path)
    );

    let info_data = match info_type {
        1 => build_file_info(file_info_class, entry, &config.source_path),
        2 => build_fs_info(file_info_class, session_tree_kind(session, hdr.tree_id)),
        _ => None,
    };
    match info_data {
        None => error_response(hdr, STATUS_NOT_SUPPORTED),
        Some(data) => {
            let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_QUERY_INFO);
            let mut resp = vec![0u8; 8];
            resp[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
            resp[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes()); // OutputBufferLength
            resp[2..4].copy_from_slice(&72u16.to_le_bytes()); // OutputBufferOffset = 64 + 8 = 72
            h.append(&mut resp);
            h.extend_from_slice(&data);
            h
        }
    }
}

pub fn handle_query_directory(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
    last_file_id: Option<u64>,
) -> Vec<u8> {
    if body.len() < 32 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }
    if session_tree_kind(session, hdr.tree_id) == TreeKind::Ipc {
        return error_response(hdr, STATUS_NO_MORE_FILES);
    }
    let file_info_class = body[2];
    let flags = body[3];
    let file_index = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default());
    let file_id_handle = resolve_file_id(body, 8, 16, last_file_id, hdr.tree_id, hdr.session_id);
    let file_name_offset = u16::from_le_bytes(body[24..26].try_into().unwrap_or_default()) as usize;
    let file_name_length = u16::from_le_bytes(body[26..28].try_into().unwrap_or_default()) as usize;
    let output_buffer_length =
        u32::from_le_bytes(body[28..32].try_into().unwrap_or_default()) as usize;
    let restart = flags & 0x01 != 0;
    let single = flags & 0x02 != 0;
    let reopen = flags & 0x10 != 0;
    let entry = match session.open_files.get_mut(&file_id_handle) {
        Some(e) => e,
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };
    if !entry.is_dir {
        return error_response(hdr, STATUS_NOT_SUPPORTED);
    }

    let pattern = query_directory_pattern(body, file_name_offset, file_name_length);
    log::debug!(
        "QUERY_DIRECTORY class={} flags=0x{:02x} file_index={} out_len={} pattern={:?} path={}",
        file_info_class,
        flags,
        file_index,
        output_buffer_length,
        pattern,
        display_path(&entry.path)
    );

    if output_buffer_length <= 8 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }
    if !matches!(file_info_class, 1 | 2 | 3 | 12 | 37 | 38) {
        return error_response(hdr, STATUS_INVALID_INFO_CLASS);
    }
    if reopen || restart || entry.enum_pattern.as_deref() != Some(pattern.as_str()) {
        entry.enum_pos = 0;
        entry.enum_pattern = Some(pattern.clone());
        entry.children = Some(list_iso_dir(
            &config.source_path,
            &entry.path,
            &pattern,
            config.iso_cache.as_deref(),
        ));
    }

    let children = entry.children.as_ref().unwrap();
    if entry.enum_pos >= children.len() {
        return error_response(hdr, STATUS_NO_MORE_FILES);
    }

    let mut output = Vec::new();
    let start_pos = entry.enum_pos;
    for i in start_pos..children.len() {
        let child = &children[i];
        if !wildcard_match(&child.name, &pattern) {
            entry.enum_pos += 1;
            continue;
        }

        let attrs = if child.is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };
        let file_id = stable_object_id(&format!("{}/{}", entry.path, child.name));
        let entry_data = build_dir_entry(
            file_info_class,
            &child.name_utf16,
            attrs,
            file_id,
            child.size,
        );
        if output.len() + entry_data.len() > output_buffer_length {
            if output.is_empty() {
                return error_response(hdr, STATUS_BUFFER_OVERFLOW);
            }
            break;
        }

        let current_offset = output.len();
        output.extend_from_slice(&entry_data);
        if i + 1 < children.len() {
            let next_offset = output.len();
            let next_entry_len = (next_offset - current_offset) as u32;
            output[current_offset..current_offset + 4]
                .copy_from_slice(&next_entry_len.to_le_bytes());
        }
        entry.enum_pos += 1;
        if single {
            break;
        }
    }

    if output.is_empty() {
        return error_response(hdr, STATUS_NO_MORE_FILES);
    }

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_QUERY_DIRECTORY);
    let mut resp = vec![0u8; 8];
    resp[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
    resp[2..4].copy_from_slice(&72u16.to_le_bytes()); // OutputBufferOffset = 64 + 8 = 72
    resp[4..8].copy_from_slice(&(output.len() as u32).to_le_bytes()); // OutputBufferLength
    h.append(&mut resp);
    h.extend_from_slice(&output);
    h
}

pub fn handle_ioctl(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    if body.len() < 56 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }
    let ctl_code = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default());
    if ctl_code == FSCTL_DFS_GET_REFERRALS {
        log::debug!("IOCTL DFS_GET_REFERRALS — not a DFS server");
        return error_response(hdr, STATUS_FS_DRIVER_REQUIRED);
    }

    if ctl_code == FSCTL_VALIDATE_NEGOTIATE_INFO {
        let input_offset = u32::from_le_bytes(body[24..28].try_into().unwrap_or_default()) as usize;
        let input_count = u32::from_le_bytes(body[28..32].try_into().unwrap_or_default()) as usize;
        let max_output = u32::from_le_bytes(body[44..48].try_into().unwrap_or_default()) as usize;

        if max_output < 24 {
            log::debug!(
                "IOCTL VALIDATE_NEGOTIATE_INFO max_output {} too small",
                max_output
            );
            return error_response(hdr, STATUS_BUFFER_TOO_SMALL);
        }

        let input_blob = if input_offset >= 64 && input_offset + input_count <= 64 + body.len() {
            &body[input_offset - 64..input_offset - 64 + input_count]
        } else {
            &[]
        };

        if input_blob.len() < 24 {
            return error_response(hdr, STATUS_INVALID_PARAMETER);
        }

        // Validate the negotiate info
        let in_capabilities = u32::from_le_bytes(input_blob[0..4].try_into().unwrap_or_default());
        let in_guid = &input_blob[4..20];
        let in_security_mode =
            u16::from_le_bytes(input_blob[20..22].try_into().unwrap_or_default());
        let in_dialects_count =
            u16::from_le_bytes(input_blob[22..24].try_into().unwrap_or_default()) as usize;

        if in_capabilities != session.client_capabilities
            || in_guid != session.client_guid
            || in_security_mode != session.client_security_mode
        {
            log::warn!("VALIDATE_NEGOTIATE_INFO failed validation");
            return error_response(hdr, STATUS_ACCESS_DENIED);
        }

        // Validate that Connection.Dialect is in the dialects array
        let mut dialect_matched = false;
        for i in 0..in_dialects_count {
            let off = 24 + i * 2;
            if off + 2 <= input_blob.len() {
                let d = u16::from_le_bytes(input_blob[off..off + 2].try_into().unwrap_or_default());
                if d == session.negotiated_dialect {
                    dialect_matched = true;
                    break;
                }
            }
        }

        if !dialect_matched {
            log::warn!(
                "VALIDATE_NEGOTIATE_INFO dialect 0x{:04x} not found in client dialects",
                session.negotiated_dialect
            );
            return error_response(hdr, STATUS_ACCESS_DENIED);
        }

        let mut output = vec![0u8; 24];
        let capabilities = if session.negotiated_dialect == SMB2_DIALECT_0202 {
            0
        } else {
            SMB2_GLOBAL_CAP_LARGE_MTU
        };
        output[0..4].copy_from_slice(&capabilities.to_le_bytes());
        output[4..20].copy_from_slice(&SERVER_GUID);
        output[20..22].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode: 1 (Signing enabled)
        output[22..24].copy_from_slice(&session.negotiated_dialect.to_le_bytes());

        return build_ioctl_success_response(hdr, ctl_code, &output);
    }

    error_response(hdr, STATUS_NOT_SUPPORTED)
}

fn build_ioctl_success_response(hdr: &Smb2Header, ctl_code: u32, output: &[u8]) -> Vec<u8> {
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_IOCTL);
    let mut resp = vec![0u8; 48];
    resp[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize = 49
    resp[4..8].copy_from_slice(&ctl_code.to_le_bytes());
    resp[8..24].copy_from_slice(&[0xffu8; 16]); // FileId = all ones for DFS/validate
    resp[24..28].copy_from_slice(&112u32.to_le_bytes()); // OutputOffset = 64 + 48 = 112
    resp[28..32].copy_from_slice(&(output.len() as u32).to_le_bytes()); // OutputCount
    h.append(&mut resp);
    h.extend_from_slice(output);
    h
}

fn build_fs_info(class: u8, tree_kind: TreeKind) -> Option<Vec<u8>> {
    let (device_type, fs_name) = match tree_kind {
        TreeKind::Data => (FILE_DEVICE_DISK, "PXEASY"),
        TreeKind::Ipc => (FILE_DEVICE_NAMED_PIPE, "IPC"),
    };

    match class {
        FILE_FS_VOLUME_INFORMATION => {
            let label_bytes = crate::handlers::utils::encode_utf16_bytes(fs_name);
            let mut d = vec![0u8; 18 + label_bytes.len()];
            let now = system_time_filetime();
            d[0..8].copy_from_slice(&now.to_le_bytes()); // VolumeCreationTime
            d[8..12].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // VolumeSerialNumber
            d[12..16].copy_from_slice(&(label_bytes.len() as u32).to_le_bytes());
            d[16] = 0; // SupportsObjects = false
            d[18..].copy_from_slice(&label_bytes);
            Some(d)
        }
        FILE_FS_SIZE_INFORMATION => {
            let total_units = 1024u64 * 1024;
            let available_units = total_units;
            let mut d = vec![0u8; 24];
            d[0..8].copy_from_slice(&total_units.to_le_bytes());
            d[8..16].copy_from_slice(&available_units.to_le_bytes());
            d[16..20].copy_from_slice(&8u32.to_le_bytes()); // SectorsPerUnit
            d[20..24].copy_from_slice(&512u32.to_le_bytes()); // BytesPerSector
            Some(d)
        }
        FILE_FS_DEVICE_INFORMATION => {
            let mut d = vec![0u8; 8];
            d[0..4].copy_from_slice(&device_type.to_le_bytes());
            d[4..8].copy_from_slice(&0u32.to_le_bytes()); // Characteristics
            Some(d)
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let name_bytes = crate::handlers::utils::encode_utf16_bytes("NTFS");
            let mut d = vec![0u8; 12 + name_bytes.len()];
            let attrs = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_READ_ONLY_VOLUME;
            d[0..4].copy_from_slice(&attrs.to_le_bytes());
            d[4..8].copy_from_slice(&255u32.to_le_bytes()); // MaxFileNameLength
            d[8..12].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            d[12..].copy_from_slice(&name_bytes);
            Some(d)
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            let total_units = 1024u64 * 1024;
            let available_units = total_units;
            let mut d = vec![0u8; 32];
            d[0..8].copy_from_slice(&total_units.to_le_bytes());
            d[8..16].copy_from_slice(&available_units.to_le_bytes());
            d[16..24].copy_from_slice(&available_units.to_le_bytes());
            d[24..28].copy_from_slice(&8u32.to_le_bytes()); // SectorsPerUnit
            d[28..32].copy_from_slice(&512u32.to_le_bytes()); // BytesPerSector
            Some(d)
        }
        _ => None,
    }
}

fn build_file_info(class: u8, entry: &IsoEntry, _source_path: &std::path::Path) -> Option<Vec<u8>> {
    let attrs = if entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    let size = if entry.is_dir { 0 } else { entry.size };
    let now = system_time_filetime();

    match class {
        FILE_BASIC_INFORMATION => {
            let mut d = vec![0u8; 40];
            d[0..8].copy_from_slice(&now.to_le_bytes()); // CreationTime
            d[8..16].copy_from_slice(&now.to_le_bytes()); // LastAccessTime
            d[16..24].copy_from_slice(&now.to_le_bytes()); // LastWriteTime
            d[24..32].copy_from_slice(&now.to_le_bytes()); // ChangeTime
            d[32..36].copy_from_slice(&attrs.to_le_bytes());
            Some(d)
        }
        FILE_STANDARD_INFORMATION => {
            let mut d = vec![0u8; 24];
            d[0..8].copy_from_slice(&size.to_le_bytes()); // AllocationSize
            d[8..16].copy_from_slice(&size.to_le_bytes()); // EndOfFile
            d[16..20].copy_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
            d[20] = 0; // DeletePending
            d[21] = if entry.is_dir { 1 } else { 0 }; // Directory
            Some(d)
        }
        FILE_INTERNAL_INFORMATION => {
            let mut d = vec![0u8; 8];
            d[0..8].copy_from_slice(&stable_object_id(&entry.path).to_le_bytes());
            Some(d)
        }
        FILE_NETWORK_OPEN_INFORMATION => {
            let mut d = vec![0u8; 56];
            d[0..8].copy_from_slice(&now.to_le_bytes()); // CreationTime
            d[8..16].copy_from_slice(&now.to_le_bytes()); // LastAccessTime
            d[16..24].copy_from_slice(&now.to_le_bytes()); // LastWriteTime
            d[24..32].copy_from_slice(&now.to_le_bytes()); // ChangeTime
            d[32..40].copy_from_slice(&size.to_le_bytes()); // AllocationSize
            d[40..48].copy_from_slice(&size.to_le_bytes()); // EndOfFile
            d[48..52].copy_from_slice(&attrs.to_le_bytes()); // FileAttributes
            Some(d)
        }
        FILE_ALL_INFORMATION => {
            let mut d = vec![0u8; 100]; // Simplification
            d[0..8].copy_from_slice(&now.to_le_bytes());
            d[8..16].copy_from_slice(&now.to_le_bytes());
            d[16..24].copy_from_slice(&now.to_le_bytes());
            d[24..32].copy_from_slice(&now.to_le_bytes());
            d[32..36].copy_from_slice(&attrs.to_le_bytes());
            d[48..56].copy_from_slice(&size.to_le_bytes());
            d[56..64].copy_from_slice(&size.to_le_bytes());
            d[64..68].copy_from_slice(&1u32.to_le_bytes());
            Some(d)
        }
        _ => None,
    }
}

fn build_dir_entry(
    file_info_class: u8,
    name_bytes: &[u8],
    attrs: u32,
    file_id: u64,
    size: u64,
) -> Vec<u8> {
    let now = system_time_filetime();
    let (
        fixed_len,
        name_offset,
        ea_offset,
        short_name_len_offset,
        short_name_offset,
        file_id_offset,
    ) = match file_info_class {
        1 => (64usize, 60usize, None, None, None, None), // FileDirectoryInformation
        2 => (68usize, 60usize, Some(64usize), None, None, None), // FileFullDirectoryInformation
        3 => (
            94usize,
            60usize,
            Some(64usize),
            Some(68usize),
            Some(70usize),
            None,
        ), // FileBothDirectoryInformation
        12 => (12usize, 8usize, None, None, None, None), // FileNamesInformation
        37 => (
            104usize,
            60usize,
            Some(64usize),
            Some(68usize),
            Some(70usize),
            Some(96usize),
        ), // FileIdBothDirectoryInformation
        38 => (80usize, 60usize, Some(64usize), None, None, Some(72usize)), // FileIdFullDirectoryInformation
        _ => return Vec::new(),
    };

    let aligned_len = (fixed_len + name_bytes.len() + 7) & !7;
    let mut r = vec![0u8; aligned_len];
    r[8..16].copy_from_slice(&now.to_le_bytes());
    r[16..24].copy_from_slice(&now.to_le_bytes());
    r[24..32].copy_from_slice(&now.to_le_bytes());
    r[32..40].copy_from_slice(&now.to_le_bytes());
    if file_info_class != 12 {
        r[40..48].copy_from_slice(&size.to_le_bytes()); // EndOfFile
        r[48..56].copy_from_slice(&size.to_le_bytes()); // AllocationSize
        r[56..60].copy_from_slice(&attrs.to_le_bytes());
    }
    if let Some(offset) = ea_offset {
        r[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
    }
    if let Some(offset) = short_name_len_offset {
        r[offset] = 0;
    }
    if let Some(offset) = short_name_offset {
        r[offset..offset + 24].fill(0);
    }
    if let Some(offset) = file_id_offset {
        r[offset..offset + 8].copy_from_slice(&file_id.to_le_bytes());
    }
    r[name_offset..name_offset + 4].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    let copy_start = match file_info_class {
        12 => 12,
        _ => fixed_len,
    };
    r[copy_start..copy_start + name_bytes.len()].copy_from_slice(name_bytes);
    r
}

fn build_create_context_response(tags: &[String], path: &str) -> (u8, Vec<u8>) {
    let mut contexts = Vec::new();
    let oplock_level = 0u8;

    if tags.iter().any(|tag| tag == "MxAc") {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
        data.extend_from_slice(&0x0012_00a9u32.to_le_bytes());
        contexts.push(build_create_context(b"MxAc", &data));
    }

    if tags.iter().any(|tag| tag == "QFid") {
        let mut data = vec![0u8; 32];
        if path.is_empty() {
            data[0..8].copy_from_slice(&9u64.to_le_bytes());
            data[8..16].copy_from_slice(&0x2bu64.to_le_bytes());
        } else {
            data[0..8].copy_from_slice(&stable_object_id(path).to_le_bytes());
            data[8..16].copy_from_slice(&0x2bu64.to_le_bytes());
        }
        contexts.push(build_create_context(b"QFid", &data));
    }

    (oplock_level, chain_create_contexts(contexts))
}

fn build_create_context(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut ctx = vec![0u8; 24];
    ctx[4..6].copy_from_slice(&16u16.to_le_bytes()); // NameOffset
    ctx[6..8].copy_from_slice(&4u16.to_le_bytes()); // NameLength
    ctx[10..12].copy_from_slice(&24u16.to_le_bytes()); // DataOffset
    ctx[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
    ctx[16..20].copy_from_slice(name);
    ctx.extend_from_slice(data);
    ctx
}

fn chain_create_contexts(mut contexts: Vec<Vec<u8>>) -> Vec<u8> {
    if contexts.is_empty() {
        return Vec::new();
    }

    let mut output = Vec::new();
    let count = contexts.len();
    for (idx, mut ctx) in contexts.drain(..).enumerate() {
        let is_last = idx + 1 == count;
        if !is_last {
            while ctx.len() % 8 != 0 {
                ctx.push(0);
            }
        }
        let next = if is_last { 0 } else { ctx.len() as u32 };
        ctx[0..4].copy_from_slice(&next.to_le_bytes());
        output.extend_from_slice(&ctx);
    }
    output
}

fn allocate_wire_file_id(session: &Session, path: &str) -> u64 {
    let base = if path.is_empty() {
        0x1159_0242u64
    } else {
        stable_object_id(path) & 0xffff_ffff
    };
    base | (session.next_file_id << 32)
}

fn parse_create_context_tags(body: &[u8], offset: usize, length: usize) -> Vec<String> {
    if offset < 64 || offset + length > 64 + body.len() {
        return Vec::new();
    }
    let mut tags = Vec::new();
    let mut cursor = offset - 64;
    let end = cursor + length;

    while cursor + 16 <= end {
        let next = u32::from_le_bytes(body[cursor..cursor + 4].try_into().unwrap_or_default());
        let name_offset =
            u16::from_le_bytes(body[cursor + 4..cursor + 6].try_into().unwrap_or_default())
                as usize;
        let name_length =
            u16::from_le_bytes(body[cursor + 6..cursor + 8].try_into().unwrap_or_default())
                as usize;
        let name_start = cursor + name_offset;
        let name_end = name_start + name_length;
        if name_length > 0 && name_end <= end {
            if let Ok(tag) = std::str::from_utf8(&body[name_start..name_end]) {
                tags.push(tag.to_string());
            }
        }

        if next == 0 {
            break;
        }
        let next = next as usize;
        if next < 16 || cursor + next > end {
            break;
        }
        cursor += next;
    }

    tags
}

fn query_directory_pattern(body: &[u8], offset: usize, length: usize) -> String {
    if offset < 64 || offset + length > 64 + body.len() || length == 0 {
        return "*".to_string();
    }
    let utf16: Vec<u16> = body[offset - 64..offset - 64 + length]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&utf16)
}

fn resolve_file_id(
    body: &[u8],
    p_off: usize,
    v_off: usize,
    last_file_id: Option<u64>,
    _tree_id: u32,
    _session_id: u64,
) -> u64 {
    if v_off + 8 > body.len() {
        return last_file_id.unwrap_or(0);
    }
    let p = u64::from_le_bytes(body[p_off..p_off + 8].try_into().unwrap_or_default());
    let v = u64::from_le_bytes(body[v_off..v_off + 8].try_into().unwrap_or_default());
    if p == 0xFFFF_FFFF_FFFF_FFFF && v == 0xFFFF_FFFF_FFFF_FFFF {
        last_file_id.unwrap_or(0)
    } else {
        p
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_close, handle_create};
    use crate::constants::{SMB2_CLOSE, SMB2_CREATE, STATUS_INVALID_PARAMETER};
    use crate::proto::Command;
    use crate::proto::Smb2Header;
    use crate::session::Session;
    use crate::SmbConfig;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn test_header(command: u16) -> Smb2Header {
        Smb2Header {
            command: Command(command),
            flags: 0,
            next_command: 0,
            message_id: 1,
            tree_id: 0,
            session_id: 0,
            signature: [0u8; 16],
            credit_charge: 0,
            credit_request: 1,
        }
    }

    fn response_status(resp: &[u8]) -> u32 {
        u32::from_le_bytes(resp[8..12].try_into().unwrap_or_default())
    }

    fn test_config() -> SmbConfig {
        SmbConfig::new(
            Ipv4Addr::LOCALHOST,
            445,
            "PXE".to_string(),
            PathBuf::from("."),
        )
    }

    #[test]
    fn create_rejects_short_body_without_panicking() {
        let resp = handle_create(
            &test_header(SMB2_CREATE),
            &[0u8; 32],
            &mut Session::default(),
            &test_config(),
        );

        assert_eq!(response_status(&resp), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn close_rejects_short_body_without_panicking() {
        let resp = handle_close(
            &test_header(SMB2_CLOSE),
            &[0u8; 8],
            &mut Session::default(),
            None,
        );

        assert_eq!(response_status(&resp), STATUS_INVALID_PARAMETER);
    }
}
