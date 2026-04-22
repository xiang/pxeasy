use crate::constants::*;
use crate::handlers::utils::system_time_filetime;
use crate::proto::*;
use crate::session::Session;

pub fn handle_negotiate(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    let dialect = negotiate_dialect(body).unwrap_or(SMB2_DIALECT_021);
    let security_mode = negotiate_security_mode(body);
    let client_capabilities = negotiate_capabilities(body);
    let client_guid = negotiate_guid(body);

    session.negotiated_dialect = dialect;
    session.client_security_mode = security_mode;
    session.client_capabilities = client_capabilities;
    session.client_guid = client_guid;

    log::debug!(
        "NEGOTIATE dialects={:?} security_mode=0x{:04x} client_caps=0x{:08x} selected={}",
        offered_dialects(body),
        security_mode,
        client_capabilities,
        dialect_name(dialect)
    );

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_NEGOTIATE);
    let mut body = vec![0u8; 65]; // Strict 65 bytes
    body[0..2].copy_from_slice(&65u16.to_le_bytes()); // StructureSize = 65
    body[2..4].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode: 1 (Signing enabled, not required)
    body[4..6].copy_from_slice(&dialect.to_le_bytes());
    body[8..24].copy_from_slice(&SERVER_GUID);
    let capabilities = if dialect == SMB2_DIALECT_0202 {
        0
    } else {
        SMB2_GLOBAL_CAP_LARGE_MTU
    };
    body[24..28].copy_from_slice(&capabilities.to_le_bytes());
    body[28..32].copy_from_slice(&MAX_SMB_SIZE.to_le_bytes());
    body[32..36].copy_from_slice(&MAX_SMB_SIZE.to_le_bytes());
    body[36..40].copy_from_slice(&MAX_SMB_SIZE.to_le_bytes());
    let system_time = system_time_filetime();
    body[40..48].copy_from_slice(&system_time.to_le_bytes());
    body[48..56].copy_from_slice(&system_time.to_le_bytes());
    // SecurityBufferOffset should be 0 if SecurityBufferLength is 0
    body[56..58].copy_from_slice(&0u16.to_le_bytes());
    body[58..60].copy_from_slice(&0u16.to_le_bytes());
    h.append(&mut body);
    h
}

pub fn handle_smb1_negotiate(header: &Smb2Header, session: &mut Session) -> Vec<u8> {
    let dialect = SMB2_DIALECT_021;
    session.negotiated_dialect = dialect;
    session.client_security_mode = 1;
    session.client_capabilities = 0;
    session.client_guid = [0u8; 16];

    let mut resp = header.build_response(STATUS_SUCCESS, SMB2_NEGOTIATE);
    let mut body = vec![0u8; 65];
    body[0..2].copy_from_slice(&65u16.to_le_bytes()); // StructureSize = 65
    body[2..4].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode: 1 (Signing enabled, not required)
    body[4..6].copy_from_slice(&dialect.to_le_bytes());
    body[8..24].copy_from_slice(&SERVER_GUID);
    let capabilities = SMB2_GLOBAL_CAP_LARGE_MTU;
    body[24..28].copy_from_slice(&capabilities.to_le_bytes());
    body[28..32].copy_from_slice(&MAX_SMB_SIZE.to_le_bytes());
    body[32..36].copy_from_slice(&MAX_SMB_SIZE.to_le_bytes());
    body[36..40].copy_from_slice(&MAX_SMB_SIZE.to_le_bytes());
    let system_time = system_time_filetime();
    body[40..48].copy_from_slice(&system_time.to_le_bytes());
    body[48..56].copy_from_slice(&system_time.to_le_bytes());
    body[56..58].copy_from_slice(&0u16.to_le_bytes()); // SecurityBufferOffset
    body[58..60].copy_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
    resp.append(&mut body);
    resp
}

fn negotiate_dialect(body: &[u8]) -> Option<u16> {
    let dialects = offered_dialects(body);
    [SMB2_DIALECT_021, SMB2_DIALECT_0202]
        .into_iter()
        .find(|d| dialects.contains(d))
}

fn offered_dialects(body: &[u8]) -> Vec<u16> {
    if body.len() < 36 {
        return Vec::new();
    }
    let count = u16::from_le_bytes(body[2..4].try_into().unwrap_or_default()) as usize;
    let mut dialects = Vec::with_capacity(count);
    for i in 0..count {
        let off = 36 + i * 2;
        if off + 2 <= body.len() {
            dialects.push(u16::from_le_bytes(
                body[off..off + 2].try_into().unwrap_or_default(),
            ));
        }
    }
    dialects
}

fn negotiate_security_mode(body: &[u8]) -> u16 {
    if body.len() >= 6 {
        u16::from_le_bytes(body[4..6].try_into().unwrap_or_default())
    } else {
        0
    }
}

fn negotiate_capabilities(body: &[u8]) -> u32 {
    if body.len() >= 12 {
        u32::from_le_bytes(body[8..12].try_into().unwrap_or_default())
    } else {
        0
    }
}

fn negotiate_guid(body: &[u8]) -> [u8; 16] {
    if body.len() >= 28 {
        body[12..28].try_into().unwrap_or([0u8; 16])
    } else {
        [0u8; 16]
    }
}

fn dialect_name(dialect: u16) -> &'static str {
    match dialect {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => "unknown",
    }
}
