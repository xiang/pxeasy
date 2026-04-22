use crate::constants::*;
use crate::proto::{error_response, Smb2Header};
use crate::session::*;
use rand::random;

pub fn handle_session_setup(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    if body.len() < 24 {
        return error_response(hdr, STATUS_INVALID_PARAMETER);
    }
    let blob_offset = u16::from_le_bytes(body[12..14].try_into().unwrap_or_default()) as usize;
    let blob_len = u16::from_le_bytes(body[14..16].try_into().unwrap_or_default()) as usize;
    let security_blob = if blob_offset >= 64 && blob_offset + blob_len <= 64 + body.len() {
        &body[blob_offset - 64..blob_offset - 64 + blob_len]
    } else {
        &[]
    };

    let ntlm_type = ntlmssp_message_type(security_blob);
    log::debug!(
        "SESSION_SETUP security_blob_len={} starts_ntlmssp={} ntlm_msg_type={:?} state={:?}",
        blob_len,
        security_blob.starts_with(b"NTLMSSP\0"),
        ntlm_type,
        session.auth_state
    );

    match (session.auth_state, ntlm_type) {
        (AuthState::Initial, Some(1)) => {
            session.session_id = allocate_session_id();
            session.auth_state = AuthState::ChallengeSent;
            if session.challenge == [0u8; 8] {
                session.challenge = [0x50, 0x58, 0x45, 0x41, 0x53, 0x59, 0x30, 0x31];
            }
            let challenge_blob = build_ntlmssp_challenge(security_blob, &session.challenge);
            build_session_setup_response(
                hdr,
                STATUS_MORE_PROCESSING_REQUIRED,
                session.session_id,
                0,
                &challenge_blob,
            )
        }
        (AuthState::ChallengeSent, Some(3)) => {
            session.auth_state = AuthState::Authenticated;
            let mut session_flags = 0u16;
            session.session_key = None;
            session.is_signing_required = false;
            if security_blob.len() >= 64 {
                const NTLMSSP_NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
                const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
                let flags =
                    u32::from_le_bytes(security_blob[60..64].try_into().unwrap_or_default());
                let domain_len =
                    u16::from_le_bytes(security_blob[28..30].try_into().unwrap_or_default())
                        as usize;
                let user_len =
                    u16::from_le_bytes(security_blob[36..38].try_into().unwrap_or_default())
                        as usize;
                let user_offset =
                    u32::from_le_bytes(security_blob[40..44].try_into().unwrap_or_default())
                        as usize;
                let username = if user_offset + user_len <= security_blob.len() {
                    String::from_utf16_lossy(
                        &security_blob[user_offset..user_offset + user_len]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<u16>>(),
                    )
                } else {
                    "unknown".to_string()
                };

                log::debug!(
                    "SESSION_SETUP NTLM Type 3 flags=0x{:08x} user={}",
                    flags,
                    username
                );

                let is_anonymous = (flags & NTLMSSP_NEGOTIATE_ANONYMOUS) != 0
                    || (username.is_empty() && domain_len == 0);
                let key_len =
                    u16::from_le_bytes(security_blob[52..54].try_into().unwrap_or_default())
                        as usize;
                let key_offset =
                    u32::from_le_bytes(security_blob[56..60].try_into().unwrap_or_default())
                        as usize;
                let encrypted_key = if key_len == 16 && key_offset + key_len <= security_blob.len()
                {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&security_blob[key_offset..key_offset + key_len]);
                    Some(key)
                } else {
                    None
                };

                if is_anonymous {
                    log::debug!("SESSION_SETUP anonymous login detected");
                    if let Some(encrypted_key) = encrypted_key {
                        let mut base_key = [0u8; 16];
                        let session_key = if (flags & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0 {
                            rc4_crypt(&base_key, &encrypted_key)
                        } else {
                            encrypted_key
                        };
                        base_key.copy_from_slice(&session_key);
                        session.session_key = Some(base_key);
                        session.is_signing_required = true;
                        log::debug!("SESSION_SETUP derived anonymous session_key for signing");
                    }
                } else if username.eq_ignore_ascii_case("guest") {
                    session_flags = SMB2_SESSION_FLAG_IS_GUEST;
                    log::debug!("SESSION_SETUP guest login detected");
                    if let Some(key) = encrypted_key {
                        session.session_key = Some(key);
                        session.is_signing_required = true;
                        log::debug!("SESSION_SETUP extracted session_key for signing");
                    }
                } else if let Some(key) = encrypted_key {
                    session.session_key = Some(key);
                    session.is_signing_required = true;
                    log::debug!("SESSION_SETUP extracted session_key for signing");
                }
            }

            build_session_setup_response(
                hdr,
                STATUS_SUCCESS,
                session.session_id,
                session_flags,
                &[],
            )
        }
        _ => {
            // Fallback for anonymous/guest without full NTLMSSP
            if session.session_id == 0 {
                session.session_id = allocate_session_id();
            }
            session.auth_state = AuthState::Authenticated;
            build_session_setup_response(
                hdr,
                STATUS_SUCCESS,
                session.session_id,
                SMB2_SESSION_FLAG_IS_GUEST,
                &[],
            )
        }
    }
}

fn allocate_session_id() -> u64 {
    loop {
        let candidate = random::<u64>() | 0x0000_0001_0000_0000;
        if candidate != 0 && candidate != 1 {
            return candidate;
        }
    }
}

pub fn handle_logoff(hdr: &Smb2Header) -> Vec<u8> {
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_LOGOFF);
    let mut body = vec![0u8; 4];
    body[0..2].copy_from_slice(&4u16.to_le_bytes()); // StructureSize = 4
    h.append(&mut body);
    h
}

fn build_session_setup_response(
    hdr: &Smb2Header,
    status: u32,
    session_id: u64,
    session_flags: u16,
    security_blob: &[u8],
) -> Vec<u8> {
    let mut h = hdr.build_response(status, SMB2_SESSION_SETUP);
    h[14..16].copy_from_slice(&32u16.to_le_bytes()); // grant 32 credits
    h[40..48].copy_from_slice(&session_id.to_le_bytes());

    let mut fixed = vec![0u8; 16]; // 9 bytes fixed + 7 bytes padding for 8-byte alignment
    fixed[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
    fixed[2..4].copy_from_slice(&session_flags.to_le_bytes());
    // Use 80 if length > 0, else 0 (64 header + 16 fixed)
    let blob_len = security_blob.len() as u16;
    let blob_offset = if blob_len > 0 { 80u16 } else { 0u16 };
    fixed[4..6].copy_from_slice(&blob_offset.to_le_bytes());
    fixed[6..8].copy_from_slice(&blob_len.to_le_bytes());

    h.extend_from_slice(&fixed);
    h.extend_from_slice(security_blob);
    h
}

fn ntlmssp_message_type(blob: &[u8]) -> Option<u32> {
    if blob.len() < 12 || !blob.starts_with(b"NTLMSSP\0") {
        return None;
    }
    Some(u32::from_le_bytes(blob[8..12].try_into().ok()?))
}

fn build_ntlmssp_challenge(negotiate_blob: &[u8], challenge: &[u8; 8]) -> Vec<u8> {
    const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
    const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
    const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
    const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;
    const MSV_AV_EOL: u16 = 0x0000;
    const MSV_AV_NB_COMPUTER_NAME: u16 = 0x0001;
    const MSV_AV_NB_DOMAIN_NAME: u16 = 0x0002;
    const MSV_AV_DNS_COMPUTER_NAME: u16 = 0x0003;
    const MSV_AV_TIMESTAMP: u16 = 0x0007;

    let client_flags = if negotiate_blob.len() >= 16 {
        u32::from_le_bytes(negotiate_blob[12..16].try_into().unwrap_or_default())
    } else {
        0
    };

    let mut flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_TARGET_TYPE_SERVER;
    flags |= client_flags
        & (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLMSSP_NEGOTIATE_128
            | NTLMSSP_NEGOTIATE_56);

    let mut av_pairs = Vec::new();
    let target_name = utf16le("PXEASY");
    let netbios_domain = utf16le("WORKGROUP");
    let dns_name = utf16le("pxeasy.local");
    append_av_pair(&mut av_pairs, MSV_AV_NB_DOMAIN_NAME, &netbios_domain);
    append_av_pair(&mut av_pairs, MSV_AV_NB_COMPUTER_NAME, &target_name);
    append_av_pair(&mut av_pairs, MSV_AV_DNS_COMPUTER_NAME, &dns_name);
    let now = crate::handlers::utils::system_time_filetime();
    append_av_pair(&mut av_pairs, MSV_AV_TIMESTAMP, &now.to_le_bytes());
    append_av_pair(&mut av_pairs, MSV_AV_EOL, &[]);

    // Standard header is 56 bytes.
    let target_name_offset = 56u32;
    let target_info_offset = target_name_offset + target_name.len() as u32;

    let mut blob = Vec::with_capacity(target_info_offset as usize + av_pairs.len());
    blob.extend_from_slice(b"NTLMSSP\0");
    blob.extend_from_slice(&2u32.to_le_bytes()); // Type 2: Challenge
    blob.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    blob.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    blob.extend_from_slice(&target_name_offset.to_le_bytes());
    blob.extend_from_slice(&flags.to_le_bytes());
    blob.extend_from_slice(challenge);
    blob.extend_from_slice(&[0u8; 8]); // Reserved
    blob.extend_from_slice(&(av_pairs.len() as u16).to_le_bytes());
    blob.extend_from_slice(&(av_pairs.len() as u16).to_le_bytes());
    blob.extend_from_slice(&target_info_offset.to_le_bytes());
    blob.extend_from_slice(&[0u8; 8]); // Version

    blob.extend_from_slice(&target_name);
    blob.extend_from_slice(&av_pairs);
    blob
}

fn append_av_pair(buf: &mut Vec<u8>, av_id: u16, value: &[u8]) {
    buf.extend_from_slice(&av_id.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
}

fn utf16le(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn rc4_crypt(key: &[u8], input: &[u8; 16]) -> [u8; 16] {
    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }

    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }

    let mut i = 0usize;
    j = 0;
    let mut out = [0u8; 16];
    for (idx, byte) in input.iter().enumerate() {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out[idx] = *byte ^ k;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntlmssp_negotiate_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 40];
        blob[0..8].copy_from_slice(b"NTLMSSP\0");
        blob[8..12].copy_from_slice(&1u32.to_le_bytes());
        blob[12..16].copy_from_slice(&0x0008_8201u32.to_le_bytes());
        blob
    }

    fn make_session_setup_request(security_blob: &[u8]) -> (Smb2Header, Vec<u8>) {
        let hdr = Smb2Header {
            command: crate::proto::Command(SMB2_SESSION_SETUP),
            flags: 0,
            next_command: 0,
            message_id: 1,
            tree_id: 0,
            session_id: 0,
            credit_charge: 0,
            credit_request: 1,
            signature: [0u8; 16],
        };
        let mut body = vec![0u8; 24 + security_blob.len()];
        body[0..2].copy_from_slice(&25u16.to_le_bytes());
        body[12..14].copy_from_slice(&(64u16 + 24u16).to_le_bytes());
        body[14..16].copy_from_slice(&(security_blob.len() as u16).to_le_bytes());
        body[24..24 + security_blob.len()].copy_from_slice(security_blob);
        (hdr, body)
    }

    #[test]
    fn session_setup_type1_returns_valid_ntstatus_and_nonzero_challenge() {
        let negotiate = ntlmssp_negotiate_blob();
        let (hdr, body) = make_session_setup_request(&negotiate);
        let mut session = Session::default();

        let resp = handle_session_setup(&hdr, &body, &mut session);

        assert_eq!(
            u32::from_le_bytes(resp[8..12].try_into().unwrap_or_default()),
            STATUS_MORE_PROCESSING_REQUIRED
        );
        let session_id = u64::from_le_bytes(resp[40..48].try_into().unwrap_or_default());
        assert_ne!(session_id, 0);
        assert_ne!(session_id, 1);
        assert_eq!(
            u16::from_le_bytes(resp[64..66].try_into().unwrap_or_default()),
            9
        );
        assert_eq!(
            u16::from_le_bytes(resp[68..70].try_into().unwrap_or_default()),
            80
        );
        let token = &resp[80..];
        assert!(token.starts_with(b"NTLMSSP\0"));
        assert_eq!(
            u32::from_le_bytes(token[8..12].try_into().unwrap_or_default()),
            2
        );
        assert_ne!(&token[24..32], &[0u8; 8]);
    }

    #[test]
    fn ntlm_challenge_contains_utf16_target_name_and_target_info() {
        let token = build_ntlmssp_challenge(&ntlmssp_negotiate_blob(), b"PXEASY01");

        let target_name_len = u16::from_le_bytes(token[12..14].try_into().unwrap_or_default());
        let target_name_offset =
            u32::from_le_bytes(token[16..20].try_into().unwrap_or_default()) as usize;
        let target_info_len = u16::from_le_bytes(token[40..42].try_into().unwrap_or_default());
        let target_info_offset =
            u32::from_le_bytes(token[44..48].try_into().unwrap_or_default()) as usize;

        assert_eq!(target_name_offset, 56);
        assert_eq!(target_name_len as usize, utf16le("PXEASY").len());
        assert_eq!(
            &token[target_name_offset..target_name_offset + target_name_len as usize],
            utf16le("PXEASY").as_slice()
        );
        assert!(target_info_len > 0);
        assert_eq!(
            target_info_offset,
            target_name_offset + target_name_len as usize
        );
    }

    fn ntlmssp_anonymous_auth_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 121];
        blob[0..8].copy_from_slice(b"NTLMSSP\0");
        blob[8..12].copy_from_slice(&3u32.to_le_bytes());
        blob[12..14].copy_from_slice(&1u16.to_le_bytes()); // LM len
        blob[14..16].copy_from_slice(&1u16.to_le_bytes());
        blob[16..20].copy_from_slice(&104u32.to_le_bytes());
        blob[52..54].copy_from_slice(&16u16.to_le_bytes()); // session key len
        blob[54..56].copy_from_slice(&16u16.to_le_bytes());
        blob[56..60].copy_from_slice(&105u32.to_le_bytes());
        blob[60..64].copy_from_slice(&0xe2888a15u32.to_le_bytes());
        blob[44..46].copy_from_slice(&16u16.to_le_bytes()); // host len
        blob[46..48].copy_from_slice(&16u16.to_le_bytes());
        blob[48..52].copy_from_slice(&88u32.to_le_bytes());
        blob[88..104].copy_from_slice(utf16le("MINWINPC").as_slice());
        blob[104] = 0;
        blob[105..121].copy_from_slice(&[
            0xa9, 0x1f, 0xd5, 0xc3, 0xa7, 0x23, 0x6f, 0xb3, 0xe9, 0x4c, 0xdb, 0x9a, 0x1e, 0xb2,
            0xc7, 0xe1,
        ]);
        blob
    }

    #[test]
    fn anonymous_type3_uses_zero_session_flags_and_derives_signing_key() {
        let negotiate = ntlmssp_negotiate_blob();
        let (hdr, body) = make_session_setup_request(&negotiate);
        let mut session = Session::default();

        let challenge_resp = handle_session_setup(&hdr, &body, &mut session);
        let session_id = u64::from_le_bytes(challenge_resp[40..48].try_into().unwrap_or_default());
        let (hdr, body) = make_session_setup_request(&ntlmssp_anonymous_auth_blob());
        let hdr = Smb2Header { session_id, ..hdr };

        let resp = handle_session_setup(&hdr, &body, &mut session);

        assert_eq!(
            u32::from_le_bytes(resp[8..12].try_into().unwrap_or_default()),
            STATUS_SUCCESS
        );
        assert_eq!(
            u16::from_le_bytes(resp[66..68].try_into().unwrap_or_default()),
            0
        );
        assert_eq!(
            session.session_key,
            Some([
                0x77, 0x07, 0x5c, 0x82, 0x04, 0x14, 0x32, 0x89, 0x63, 0x4a, 0xc5, 0xfd, 0x49, 0xdc,
                0x55, 0x8c,
            ])
        );
        assert!(session.is_signing_required);
    }
}
