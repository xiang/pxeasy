//! Minimal read-only SMB2 server for serving Windows ISO contents over the network.
//!
//! Supports the protocol subset required for WinPE to connect and read installer files:
//! NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, QUERY_INFO, QUERY_DIRECTORY,
//! CLOSE, LOGOFF, TREE_DISCONNECT, IOCTL (returns error). All write-class commands return
//! STATUS_ACCESS_DENIED.

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime},
};

pub struct SmbConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    pub share_name: String,
    pub source_path: PathBuf,
}

pub struct SmbServer {
    listener: TcpListener,
    config: Arc<SmbConfig>,
}

impl SmbServer {
    pub fn bind(config: SmbConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(config.bind_ip),
            config.bind_port,
        ))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        let mut threads = Vec::new();
        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if let Err(e) = stream.set_nonblocking(false) {
                        log::warn!("smb: set blocking failed for {peer}: {e}");
                        continue;
                    }
                    let config = Arc::clone(&self.config);
                    let handle = thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, &config) {
                            if e.kind() != io::ErrorKind::BrokenPipe
                                && e.kind() != io::ErrorKind::ConnectionReset
                            {
                                log::warn!("smb: connection from {peer} failed: {e}");
                            }
                        }
                    });
                    threads.push(handle);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(250));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SMB2 constants
// ---------------------------------------------------------------------------

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const SMB1_MAGIC: &[u8; 4] = b"\xffSMB";

// SMB2 command codes
const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_LOGOFF: u16 = 0x0002;
const SMB2_TREE_CONNECT: u16 = 0x0003;
const SMB2_TREE_DISCONNECT: u16 = 0x0004;
const SMB2_CREATE: u16 = 0x0005;
const SMB2_CLOSE: u16 = 0x0006;
const SMB2_READ: u16 = 0x0008;
const SMB2_ECHO: u16 = 0x000d;
const SMB2_QUERY_INFO: u16 = 0x0010;
const SMB2_QUERY_DIRECTORY: u16 = 0x000e;
const SMB2_IOCTL: u16 = 0x000b;

// Write-class commands — return ACCESS_DENIED
const SMB2_WRITE: u16 = 0x0009;
const SMB2_SET_INFO: u16 = 0x0011;
const SMB2_CHANGE_NOTIFY: u16 = 0x000f;
const SMB2_LOCK: u16 = 0x000a;
const SMB2_CANCEL: u16 = 0x0016;
const SMB2_OPLOCK_BREAK: u16 = 0x0012;
const SMB2_FLUSH: u16 = 0x0007;

// NTSTATUS codes
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_0035;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_FS_DRIVER_REQUIRED: u32 = 0xC000_019C;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;

// Dialect revisions
const SMB2_DIALECT_0202: u16 = 0x0202;
const SMB2_DIALECT_021: u16 = 0x0210;
const SMB2_DIALECT_WILDCARD: u16 = 0x02ff;
const SERVER_GUID: [u8; 16] = [
    0x70, 0x78, 0x65, 0x61, 0x73, 0x79, 0x2d, 0x73, 0x6d, 0x62, 0x2d, 0x67, 0x75, 0x69, 0x64, 0x31,
];

// File attribute flags
const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;

const TREE_SHARE_TYPE_DISK: u8 = 0x01;
const TREE_SHARE_TYPE_PIPE: u8 = 0x02;
const SMB2_GLOBAL_CAP_LARGE_MTU: u32 = 0x0000_0004;
const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_DEVICE_NAMED_PIPE: u32 = 0x0000_0011;
const FILE_FS_ATTRIBUTE_INFORMATION: u8 = 5;
const FILE_FS_DEVICE_INFORMATION: u8 = 4;
const FILE_FS_SIZE_INFORMATION: u8 = 3;
const FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;
const FILE_FS_SECTOR_SIZE_INFORMATION: u8 = 11;
const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;

// ---------------------------------------------------------------------------
// Netbios Session Service framing
// ---------------------------------------------------------------------------

fn read_nbss_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    // Byte 0: type (0 = session message)
    // Bytes 1-3: length (big-endian 3 bytes)
    let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NBSS frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_nbss_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let len = payload.len();
    let header = [
        0u8,
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
    ];
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// SMB2 message header (64 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Smb2Header {
    command: u16,
    flags: u32,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
}

impl Smb2Header {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 64 {
            return None;
        }
        if &buf[0..4] != SMB2_MAGIC {
            return None;
        }
        Some(Self {
            command: u16::from_le_bytes(buf[12..14].try_into().ok()?),
            flags: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            message_id: u64::from_le_bytes(buf[24..32].try_into().ok()?),
            tree_id: u32::from_le_bytes(buf[36..40].try_into().ok()?),
            session_id: u64::from_le_bytes(buf[40..48].try_into().ok()?),
        })
    }

    fn build_response(&self, status: u32, command: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(SMB2_MAGIC);
        h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
                                                       // ChannelSequence/Reserved at 6..8 = 0
                                                       // Status
        h[8..12].copy_from_slice(&status.to_le_bytes());
        // Command
        h[12..14].copy_from_slice(&command.to_le_bytes());
        // CreditResponse = 1
        h[14..16].copy_from_slice(&1u16.to_le_bytes());
        // Flags: SERVER_TO_REDIR = bit 0
        let flags = self.flags | 0x0000_0001;
        h[16..20].copy_from_slice(&flags.to_le_bytes());
        // NextCommand = 0
        // MessageId
        h[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        // ProcessId/Reserved = 0
        // TreeId
        h[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        // SessionId
        h[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        // Signature = 0
        h
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Session {
    session_id: u64,
    auth_state: AuthState,
    tree_connected: bool,
    tree_id: u32,
    tree_kind: TreeKind,
    // file_id → IsoEntry
    open_files: HashMap<u128, IsoEntry>,
    next_file_id: u64,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum AuthState {
    #[default]
    Initial,
    ChallengeSent,
    Authenticated,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum TreeKind {
    #[default]
    Data,
    Ipc,
}

#[derive(Clone)]
struct IsoEntry {
    path: String,
    is_dir: bool,
    size: u64,
    // For directory enumeration: list of child names
    children: Option<Vec<String>>,
    // Enumeration position
    enum_pos: usize,
}

// ---------------------------------------------------------------------------
// Main connection handler
// ---------------------------------------------------------------------------

fn handle_connection(mut stream: TcpStream, config: &SmbConfig) -> io::Result<()> {
    let mut session = Session::default();
    let peer = stream.peer_addr().ok();
    log::debug!("smb: {peer:?} connected");

    loop {
        let frame = read_nbss_frame(&mut stream)?;
        if frame.is_empty() {
            log::debug!("smb: {peer:?} closed");
            return Ok(());
        }

        // SMB1 NEGOTIATE — respond with SMB2 negotiate
        if frame.len() >= 4 && &frame[0..4] == SMB1_MAGIC {
            log::debug!("smb: {peer:?} SMB1 negotiate -> SMB2 upgrade");
            let resp = build_smb1_to_smb2_response();
            write_nbss_frame(&mut stream, &resp)?;
            continue;
        }

        if frame.len() < 64 {
            return Ok(());
        }

        let hdr = match Smb2Header::parse(&frame) {
            Some(h) => h,
            None => return Ok(()),
        };

        let body = &frame[64..];
        log::debug!(
            "smb: {peer:?} request cmd={} msg_id={} tree_id={} session_id={} body_len={}",
            command_name(hdr.command),
            hdr.message_id,
            hdr.tree_id,
            hdr.session_id,
            body.len()
        );
        let response = dispatch(&hdr, body, &mut session, config)?;
        if let Some(resp) = response {
            if resp.len() >= 12 {
                let status = u32::from_le_bytes(resp[8..12].try_into().unwrap_or_default());
                log::debug!(
                    "smb: {peer:?} response cmd={} msg_id={} status={}",
                    command_name(hdr.command),
                    hdr.message_id,
                    status_name(status)
                );
            }
            write_nbss_frame(&mut stream, &resp)?;
        }
    }
}

fn dispatch(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> io::Result<Option<Vec<u8>>> {
    match hdr.command {
        SMB2_NEGOTIATE => Ok(Some(handle_negotiate(hdr, body))),
        SMB2_SESSION_SETUP => Ok(Some(handle_session_setup(hdr, body, session))),
        SMB2_LOGOFF => Ok(Some(handle_logoff(hdr))),
        SMB2_TREE_CONNECT => Ok(Some(handle_tree_connect(hdr, body, session, config))),
        SMB2_TREE_DISCONNECT => Ok(Some(handle_tree_disconnect(hdr, session))),
        SMB2_CREATE => Ok(Some(handle_create(hdr, body, session, config))),
        SMB2_CLOSE => Ok(Some(handle_close(hdr, body, session))),
        SMB2_READ => Ok(Some(handle_read(hdr, body, session, config))),
        SMB2_ECHO => Ok(Some(handle_echo(hdr))),
        SMB2_QUERY_INFO => Ok(Some(handle_query_info(hdr, body, session))),
        SMB2_QUERY_DIRECTORY => Ok(Some(handle_query_directory(hdr, body, session, config))),
        SMB2_IOCTL => Ok(Some(handle_ioctl(hdr, body))),
        SMB2_WRITE | SMB2_SET_INFO | SMB2_CHANGE_NOTIFY | SMB2_LOCK | SMB2_FLUSH
        | SMB2_OPLOCK_BREAK => Ok(Some(error_response(hdr, STATUS_ACCESS_DENIED))),
        SMB2_CANCEL => Ok(None),
        _ => {
            log::debug!("smb: unhandled command 0x{:04x}", hdr.command);
            Ok(Some(error_response(hdr, STATUS_NOT_SUPPORTED)))
        }
    }
}

// ---------------------------------------------------------------------------
// SMB1 → SMB2 upgrade response
// ---------------------------------------------------------------------------

fn build_smb1_to_smb2_response() -> Vec<u8> {
    // Multi-protocol negotiate uses an SMB1 request that carries the "SMB 2.???"
    // dialect. The server replies with an SMB2 NEGOTIATE response using the
    // wildcard dialect 0x02ff, which prompts the client to send a real SMB2
    // NEGOTIATE next.
    let header = Smb2Header {
        command: SMB2_NEGOTIATE,
        flags: 0,
        message_id: 0,
        tree_id: 0,
        session_id: 0,
    };
    let mut resp = header.build_response(STATUS_SUCCESS, SMB2_NEGOTIATE);
    let mut body = vec![0u8; 65];
    body[0..2].copy_from_slice(&65u16.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes()); // SIGNING_ENABLED
    body[4..6].copy_from_slice(&SMB2_DIALECT_WILDCARD.to_le_bytes());
    body[24..28].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    body[28..32].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    body[32..36].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    body[52..54].copy_from_slice(&128u16.to_le_bytes());
    resp.append(&mut body);
    resp
}

// ---------------------------------------------------------------------------
// NEGOTIATE
// ---------------------------------------------------------------------------

fn handle_negotiate(hdr: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let dialect = negotiate_dialect(body).unwrap_or(SMB2_DIALECT_021);
    let security_mode = negotiate_security_mode(body);
    let client_capabilities = negotiate_capabilities(body);
    log::debug!(
        "smb: NEGOTIATE dialects={:?} security_mode=0x{:04x} client_caps=0x{:08x} selected={}",
        offered_dialects(body),
        security_mode,
        client_capabilities,
        dialect_name(dialect)
    );

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_NEGOTIATE);
    // Negotiate response body (65 bytes minimum)
    let mut body = vec![0u8; 65];
    // StructureSize = 65
    body[0..2].copy_from_slice(&65u16.to_le_bytes());
    // SecurityMode = SIGNING_ENABLED (bit 0)
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    // DialectRevision
    body[4..6].copy_from_slice(&dialect.to_le_bytes());
    // NegotiateContextCount = 0
    body[8..24].copy_from_slice(&SERVER_GUID);
    let capabilities = if dialect == SMB2_DIALECT_0202 {
        0
    } else {
        SMB2_GLOBAL_CAP_LARGE_MTU
    };
    body[24..28].copy_from_slice(&capabilities.to_le_bytes());
    // MaxTransactSize
    body[28..32].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    // MaxReadSize
    body[32..36].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    // MaxWriteSize
    body[36..40].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    let system_time = system_time_filetime();
    body[40..48].copy_from_slice(&system_time.to_le_bytes());
    body[48..56].copy_from_slice(&system_time.to_le_bytes());
    // SecurityBufferOffset = 128 (= 64 header + 64 body offset)
    body[56..58].copy_from_slice(&128u16.to_le_bytes());
    // SecurityBufferLength = 0
    // NegotiateContextOffset = 0

    h.append(&mut body);
    h
}

fn negotiate_dialect(body: &[u8]) -> Option<u16> {
    let dialects = offered_dialects(body);
    [SMB2_DIALECT_021, SMB2_DIALECT_0202]
        .into_iter()
        .find(|candidate| dialects.contains(candidate))
}

fn offered_dialects(body: &[u8]) -> Vec<u16> {
    if body.len() < 8 {
        return Vec::new();
    }
    let dialect_count = u16::from_le_bytes(body[2..4].try_into().unwrap_or_default()) as usize;
    let dialect_bytes = dialect_count.saturating_mul(2);
    let start = 36usize.min(body.len());
    let end = start.saturating_add(dialect_bytes).min(body.len());
    body[start..end]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect()
}

fn negotiate_security_mode(body: &[u8]) -> u16 {
    if body.len() < 4 {
        return 0;
    }
    u16::from_le_bytes(body[4..6].try_into().unwrap_or_default())
}

fn negotiate_capabilities(body: &[u8]) -> u32 {
    if body.len() < 12 {
        return 0;
    }
    u32::from_le_bytes(body[8..12].try_into().unwrap_or_default())
}

fn system_time_filetime() -> u64 {
    const WINDOWS_EPOCH_OFFSET_SECS: u64 = 11_644_473_600;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            (duration.as_secs() + WINDOWS_EPOCH_OFFSET_SECS) * 10_000_000
                + u64::from(duration.subsec_nanos() / 100)
        }
        Err(_) => 0,
    }
}

fn dialect_name(dialect: u16) -> &'static str {
    match dialect {
        SMB2_DIALECT_0202 => "SMB 2.0.2",
        SMB2_DIALECT_021 => "SMB 2.1",
        SMB2_DIALECT_WILDCARD => "SMB 2.???",
        _ => "unknown",
    }
}

fn build_session_setup_response(
    hdr: &Smb2Header,
    status: u32,
    session_id: u64,
    session_flags: u16,
    security_blob: &[u8],
) -> Vec<u8> {
    let mut h = hdr.build_response(status, SMB2_SESSION_SETUP);
    h[40..48].copy_from_slice(&session_id.to_le_bytes());

    let mut fixed = vec![0u8; 8];
    fixed[0..2].copy_from_slice(&9u16.to_le_bytes());
    fixed[2..4].copy_from_slice(&session_flags.to_le_bytes());
    if !security_blob.is_empty() {
        fixed[4..6].copy_from_slice(&(64u16 + 8u16).to_le_bytes());
        fixed[6..8].copy_from_slice(&(security_blob.len() as u16).to_le_bytes());
    }

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

fn build_ntlmssp_challenge(negotiate_blob: &[u8]) -> Vec<u8> {
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

    let target_name: Vec<u8> = "PXEASY"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let dns_name: Vec<u8> = "pxeasy"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut target_info = Vec::new();
    append_av_pair(&mut target_info, MSV_AV_NB_COMPUTER_NAME, &target_name);
    append_av_pair(&mut target_info, MSV_AV_NB_DOMAIN_NAME, &target_name);
    append_av_pair(&mut target_info, MSV_AV_DNS_COMPUTER_NAME, &dns_name);
    append_av_pair(
        &mut target_info,
        MSV_AV_TIMESTAMP,
        &system_time_filetime().to_le_bytes(),
    );
    append_av_pair(&mut target_info, MSV_AV_EOL, &[]);

    let target_name_offset = 48u32;
    let target_info_offset = target_name_offset + target_name.len() as u32;
    let mut token = vec![0u8; target_info_offset as usize + target_info.len()];
    token[0..8].copy_from_slice(b"NTLMSSP\0");
    token[8..12].copy_from_slice(&2u32.to_le_bytes());
    token[12..14].copy_from_slice(&(target_name.len() as u16).to_le_bytes());
    token[14..16].copy_from_slice(&(target_name.len() as u16).to_le_bytes());
    token[16..20].copy_from_slice(&target_name_offset.to_le_bytes());
    token[20..24].copy_from_slice(&flags.to_le_bytes());
    token[24..32].copy_from_slice(&[0x50, 0x58, 0x45, 0x41, 0x53, 0x59, 0x30, 0x31]);
    token[32..40].copy_from_slice(&[0u8; 8]);
    token[40..42].copy_from_slice(&(target_info.len() as u16).to_le_bytes());
    token[42..44].copy_from_slice(&(target_info.len() as u16).to_le_bytes());
    token[44..48].copy_from_slice(&target_info_offset.to_le_bytes());
    token[target_name_offset as usize..target_info_offset as usize].copy_from_slice(&target_name);
    token[target_info_offset as usize..].copy_from_slice(&target_info);
    token
}

fn append_av_pair(buf: &mut Vec<u8>, av_id: u16, value: &[u8]) {
    buf.extend_from_slice(&av_id.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
}

// ---------------------------------------------------------------------------
// SESSION_SETUP
// ---------------------------------------------------------------------------

fn handle_session_setup(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    if session.session_id == 0 {
        session.session_id = 1;
    }
    let (sec_offset, sec_length) = if body.len() >= 16 {
        (
            u16::from_le_bytes(body[12..14].try_into().unwrap_or_default()) as usize,
            u16::from_le_bytes(body[14..16].try_into().unwrap_or_default()) as usize,
        )
    } else {
        (0, 0)
    };
    let sec_start = sec_offset.saturating_sub(64);
    let sec_end = sec_start.saturating_add(sec_length);
    let sec_blob = if sec_start < sec_end && sec_end <= body.len() {
        &body[sec_start..sec_end]
    } else {
        &[]
    };
    log::debug!(
        "smb: SESSION_SETUP security_blob_len={} starts_ntlmssp={} ntlm_msg_type={:?} state={:?}",
        sec_blob.len(),
        sec_blob.starts_with(b"NTLMSSP\0"),
        ntlmssp_message_type(sec_blob),
        session.auth_state
    );
    match ntlmssp_message_type(sec_blob) {
        Some(1) if hdr.session_id == 0 || session.auth_state == AuthState::Initial => {
            session.auth_state = AuthState::ChallengeSent;
            build_session_setup_response(
                hdr,
                STATUS_MORE_PROCESSING_REQUIRED,
                session.session_id,
                0,
                &build_ntlmssp_challenge(sec_blob),
            )
        }
        Some(3) if hdr.session_id == session.session_id || hdr.session_id == 0 => {
            session.auth_state = AuthState::Authenticated;
            build_session_setup_response(hdr, STATUS_SUCCESS, session.session_id, 0, &[])
        }
        _ if sec_blob.is_empty() => {
            build_session_setup_response(hdr, STATUS_SUCCESS, session.session_id, 0, &[])
        }
        _ => build_session_setup_response(hdr, STATUS_LOGON_FAILURE, session.session_id, 0, &[]),
    }
}

// ---------------------------------------------------------------------------
// LOGOFF
// ---------------------------------------------------------------------------

fn handle_logoff(hdr: &Smb2Header) -> Vec<u8> {
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_LOGOFF);
    let mut body = vec![0u8; 4];
    body[0..2].copy_from_slice(&4u16.to_le_bytes()); // StructureSize
    h.append(&mut body);
    h
}

// ---------------------------------------------------------------------------
// TREE_CONNECT
// ---------------------------------------------------------------------------

fn handle_tree_connect(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> Vec<u8> {
    // Extract share path from request
    // Body: StructureSize(2), Reserved(2), PathOffset(2), PathLength(2), Path(variable)
    if body.len() < 8 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }
    let path_offset = u16::from_le_bytes(body[4..6].try_into().unwrap_or_default()) as usize;
    let path_length = u16::from_le_bytes(body[6..8].try_into().unwrap_or_default()) as usize;

    // PathOffset is relative to start of SMB2 message (i.e. includes the 64-byte header)
    let header_size = 64usize;
    let start = path_offset.saturating_sub(header_size);
    let end = start.saturating_add(path_length);
    let share_name = if end <= body.len() {
        decode_utf16le(&body[start..end])
    } else {
        String::new()
    };

    // Accept \\*\<share_name> regardless of server name
    let share_lower = share_name.to_ascii_lowercase();
    let expected = format!("\\{}", config.share_name);
    let accepted = share_name
        .split_once('\\')
        .map(|(_, rest)| format!("\\{}", rest.rsplit('\\').next().unwrap_or("")))
        .as_deref()
        == Some(expected.as_str())
        || share_lower.ends_with(&format!("\\{}", config.share_name.to_ascii_lowercase()))
        || share_lower.ends_with("\\ipc$");

    if !accepted {
        log::debug!("smb: TREE_CONNECT rejected share: {:?}", share_name);
        return error_response(hdr, STATUS_BAD_NETWORK_NAME);
    }

    session.tree_connected = true;
    session.tree_id = 1;
    session.tree_kind = if share_name.to_ascii_lowercase().ends_with("\\ipc$") {
        TreeKind::Ipc
    } else {
        TreeKind::Data
    };
    log::debug!(
        "smb: TREE_CONNECT accepted share={share_name:?} kind={:?}",
        session.tree_kind
    );

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_TREE_CONNECT);
    // Patch tree_id in response header
    h[36..40].copy_from_slice(&1u32.to_le_bytes());

    let mut resp_body = vec![0u8; 16];
    resp_body[0..2].copy_from_slice(&16u16.to_le_bytes()); // StructureSize
    resp_body[2] = match session.tree_kind {
        TreeKind::Data => TREE_SHARE_TYPE_DISK,
        TreeKind::Ipc => TREE_SHARE_TYPE_PIPE,
    };
    // ShareFlags, Capabilities, MaximalAccess
    resp_body[12..16].copy_from_slice(&0x001F_01FFu32.to_le_bytes()); // MaximalAccess: full for read

    h.append(&mut resp_body);
    h
}

// ---------------------------------------------------------------------------
// TREE_DISCONNECT
// ---------------------------------------------------------------------------

fn handle_tree_disconnect(hdr: &Smb2Header, session: &mut Session) -> Vec<u8> {
    session.tree_connected = false;
    session.tree_kind = TreeKind::Data;
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_TREE_DISCONNECT);
    let mut body = vec![0u8; 4];
    body[0..2].copy_from_slice(&4u16.to_le_bytes());
    h.append(&mut body);
    h
}

// ---------------------------------------------------------------------------
// CREATE
// ---------------------------------------------------------------------------

fn handle_create(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> Vec<u8> {
    if body.len() < 57 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    if session.tree_kind == TreeKind::Ipc {
        return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND);
    }

    // NameOffset and NameLength are at offsets 44 and 46 within the CREATE request body
    let name_offset = u16::from_le_bytes(body[44..46].try_into().unwrap_or_default()) as usize;
    let name_length = u16::from_le_bytes(body[46..48].try_into().unwrap_or_default()) as usize;

    let start = name_offset.saturating_sub(64 + 57); // relative to body start
    let end = start.saturating_add(name_length);
    let name = if end <= body.len() && start < end {
        decode_utf16le(&body[start..end])
    } else {
        String::new()
    };

    // Normalize: replace backslashes with forward slashes, prepend /
    let iso_path = normalize_windows_path(&name);
    log::debug!("smb: CREATE name={name:?} iso_path={iso_path:?}");

    // Check if this is a write-class create
    let desired_access = u32::from_le_bytes(body[28..32].try_into().unwrap_or_default());
    let write_mask = 0x0002 | 0x0004 | 0x0040 | 0x0080 | 0x0100; // WRITE_DATA | APPEND_DATA | etc
    if desired_access & write_mask != 0 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    let entry = resolve_iso_entry(&config.source_path, &iso_path);
    match entry {
        None => error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
        Some(e) => {
            let file_id_low = session.next_file_id;
            session.next_file_id += 1;
            let file_id_high = 0u64;
            let file_id: u128 = ((file_id_high as u128) << 64) | (file_id_low as u128);
            session.open_files.insert(file_id, e.clone());

            let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_CREATE);
            let mut resp = vec![0u8; 89];
            resp[0..2].copy_from_slice(&89u16.to_le_bytes()); // StructureSize
            resp[2] = 0; // OplockLevel: NONE
            resp[3] = 0; // Flags
            resp[4..8].copy_from_slice(&1u32.to_le_bytes()); // CreateAction: FILE_OPENED
                                                             // CreationTime, LastAccessTime, LastWriteTime, ChangeTime — all 0
                                                             // AllocationSize
            resp[40..48].copy_from_slice(&e.size.to_le_bytes());
            // EndOfFile
            resp[48..56].copy_from_slice(&e.size.to_le_bytes());
            // FileAttributes
            let attrs = if e.is_dir {
                FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
            } else {
                FILE_ATTRIBUTE_READONLY
            };
            resp[56..60].copy_from_slice(&attrs.to_le_bytes());
            // Reserved2 at 60..64 = 0
            // FileId (16 bytes at 64..80)
            resp[64..72].copy_from_slice(&file_id_low.to_le_bytes());
            resp[72..80].copy_from_slice(&file_id_high.to_le_bytes());
            // CreateContextsOffset and CreateContextsLength at 80..88 = 0
            h.append(&mut resp);
            h
        }
    }
}

// ---------------------------------------------------------------------------
// CLOSE
// ---------------------------------------------------------------------------

fn handle_close(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    if body.len() >= 24 {
        let file_id_low = u64::from_le_bytes(body[8..16].try_into().unwrap_or_default());
        let file_id_high = u64::from_le_bytes(body[16..24].try_into().unwrap_or_default());
        let file_id: u128 = ((file_id_high as u128) << 64) | (file_id_low as u128);
        session.open_files.remove(&file_id);
    }

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_CLOSE);
    let mut resp = vec![0u8; 60];
    resp[0..2].copy_from_slice(&60u16.to_le_bytes());
    h.append(&mut resp);
    h
}

// ---------------------------------------------------------------------------
// READ
// ---------------------------------------------------------------------------

fn handle_read(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> Vec<u8> {
    if body.len() < 49 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    if session.tree_kind == TreeKind::Ipc {
        return error_response(hdr, STATUS_FS_DRIVER_REQUIRED);
    }

    let read_length = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default()) as usize;
    let read_offset = u64::from_le_bytes(body[8..16].try_into().unwrap_or_default());
    let file_id_low = u64::from_le_bytes(body[16..24].try_into().unwrap_or_default());
    let file_id_high = u64::from_le_bytes(body[24..32].try_into().unwrap_or_default());
    let file_id: u128 = ((file_id_high as u128) << 64) | (file_id_low as u128);

    let entry = match session.open_files.get(&file_id) {
        Some(e) => e.clone(),
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };

    if entry.is_dir {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    if read_offset >= entry.size {
        return error_response(hdr, STATUS_END_OF_FILE);
    }

    let to_read = read_length.min((entry.size - read_offset) as usize);
    let data = match read_iso_range(&config.source_path, &entry.path, read_offset, to_read) {
        Ok(d) => d,
        Err(_) => return error_response(hdr, STATUS_ACCESS_DENIED),
    };

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_READ);
    let mut resp = vec![0u8; 16];
    resp[0..2].copy_from_slice(&17u16.to_le_bytes()); // StructureSize = 17
    resp[2] = 0x50; // DataOffset = 64 (header) + 16 (fixed body) = 80... actually 64+17-1=80
                    // DataLength
    resp[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    h.append(&mut resp);
    h.push(0); // Padding byte (StructureSize=17 means 16 bytes + 1 variable)
    h.extend_from_slice(&data);
    h
}

fn handle_echo(hdr: &Smb2Header) -> Vec<u8> {
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_ECHO);
    let mut body = vec![0u8; 4];
    body[0..2].copy_from_slice(&4u16.to_le_bytes());
    h.append(&mut body);
    h
}

// ---------------------------------------------------------------------------
// QUERY_INFO
// ---------------------------------------------------------------------------

fn handle_query_info(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    if body.len() < 40 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    let info_type = body[2];
    let file_info_class = body[3];
    let additional_info = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default());
    let flags = u32::from_le_bytes(body[8..12].try_into().unwrap_or_default());

    let file_id_low = u64::from_le_bytes(body[24..32].try_into().unwrap_or_default());
    let file_id_high = u64::from_le_bytes(body[32..40].try_into().unwrap_or_default());
    let file_id: u128 = ((file_id_high as u128) << 64) | (file_id_low as u128);

    let entry = match session.open_files.get(&file_id) {
        Some(e) => e.clone(),
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };

    log::debug!(
        "smb: QUERY_INFO info_type={} file_info_class={} additional_info=0x{:08x} flags=0x{:08x} path={:?}",
        info_type,
        file_info_class,
        additional_info,
        flags,
        entry.path
    );

    let info_data = match info_type {
        1 => build_file_info(file_info_class, &entry),
        2 => build_fs_info(file_info_class, session.tree_kind),
        3 => None,
        _ => None,
    };
    match info_data {
        None => error_response(hdr, STATUS_NOT_SUPPORTED),
        Some(data) => {
            let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_QUERY_INFO);
            let mut resp = vec![0u8; 8];
            resp[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
            resp[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes()); // OutputBufferLength
                                                                            // OutputBufferOffset = 64 + 8 = 72
            resp[2..4].copy_from_slice(&72u16.to_le_bytes());
            h.append(&mut resp);
            h.extend_from_slice(&data);
            h
        }
    }
}

fn build_fs_info(class: u8, tree_kind: TreeKind) -> Option<Vec<u8>> {
    let (device_type, fs_name) = match tree_kind {
        TreeKind::Data => (FILE_DEVICE_DISK, "PXEASY"),
        TreeKind::Ipc => (FILE_DEVICE_NAMED_PIPE, "IPC"),
    };

    match class {
        FILE_FS_SIZE_INFORMATION => {
            let total_units = 1024u64 * 1024;
            let available_units = total_units / 2;
            let sectors_per_unit = 8u32;
            let bytes_per_sector = 512u32;
            let mut d = vec![0u8; 24];
            d[0..8].copy_from_slice(&total_units.to_le_bytes());
            d[8..16].copy_from_slice(&available_units.to_le_bytes());
            d[16..20].copy_from_slice(&sectors_per_unit.to_le_bytes());
            d[20..24].copy_from_slice(&bytes_per_sector.to_le_bytes());
            Some(d)
        }
        FILE_FS_DEVICE_INFORMATION => {
            let mut d = vec![0u8; 8];
            d[0..4].copy_from_slice(&device_type.to_le_bytes());
            d[4..8].copy_from_slice(&0u32.to_le_bytes());
            Some(d)
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let name_utf16: Vec<u16> = fs_name.encode_utf16().collect();
            let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
            let mut d = vec![0u8; 12 + name_bytes.len()];
            d[0..4].copy_from_slice(&0x0000_0003u32.to_le_bytes());
            d[4..8].copy_from_slice(&255u32.to_le_bytes());
            d[8..12].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            d[12..].copy_from_slice(&name_bytes);
            Some(d)
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            let total_units = 1024u64 * 1024;
            let available_units = total_units / 2;
            let mut d = vec![0u8; 32];
            d[0..8].copy_from_slice(&available_units.to_le_bytes());
            d[8..16].copy_from_slice(&total_units.to_le_bytes());
            d[16..24].copy_from_slice(&available_units.to_le_bytes());
            d[24..28].copy_from_slice(&8u32.to_le_bytes());
            d[28..32].copy_from_slice(&512u32.to_le_bytes());
            Some(d)
        }
        FILE_FS_SECTOR_SIZE_INFORMATION => {
            let mut d = vec![0u8; 28];
            d[0..4].copy_from_slice(&512u32.to_le_bytes());
            d[4..8].copy_from_slice(&512u32.to_le_bytes());
            d[8..12].copy_from_slice(&512u32.to_le_bytes());
            d[12..16].copy_from_slice(&512u32.to_le_bytes());
            d[16..20].copy_from_slice(&0u32.to_le_bytes());
            d[20..24].copy_from_slice(&0u32.to_le_bytes());
            d[24..28].copy_from_slice(&0u32.to_le_bytes());
            Some(d)
        }
        _ => None,
    }
}

fn build_file_info(class: u8, entry: &IsoEntry) -> Option<Vec<u8>> {
    let attrs = if entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
    } else {
        FILE_ATTRIBUTE_READONLY
    };

    match class {
        4 => {
            // FileBasicInformation (40 bytes)
            let mut d = vec![0u8; 40];
            // CreationTime, LastAccessTime, LastWriteTime, ChangeTime — all 0
            d[32..36].copy_from_slice(&attrs.to_le_bytes()); // FileAttributes
            Some(d)
        }
        5 => {
            // FileStandardInformation (24 bytes)
            let mut d = vec![0u8; 24];
            d[0..8].copy_from_slice(&entry.size.to_le_bytes()); // AllocationSize
            d[8..16].copy_from_slice(&entry.size.to_le_bytes()); // EndOfFile
            d[16..20].copy_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
            d[20] = 0; // DeletePending
            d[21] = if entry.is_dir { 1 } else { 0 }; // Directory
            Some(d)
        }
        7 => {
            // FileEaInformation (4 bytes)
            let d = vec![0u8; 4];
            Some(d)
        }
        14 => {
            // FilePositionInformation (8 bytes)
            let d = vec![0u8; 8];
            Some(d)
        }
        16 => {
            // FileModeInformation (4 bytes)
            let d = vec![0u8; 4];
            Some(d)
        }
        18 => {
            // FileInternalInformation (8 bytes)
            let d = vec![0u8; 8];
            Some(d)
        }
        20 => {
            // FileEndOfFileInformation (8 bytes)
            let mut d = vec![0u8; 8];
            d[0..8].copy_from_slice(&entry.size.to_le_bytes());
            Some(d)
        }
        21 => {
            // FileAlignmentInformation (4 bytes)
            let d = vec![0u8; 4];
            Some(d)
        }
        22 => {
            // FileAccessInformation (4 bytes)
            let mut d = vec![0u8; 4];
            d[0..4].copy_from_slice(&0x0012_0089u32.to_le_bytes()); // READ access
            Some(d)
        }
        34 => {
            // FileNetworkOpenInformation (56 bytes)
            let mut d = vec![0u8; 56];
            d[32..40].copy_from_slice(&entry.size.to_le_bytes()); // AllocationSize
            d[40..48].copy_from_slice(&entry.size.to_le_bytes()); // EndOfFile
            d[48..52].copy_from_slice(&attrs.to_le_bytes()); // FileAttributes
            Some(d)
        }
        35 => {
            // FileAttributeTagInformation (8 bytes)
            let mut d = vec![0u8; 8];
            d[0..4].copy_from_slice(&attrs.to_le_bytes());
            Some(d)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// QUERY_DIRECTORY
// ---------------------------------------------------------------------------

fn handle_query_directory(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
) -> Vec<u8> {
    if body.len() < 32 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    if session.tree_kind == TreeKind::Ipc {
        return error_response(hdr, STATUS_NO_MORE_FILES);
    }

    let flags = body[2];
    let file_id_low = u64::from_le_bytes(body[8..16].try_into().unwrap_or_default());
    let file_id_high = u64::from_le_bytes(body[16..24].try_into().unwrap_or_default());
    let file_id: u128 = ((file_id_high as u128) << 64) | (file_id_low as u128);

    // RESTART_SCANS flag = 0x01
    let restart = flags & 0x01 != 0;

    let entry = match session.open_files.get_mut(&file_id) {
        Some(e) => e,
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };

    if !entry.is_dir {
        return error_response(hdr, STATUS_NOT_SUPPORTED);
    }

    if restart {
        entry.enum_pos = 0;
    }

    // Lazily populate children
    if entry.children.is_none() {
        let children = list_iso_dir(&config.source_path, &entry.path);
        entry.children = Some(children);
    }

    let children = entry.children.clone().unwrap_or_default();
    let pos = entry.enum_pos;

    if pos >= children.len() {
        return error_response(hdr, STATUS_NO_MORE_FILES);
    }

    // Return one entry at a time to keep implementation simple
    let child_name = &children[pos];
    let child_path = if entry.path == "/" {
        format!("/{child_name}")
    } else {
        format!("{}/{child_name}", entry.path.trim_end_matches('/'))
    };

    let child_entry = resolve_iso_entry(&config.source_path, &child_path).unwrap_or(IsoEntry {
        path: child_path,
        is_dir: false,
        size: 0,
        children: None,
        enum_pos: 0,
    });

    entry.enum_pos += 1;

    // Build FileIdBothDirectoryInformation (FILE_INFO_CLASS 37) — but we use FileDirectoryInfo (1)
    // Using FileDirectoryInformation (class 1) which is 64 bytes fixed + variable name
    let name_utf16: Vec<u16> = child_name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let record_len = 64 + name_bytes.len();
    let mut record = vec![0u8; record_len];
    // NextEntryOffset = 0 (last/only entry)
    // FileIndex = 0
    record[4..8].copy_from_slice(&0u32.to_le_bytes());
    // CreationTime, LastAccessTime, LastWriteTime, ChangeTime — offsets 8..40, all 0
    // EndOfFile at 40
    record[40..48].copy_from_slice(&child_entry.size.to_le_bytes());
    // AllocationSize at 48
    record[48..56].copy_from_slice(&child_entry.size.to_le_bytes());
    // FileAttributes at 56
    let attrs = if child_entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
    } else {
        FILE_ATTRIBUTE_READONLY
    };
    record[56..60].copy_from_slice(&attrs.to_le_bytes());
    // FileNameLength at 60
    record[60..64].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    // FileName at 64
    record[64..].copy_from_slice(&name_bytes);

    let output_len = record.len() as u32;
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_QUERY_DIRECTORY);
    let mut resp = vec![0u8; 8];
    resp[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
    let out_offset = 64u16 + 8u16; // header + fixed body
    resp[2..4].copy_from_slice(&out_offset.to_le_bytes()); // OutputBufferOffset
    resp[4..8].copy_from_slice(&output_len.to_le_bytes()); // OutputBufferLength
    h.append(&mut resp);
    h.push(0); // padding (StructureSize = 9 means 8 bytes fixed + 1 variable)
    h.extend_from_slice(&record);
    h
}

// ---------------------------------------------------------------------------
// IOCTL
// ---------------------------------------------------------------------------

fn handle_ioctl(hdr: &Smb2Header, body: &[u8]) -> Vec<u8> {
    if body.len() < 56 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    let ctl_code = u32::from_le_bytes(body[4..8].try_into().unwrap_or_default());
    log::debug!("smb: IOCTL ctl=0x{ctl_code:08x}");

    if ctl_code != FSCTL_VALIDATE_NEGOTIATE_INFO {
        return error_response(hdr, STATUS_NOT_SUPPORTED);
    }

    let mut data = vec![0u8; 24];
    data[0..4].copy_from_slice(&0u32.to_le_bytes());
    data[4..20].copy_from_slice(&SERVER_GUID);
    data[20..22].copy_from_slice(&1u16.to_le_bytes());
    data[22..24].copy_from_slice(&SMB2_DIALECT_021.to_le_bytes());

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_IOCTL);
    let mut resp = vec![0u8; 48];
    resp[0..2].copy_from_slice(&49u16.to_le_bytes());
    resp[4..8].copy_from_slice(&ctl_code.to_le_bytes());
    let output_offset = 64u32 + 48u32;
    resp[36..40].copy_from_slice(&output_offset.to_le_bytes());
    resp[40..44].copy_from_slice(&(data.len() as u32).to_le_bytes());
    h.append(&mut resp);
    h.push(0);
    h.extend_from_slice(&data);
    h
}

// ---------------------------------------------------------------------------
// Error response helper
// ---------------------------------------------------------------------------

fn error_response(hdr: &Smb2Header, status: u32) -> Vec<u8> {
    let mut h = hdr.build_response(status, hdr.command);
    // Error response body: StructureSize=9, ErrorContextCount=0, Reserved=0, ByteCount=0
    let mut body = vec![0u8; 8];
    body[0..2].copy_from_slice(&9u16.to_le_bytes());
    h.append(&mut body);
    h.push(0); // ErrorData padding
    h
}

// ---------------------------------------------------------------------------
// ISO helpers
// ---------------------------------------------------------------------------

fn resolve_iso_entry(source_path: &std::path::Path, iso_path: &str) -> Option<IsoEntry> {
    let normalized = if iso_path.is_empty() || iso_path == "/" {
        "/".to_string()
    } else {
        let p = iso_path.trim_start_matches('/').trim_end_matches('/');
        format!("/{p}")
    };

    // Check if it's a file
    if let Ok(data) = pxe_profiles::load_file(source_path, &normalized) {
        return Some(IsoEntry {
            path: normalized,
            is_dir: false,
            size: data.len() as u64,
            children: None,
            enum_pos: 0,
        });
    }

    // Check if it's a directory by listing files with that prefix
    let prefix = if normalized == "/" {
        "/".to_string()
    } else {
        format!("{}/", normalized.trim_end_matches('/'))
    };
    match pxe_profiles::list_files(source_path, &prefix) {
        Ok(files) if !files.is_empty() || normalized == "/" => Some(IsoEntry {
            path: normalized,
            is_dir: true,
            size: 0,
            children: None,
            enum_pos: 0,
        }),
        _ => None,
    }
}

fn list_iso_dir(source_path: &std::path::Path, dir_path: &str) -> Vec<String> {
    let prefix = if dir_path == "/" {
        "/".to_string()
    } else {
        format!("{}/", dir_path.trim_end_matches('/'))
    };

    let files = pxe_profiles::list_files(source_path, &prefix).unwrap_or_default();

    // Extract immediate children only
    let mut children: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for file_path in &files {
        let relative = file_path.strip_prefix(&prefix).unwrap_or(file_path);
        let immediate = relative.split('/').next().unwrap_or("");
        if !immediate.is_empty() && seen.insert(immediate.to_string()) {
            children.push(immediate.to_string());
        }
    }

    children.sort();
    children
}

fn read_iso_range(
    source_path: &std::path::Path,
    iso_path: &str,
    offset: u64,
    length: usize,
) -> io::Result<Vec<u8>> {
    let data = pxe_profiles::load_file(source_path, iso_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;

    let start = offset as usize;
    if start >= data.len() {
        return Ok(Vec::new());
    }
    let end = (start + length).min(data.len());
    Ok(data[start..end].to_vec())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn normalize_windows_path(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words).to_owned()
}

fn command_name(command: u16) -> &'static str {
    match command {
        SMB2_NEGOTIATE => "NEGOTIATE",
        SMB2_SESSION_SETUP => "SESSION_SETUP",
        SMB2_LOGOFF => "LOGOFF",
        SMB2_TREE_CONNECT => "TREE_CONNECT",
        SMB2_TREE_DISCONNECT => "TREE_DISCONNECT",
        SMB2_CREATE => "CREATE",
        SMB2_CLOSE => "CLOSE",
        SMB2_READ => "READ",
        SMB2_WRITE => "WRITE",
        SMB2_IOCTL => "IOCTL",
        SMB2_QUERY_DIRECTORY => "QUERY_DIRECTORY",
        SMB2_ECHO => "ECHO",
        SMB2_QUERY_INFO => "QUERY_INFO",
        SMB2_CHANGE_NOTIFY => "CHANGE_NOTIFY",
        SMB2_SET_INFO => "SET_INFO",
        SMB2_OPLOCK_BREAK => "OPLOCK_BREAK",
        SMB2_LOCK => "LOCK",
        SMB2_FLUSH => "FLUSH",
        SMB2_CANCEL => "CANCEL",
        _ => "UNKNOWN",
    }
}

fn status_name(status: u32) -> &'static str {
    match status {
        STATUS_SUCCESS => "STATUS_SUCCESS",
        STATUS_ACCESS_DENIED => "STATUS_ACCESS_DENIED",
        STATUS_BAD_NETWORK_NAME => "STATUS_BAD_NETWORK_NAME",
        STATUS_OBJECT_NAME_NOT_FOUND => "STATUS_OBJECT_NAME_NOT_FOUND",
        STATUS_NOT_SUPPORTED => "STATUS_NOT_SUPPORTED",
        STATUS_MORE_PROCESSING_REQUIRED => "STATUS_MORE_PROCESSING_REQUIRED",
        STATUS_END_OF_FILE => "STATUS_END_OF_FILE",
        STATUS_NO_MORE_FILES => "STATUS_NO_MORE_FILES",
        STATUS_FS_DRIVER_REQUIRED => "STATUS_FS_DRIVER_REQUIRED",
        _ => "STATUS_OTHER",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_negotiate_request() -> Vec<u8> {
        // Minimal SMB2 NEGOTIATE request
        let mut buf = vec![0u8; 64 + 36];
        // Header
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        buf[12..14].copy_from_slice(&SMB2_NEGOTIATE.to_le_bytes());
        buf[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest
        buf[28..36].copy_from_slice(&0u64.to_le_bytes()); // MessageId
                                                          // Body: StructureSize=36, DialectCount=2
        buf[64..66].copy_from_slice(&36u16.to_le_bytes());
        buf[66..68].copy_from_slice(&2u16.to_le_bytes()); // DialectCount
                                                          // Dialects
        buf[72..74].copy_from_slice(&SMB2_DIALECT_0202.to_le_bytes());
        buf[74..76].copy_from_slice(&SMB2_DIALECT_021.to_le_bytes());
        buf
    }

    fn parse_response_status(resp: &[u8]) -> u32 {
        if resp.len() < 12 {
            return 0xFFFF_FFFF;
        }
        u32::from_le_bytes(resp[8..12].try_into().unwrap())
    }

    fn parse_response_command(resp: &[u8]) -> u16 {
        if resp.len() < 14 {
            return 0xFFFF;
        }
        u16::from_le_bytes(resp[12..14].try_into().unwrap())
    }

    fn test_config() -> SmbConfig {
        SmbConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 445,
            share_name: "windows".to_string(),
            source_path: PathBuf::from("/nonexistent"),
        }
    }

    fn make_session_setup_request(session_id: u64, security_blob: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 64 + 24 + security_blob.len()];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_SESSION_SETUP.to_le_bytes());
        buf[24..32].copy_from_slice(&1u64.to_le_bytes());
        buf[40..48].copy_from_slice(&session_id.to_le_bytes());
        buf[64..66].copy_from_slice(&25u16.to_le_bytes());
        if !security_blob.is_empty() {
            buf[76..78].copy_from_slice(&(64u16 + 24u16).to_le_bytes());
            buf[78..80].copy_from_slice(&(security_blob.len() as u16).to_le_bytes());
            buf[88..88 + security_blob.len()].copy_from_slice(security_blob);
        }
        buf
    }

    fn ntlmssp_negotiate_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 40];
        blob[0..8].copy_from_slice(b"NTLMSSP\0");
        blob[8..12].copy_from_slice(&1u32.to_le_bytes());
        blob[12..16].copy_from_slice(&0x0008_8201u32.to_le_bytes());
        blob
    }

    fn ntlmssp_authenticate_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 64];
        blob[0..8].copy_from_slice(b"NTLMSSP\0");
        blob[8..12].copy_from_slice(&3u32.to_le_bytes());
        blob
    }

    #[test]
    fn smb2_header_field_offsets_are_correct() {
        let hdr = Smb2Header {
            command: SMB2_NEGOTIATE,
            flags: 0,
            message_id: 0x0102_0304_0506_0708,
            tree_id: 0x1122_3344,
            session_id: 0x8877_6655_4433_2211,
        };
        let resp = hdr.build_response(STATUS_SUCCESS, SMB2_NEGOTIATE);
        assert_eq!(
            u64::from_le_bytes(resp[24..32].try_into().unwrap()),
            hdr.message_id
        );
        assert_eq!(
            u32::from_le_bytes(resp[36..40].try_into().unwrap()),
            hdr.tree_id
        );
        assert_eq!(
            u64::from_le_bytes(resp[40..48].try_into().unwrap()),
            hdr.session_id
        );
        let parsed = Smb2Header::parse(&resp).unwrap();
        assert_eq!(parsed.message_id, hdr.message_id);
        assert_eq!(parsed.tree_id, hdr.tree_id);
        assert_eq!(parsed.session_id, hdr.session_id);
    }

    #[test]
    fn negotiate_returns_smb2_dialect() {
        let req_buf = make_negotiate_request();
        let hdr = Smb2Header::parse(&req_buf).unwrap();
        let body = &req_buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(parse_response_command(&resp), SMB2_NEGOTIATE);
        // Check dialect in response body
        let dialect = u16::from_le_bytes(resp[68..70].try_into().unwrap());
        assert_eq!(dialect, SMB2_DIALECT_021);
    }

    #[test]
    fn smb1_upgrade_returns_smb2_wildcard_negotiate() {
        let resp = build_smb1_to_smb2_response();
        assert_eq!(&resp[0..4], SMB2_MAGIC);
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(parse_response_command(&resp), SMB2_NEGOTIATE);
        let dialect = u16::from_le_bytes(resp[68..70].try_into().unwrap());
        assert_eq!(dialect, SMB2_DIALECT_WILDCARD);
    }

    #[test]
    fn session_setup_accepts_any_credentials() {
        let buf = make_session_setup_request(0, &[]);

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(session.session_id, 1);
    }

    #[test]
    fn session_setup_ntlm_negotiate_returns_challenge() {
        let negotiate = ntlmssp_negotiate_blob();
        let buf = make_session_setup_request(0, &negotiate);

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(
            parse_response_status(&resp),
            STATUS_MORE_PROCESSING_REQUIRED
        );
        assert_eq!(parse_response_command(&resp), SMB2_SESSION_SETUP);
        assert_eq!(u64::from_le_bytes(resp[40..48].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(resp[68..70].try_into().unwrap()), 72);
        assert!(resp[72..].starts_with(b"NTLMSSP\0"));
        assert_eq!(session.auth_state, AuthState::ChallengeSent);
    }

    #[test]
    fn session_setup_ntlm_authenticate_returns_success() {
        let auth = ntlmssp_authenticate_blob();
        let buf = make_session_setup_request(1, &auth);

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session {
            session_id: 1,
            auth_state: AuthState::ChallengeSent,
            ..Session::default()
        };
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(parse_response_command(&resp), SMB2_SESSION_SETUP);
        assert_eq!(session.auth_state, AuthState::Authenticated);
    }

    #[test]
    fn tree_connect_wrong_share_returns_bad_network_name() {
        let share_utf16: Vec<u16> = "\\\\server\\wrongshare".encode_utf16().collect();
        let share_bytes: Vec<u8> = share_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let path_offset = 64u16 + 8u16; // after header + 8 bytes of fixed body
        let path_length = share_bytes.len() as u16;

        let mut buf = vec![0u8; 64 + 8 + share_bytes.len()];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_TREE_CONNECT.to_le_bytes());
        buf[64..66].copy_from_slice(&9u16.to_le_bytes()); // StructureSize
        buf[68..70].copy_from_slice(&path_offset.to_le_bytes());
        buf[70..72].copy_from_slice(&path_length.to_le_bytes());
        buf[72..72 + share_bytes.len()].copy_from_slice(&share_bytes);

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_BAD_NETWORK_NAME);
    }

    #[test]
    fn write_command_returns_access_denied() {
        let mut buf = vec![0u8; 64 + 49];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_WRITE.to_le_bytes());

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_ACCESS_DENIED);
    }

    #[test]
    fn tree_connect_accepts_ipc_share() {
        let share_utf16: Vec<u16> = "\\\\server\\IPC$".encode_utf16().collect();
        let share_bytes: Vec<u8> = share_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let path_offset = 64u16 + 8u16;
        let path_length = share_bytes.len() as u16;

        let mut buf = vec![0u8; 64 + 8 + share_bytes.len()];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_TREE_CONNECT.to_le_bytes());
        buf[64..66].copy_from_slice(&9u16.to_le_bytes());
        buf[68..70].copy_from_slice(&path_offset.to_le_bytes());
        buf[70..72].copy_from_slice(&path_length.to_le_bytes());
        buf[72..72 + share_bytes.len()].copy_from_slice(&share_bytes);

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(session.tree_kind, TreeKind::Ipc);
    }

    #[test]
    fn echo_returns_success() {
        let mut buf = vec![0u8; 64 + 4];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_ECHO.to_le_bytes());
        buf[64..66].copy_from_slice(&4u16.to_le_bytes());

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(parse_response_command(&resp), SMB2_ECHO);
    }

    #[test]
    fn validate_negotiate_ioctl_returns_success() {
        let mut buf = vec![0u8; 64 + 56];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_IOCTL.to_le_bytes());
        buf[64..66].copy_from_slice(&57u16.to_le_bytes());
        buf[68..72].copy_from_slice(&FSCTL_VALIDATE_NEGOTIATE_INFO.to_le_bytes());

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = test_config();
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(parse_response_command(&resp), SMB2_IOCTL);
    }
}
