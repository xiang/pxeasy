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
    time::Duration,
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
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

// Dialect revisions
#[cfg(test)]
const SMB2_DIALECT_0202: u16 = 0x0202;
const SMB2_DIALECT_021: u16 = 0x0210;

// File attribute flags
const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;

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
            message_id: u64::from_le_bytes(buf[28..36].try_into().ok()?),
            tree_id: u32::from_le_bytes(buf[40..44].try_into().ok()?),
            session_id: u64::from_le_bytes(buf[44..52].try_into().ok()?),
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
        h[28..36].copy_from_slice(&self.message_id.to_le_bytes());
        // TreeId
        h[40..44].copy_from_slice(&self.tree_id.to_le_bytes());
        // SessionId
        h[44..52].copy_from_slice(&self.session_id.to_le_bytes());
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
    tree_connected: bool,
    tree_id: u32,
    // file_id → IsoEntry
    open_files: HashMap<u128, IsoEntry>,
    next_file_id: u64,
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

    loop {
        let frame = read_nbss_frame(&mut stream)?;
        if frame.is_empty() {
            return Ok(());
        }

        // SMB1 NEGOTIATE — respond with SMB2 negotiate
        if frame.len() >= 4 && &frame[0..4] == SMB1_MAGIC {
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
        let response = dispatch(&hdr, body, &mut session, config)?;
        if let Some(resp) = response {
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
        SMB2_NEGOTIATE => Ok(Some(handle_negotiate(hdr))),
        SMB2_SESSION_SETUP => Ok(Some(handle_session_setup(hdr, session))),
        SMB2_LOGOFF => Ok(Some(handle_logoff(hdr))),
        SMB2_TREE_CONNECT => Ok(Some(handle_tree_connect(hdr, body, session, config))),
        SMB2_TREE_DISCONNECT => Ok(Some(handle_tree_disconnect(hdr, session))),
        SMB2_CREATE => Ok(Some(handle_create(hdr, body, session, config))),
        SMB2_CLOSE => Ok(Some(handle_close(hdr, body, session))),
        SMB2_READ => Ok(Some(handle_read(hdr, body, session, config))),
        SMB2_QUERY_INFO => Ok(Some(handle_query_info(hdr, body, session))),
        SMB2_QUERY_DIRECTORY => Ok(Some(handle_query_directory(hdr, body, session, config))),
        SMB2_IOCTL => Ok(Some(handle_ioctl(hdr))),
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
    // SMB1 NEGOTIATE response pointing client to SMB2
    // Structure: NBSS header + SMB header + dialect selection
    // We respond with a minimal SMB1 error that forces SMB2 negotiation:
    // In practice, modern clients send an SMB2 NEGOTIATE immediately after.
    // Return a minimal valid SMB1 error response.
    let mut resp = Vec::new();
    // SMB header
    resp.extend_from_slice(b"\xffSMB");
    resp.push(0x72); // Command: NEGOTIATE
    resp.extend_from_slice(&0x0000_0000u32.to_le_bytes()); // Status: SUCCESS
    resp.push(0x88); // Flags
    resp.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags2
    resp.extend_from_slice(&[0u8; 12]); // PidHigh, Security, Tid, Pid, Uid, Mid
                                        // Parameters
    resp.push(0x01); // WordCount
    resp.extend_from_slice(&0xffffu16.to_le_bytes()); // DialectIndex: SMB2
                                                      // Data
    resp.extend_from_slice(&0x0000u16.to_le_bytes()); // ByteCount
    resp
}

// ---------------------------------------------------------------------------
// NEGOTIATE
// ---------------------------------------------------------------------------

fn handle_negotiate(hdr: &Smb2Header) -> Vec<u8> {
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_NEGOTIATE);
    // Negotiate response body (65 bytes minimum)
    let mut body = vec![0u8; 65];
    // StructureSize = 65
    body[0..2].copy_from_slice(&65u16.to_le_bytes());
    // SecurityMode = SIGNING_ENABLED (bit 0)
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    // DialectRevision
    body[4..6].copy_from_slice(&SMB2_DIALECT_021.to_le_bytes());
    // NegotiateContextCount = 0
    // ServerGuid (16 bytes at offset 8) — all zeros
    // Capabilities = 0
    // MaxTransactSize
    body[24..28].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    // MaxReadSize
    body[28..32].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    // MaxWriteSize
    body[32..36].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
    // SystemTime (8 bytes at 36) — 0
    // ServerStartTime (8 bytes at 44) — 0
    // SecurityBufferOffset = 128 (= 64 header + 64 body offset)
    body[52..54].copy_from_slice(&128u16.to_le_bytes());
    // SecurityBufferLength = 0
    // NegotiateContextOffset = 0

    h.append(&mut body);
    h
}

// ---------------------------------------------------------------------------
// SESSION_SETUP
// ---------------------------------------------------------------------------

fn handle_session_setup(hdr: &Smb2Header, session: &mut Session) -> Vec<u8> {
    // Accept any credentials — assign session_id 1
    session.session_id = 1;
    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_SESSION_SETUP);
    // Patch session_id in response header
    h[44..52].copy_from_slice(&1u64.to_le_bytes());

    let mut body = vec![0u8; 9];
    // StructureSize = 9
    body[0..2].copy_from_slice(&9u16.to_le_bytes());
    // SessionFlags = 0 (GUEST not set)
    // SecurityBufferOffset = 64+9 = 73 — but length 0
    body[4..6].copy_from_slice(&73u16.to_le_bytes());
    // SecurityBufferLength = 0

    h.append(&mut body);
    h
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
    let expected = format!("\\{}", config.share_name);
    let accepted = share_name
        .split_once('\\')
        .map(|(_, rest)| format!("\\{}", rest.rsplit('\\').next().unwrap_or("")))
        .as_deref()
        == Some(expected.as_str())
        || share_name
            .to_ascii_lowercase()
            .ends_with(&format!("\\{}", config.share_name.to_ascii_lowercase()));

    if !accepted {
        log::debug!("smb: TREE_CONNECT rejected share: {:?}", share_name);
        return error_response(hdr, STATUS_BAD_NETWORK_NAME);
    }

    session.tree_connected = true;
    session.tree_id = 1;

    let mut h = hdr.build_response(STATUS_SUCCESS, SMB2_TREE_CONNECT);
    // Patch tree_id in response header
    h[40..44].copy_from_slice(&1u32.to_le_bytes());

    let mut resp_body = vec![0u8; 16];
    resp_body[0..2].copy_from_slice(&16u16.to_le_bytes()); // StructureSize
    resp_body[2] = 0x01; // ShareType: DISK
                         // ShareFlags, Capabilities, MaximalAccess — all 0 means read
    resp_body[12..16].copy_from_slice(&0x001F_01FFu32.to_le_bytes()); // MaximalAccess: full for read

    h.append(&mut resp_body);
    h
}

// ---------------------------------------------------------------------------
// TREE_DISCONNECT
// ---------------------------------------------------------------------------

fn handle_tree_disconnect(hdr: &Smb2Header, session: &mut Session) -> Vec<u8> {
    session.tree_connected = false;
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

// ---------------------------------------------------------------------------
// QUERY_INFO
// ---------------------------------------------------------------------------

fn handle_query_info(hdr: &Smb2Header, body: &[u8], session: &mut Session) -> Vec<u8> {
    if body.len() < 40 {
        return error_response(hdr, STATUS_ACCESS_DENIED);
    }

    let info_type = body[2];
    let file_info_class = body[3];

    let file_id_low = u64::from_le_bytes(body[24..32].try_into().unwrap_or_default());
    let file_id_high = u64::from_le_bytes(body[32..40].try_into().unwrap_or_default());
    let file_id: u128 = ((file_id_high as u128) << 64) | (file_id_low as u128);

    let entry = match session.open_files.get(&file_id) {
        Some(e) => e.clone(),
        None => return error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND),
    };

    // info_type 1 = FILE, 2 = FS, 3 = SECURITY
    if info_type != 1 {
        return error_response(hdr, STATUS_NOT_SUPPORTED);
    }

    // Build file information response based on file_info_class
    let info_data = build_file_info(file_info_class, &entry);
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
        18 => {
            // FileInternalInformation (8 bytes)
            let d = vec![0u8; 8];
            Some(d)
        }
        22 => {
            // FileAccessInformation (4 bytes)
            let mut d = vec![0u8; 4];
            d[0..4].copy_from_slice(&0x0012_0089u32.to_le_bytes()); // READ access
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

fn handle_ioctl(hdr: &Smb2Header) -> Vec<u8> {
    error_response(hdr, STATUS_NOT_SUPPORTED)
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

    #[test]
    fn negotiate_returns_smb2_dialect() {
        let req_buf = make_negotiate_request();
        let hdr = Smb2Header::parse(&req_buf).unwrap();
        let body = &req_buf[64..];
        let mut session = Session::default();
        let config = SmbConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 445,
            share_name: "windows".to_string(),
            source_path: PathBuf::from("/nonexistent"),
        };
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
    fn session_setup_accepts_any_credentials() {
        let mut buf = vec![0u8; 64 + 24];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[12..14].copy_from_slice(&SMB2_SESSION_SETUP.to_le_bytes());
        // Body: StructureSize=25
        buf[64..66].copy_from_slice(&25u16.to_le_bytes());

        let hdr = Smb2Header::parse(&buf).unwrap();
        let body = &buf[64..];
        let mut session = Session::default();
        let config = SmbConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 445,
            share_name: "windows".to_string(),
            source_path: PathBuf::from("/nonexistent"),
        };
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_SUCCESS);
        assert_eq!(session.session_id, 1);
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
        let config = SmbConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 445,
            share_name: "windows".to_string(),
            source_path: PathBuf::from("/nonexistent"),
        };
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
        let config = SmbConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 445,
            share_name: "windows".to_string(),
            source_path: PathBuf::from("/nonexistent"),
        };
        let resp = dispatch(&hdr, body, &mut session, &config)
            .unwrap()
            .unwrap();
        assert_eq!(parse_response_status(&resp), STATUS_ACCESS_DENIED);
    }
}
