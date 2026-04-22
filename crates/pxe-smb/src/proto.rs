#![allow(dead_code)]

use crate::constants::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

pub fn sign_message(key: &[u8], message: &mut [u8]) {
    if message.len() < 64 {
        return;
    }
    // Zero out the signature field
    message[48..64].copy_from_slice(&[0u8; 16]);

    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return;
    };
    mac.update(message);
    let result = mac.finalize();
    let code = result.into_bytes();
    message[48..64].copy_from_slice(&code[0..16]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status(pub u32);

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self.0 {
            STATUS_SUCCESS => "SUCCESS",
            STATUS_MORE_PROCESSING_REQUIRED => "MORE_PROCESSING_REQUIRED",
            STATUS_INVALID_PARAMETER => "INVALID_PARAMETER",
            STATUS_OBJECT_NAME_NOT_FOUND => "OBJECT_NAME_NOT_FOUND",
            STATUS_ACCESS_DENIED => "ACCESS_DENIED",
            STATUS_NOT_SUPPORTED => "NOT_SUPPORTED",
            STATUS_BAD_NETWORK_NAME => "BAD_NETWORK_NAME",
            STATUS_END_OF_FILE => "END_OF_FILE",
            STATUS_NO_MORE_FILES => "NO_MORE_FILES",
            STATUS_BUFFER_OVERFLOW => "BUFFER_OVERFLOW",
            STATUS_BUFFER_TOO_SMALL => "BUFFER_TOO_SMALL",
            STATUS_LOGON_FAILURE => "LOGON_FAILURE",
            STATUS_FS_DRIVER_REQUIRED => "FS_DRIVER_REQUIRED",
            _ => "OTHER_ERROR",
        }
    }

    pub fn is_success(&self) -> bool {
        self.0 == STATUS_SUCCESS
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:08x})", self.as_str(), self.0)
    }
}

impl fmt::LowerHex for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Command(pub u16);

impl Command {
    pub fn as_str(&self) -> &'static str {
        match self.0 {
            SMB2_NEGOTIATE => "NEGOTIATE",
            SMB2_SESSION_SETUP => "SESSION_SETUP",
            SMB2_LOGOFF => "LOGOFF",
            SMB2_TREE_CONNECT => "TREE_CONNECT",
            SMB2_TREE_DISCONNECT => "TREE_DISCONNECT",
            SMB2_CREATE => "CREATE",
            SMB2_CLOSE => "CLOSE",
            SMB2_FLUSH => "FLUSH",
            SMB2_READ => "READ",
            SMB2_WRITE => "WRITE",
            SMB2_LOCK => "LOCK",
            SMB2_IOCTL => "IOCTL",
            SMB2_CANCEL => "CANCEL",
            SMB2_ECHO => "ECHO",
            SMB2_QUERY_DIRECTORY => "QUERY_DIRECTORY",
            SMB2_CHANGE_NOTIFY => "CHANGE_NOTIFY",
            SMB2_QUERY_INFO => "QUERY_INFO",
            SMB2_SET_INFO => "SET_INFO",
            SMB2_OPLOCK_BREAK => "OPLOCK_BREAK",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04x})", self.as_str(), self.0)
    }
}

impl fmt::LowerHex for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Header {
    pub command: Command,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
    pub credit_charge: u16,
    pub credit_request: u16,
}

impl Smb2Header {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SMB2_HEADER_SIZE {
            return None;
        }
        if &buf[0..4] != SMB2_MAGIC {
            return None;
        }
        let mut signature = [0u8; 16];
        signature.copy_from_slice(&buf[48..64]);
        Some(Self {
            command: Command(u16::from_le_bytes(buf[12..14].try_into().ok()?)),
            credit_charge: u16::from_le_bytes(buf[6..8].try_into().ok()?),
            credit_request: u16::from_le_bytes(buf[14..16].try_into().ok()?),
            flags: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            next_command: u32::from_le_bytes(buf[20..24].try_into().ok()?),
            message_id: u64::from_le_bytes(buf[24..32].try_into().ok()?),
            tree_id: u32::from_le_bytes(buf[36..40].try_into().ok()?),
            session_id: u64::from_le_bytes(buf[40..48].try_into().ok()?),
            signature,
        })
    }

    pub fn build_response(&self, status: u32, command: u16) -> Vec<u8> {
        let mut h = vec![0u8; SMB2_HEADER_SIZE];
        h[0..4].copy_from_slice(SMB2_MAGIC);
        h[4..6].copy_from_slice(&(SMB2_HEADER_SIZE as u16).to_le_bytes()); // StructureSize
        h[8..12].copy_from_slice(&status.to_le_bytes());
        h[12..14].copy_from_slice(&command.to_le_bytes());
        // Grant between 1 and 64 credits based on client request.
        let credits = self.credit_request.clamp(1, 64);
        h[14..16].copy_from_slice(&credits.to_le_bytes());
        let flags = self.flags | SMB2_FLAGS_SERVER_TO_REDIR;
        h[16..20].copy_from_slice(&flags.to_le_bytes());
        h[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        h[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        h[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        // signature field h[48..64] remains zeroed
        h
    }
}

pub fn error_response(hdr: &Smb2Header, status: u32) -> Vec<u8> {
    let mut h = hdr.build_response(status, hdr.command.0);
    let mut body = vec![0u8; 9];
    body[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
    h.append(&mut body);
    h
}

pub fn read_nbss_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
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

pub fn write_nbss_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let len = payload.len();
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&[
        0u8,
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
    ]);
    buf.extend_from_slice(payload);
    stream.write_all(&buf)
}

pub fn normalize_windows_path(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}
