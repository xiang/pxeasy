use std::io::{self, Read, Write};

// ONC RPC message types
pub const CALL: u32 = 0;
pub const REPLY: u32 = 1;

const RPC_VERSION: u32 = 2;

// Reply stats
pub const MSG_ACCEPTED: u32 = 0;

// Accept stats
pub const SUCCESS: u32 = 0;
pub const PROC_UNAVAIL: u32 = 3;

// Auth flavors
pub const AUTH_NULL: u32 = 0;

/// Read one ONC RPC TCP record (handles multi-fragment records).
pub fn read_record(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let word = u32::from_be_bytes(hdr);
        let last = (word & 0x8000_0000) != 0;
        let len = (word & 0x7fff_ffff) as usize;
        let start = data.len();
        data.resize(start + len, 0);
        stream.read_exact(&mut data[start..])?;
        if last {
            break;
        }
    }
    Ok(data)
}

/// Write one ONC RPC TCP record (single last fragment).
///
/// Header and payload are combined into one write so the kernel sends them
/// in a single TCP segment. Splitting across two writes causes the client's
/// read(28) to return after the 4-byte header segment, producing "short read".
pub fn write_record(stream: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let header = (data.len() as u32) | 0x8000_0000;
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&header.to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf)
}

/// Parsed RPC call header.
pub struct RpcCall {
    pub xid: u32,
    pub prog: u32,
    pub vers: u32,
    pub proc: u32,
    /// Byte offset where procedure arguments start.
    pub args_offset: usize,
}

/// Parse an RPC CALL from a byte buffer.
pub fn parse_call(buf: &[u8]) -> Option<RpcCall> {
    let mut r = Reader::new(buf);
    let xid = r.u32()?;
    if r.u32()? != CALL {
        return None;
    }
    if r.u32()? != RPC_VERSION {
        return None;
    }
    let prog = r.u32()?;
    let vers = r.u32()?;
    let proc = r.u32()?;
    r.skip_opaque_auth()?; // cred
    r.skip_opaque_auth()?; // verf
    Some(RpcCall {
        xid,
        prog,
        vers,
        proc,
        args_offset: r.pos,
    })
}

/// Build an RPC accepted reply with SUCCESS and the given payload bytes.
pub fn build_accepted_reply(xid: u32, payload: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(xid);
    w.u32(REPLY);
    w.u32(MSG_ACCEPTED);
    w.opaque_auth_null();
    w.u32(SUCCESS);
    w.raw(payload);
    w.into_bytes()
}

/// Build an RPC accepted reply with PROC_UNAVAIL.
pub fn build_proc_unavail_reply(xid: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(xid);
    w.u32(REPLY);
    w.u32(MSG_ACCEPTED);
    w.opaque_auth_null();
    w.u32(PROC_UNAVAIL);
    w.into_bytes()
}

// ---------------------------------------------------------------------------
// XDR reader
// ---------------------------------------------------------------------------

pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn u32(&mut self) -> Option<u32> {
        let v = u32::from_be_bytes(self.buf.get(self.pos..self.pos + 4)?.try_into().ok()?);
        self.pos += 4;
        Some(v)
    }

    pub fn u64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.buf.len() {
            return None;
        }
        let hi = self.u32()? as u64;
        let lo = self.u32()? as u64;
        Some((hi << 32) | lo)
    }

    pub fn opaque(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let padded = (len + 3) & !3;
        if self.pos + padded > self.buf.len() {
            return None;
        }
        let data = &self.buf[self.pos..self.pos + len];
        self.pos += padded;
        Some(data)
    }

    pub fn string(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.opaque()?).ok()
    }

    fn skip_opaque_auth(&mut self) -> Option<()> {
        let _flavor = self.u32()?;
        let len = self.u32()? as usize;
        let padded = (len + 3) & !3;
        if self.pos + padded > self.buf.len() {
            return None;
        }
        self.pos += padded;
        Some(())
    }
}

// ---------------------------------------------------------------------------
// XDR writer
// ---------------------------------------------------------------------------

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.u32((v >> 32) as u32);
        self.u32(v as u32);
    }

    pub fn opaque(&mut self, data: &[u8]) {
        self.u32(data.len() as u32);
        self.buf.extend_from_slice(data);
        let pad = (4 - data.len() % 4) % 4;
        self.buf.extend(std::iter::repeat_n(0u8, pad));
    }

    pub fn string(&mut self, s: &str) {
        self.opaque(s.as_bytes());
    }

    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn opaque_auth_null(&mut self) {
        self.u32(AUTH_NULL);
        self.u32(0);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}
