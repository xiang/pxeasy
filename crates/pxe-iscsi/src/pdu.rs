//! iSCSI PDU parsing and serialization.
//!
//! Covers the PDU subset needed for a read-only iSCSI target:
//! LoginRequest/Response, TextRequest/Response, SCSICommand, SCSIResponse,
//! DataIn, LogoutRequest/Response, and NopOut/NopIn.
//!
//! All multi-byte integers are big-endian (RFC 3720 §3.1).
//! Data segments are padded to 4-byte boundaries with zero bytes.

use std::io::{self, Read, Write};

pub const BHS_SIZE: usize = 48;

/// Safety limit: reject data segments larger than 8 MiB to guard against
/// malformed PDUs exhausting host RAM. Must fit in the 24-bit DSL field
/// (max representable value is 16,777,215 = 0xFF_FFFF).
const MAX_DATA_SEGMENT: usize = 8 * 1024 * 1024;

pub mod opcode {
    pub const NOP_OUT: u8 = 0x00;
    pub const SCSI_COMMAND: u8 = 0x01;
    pub const LOGIN_REQUEST: u8 = 0x03;
    pub const TEXT_REQUEST: u8 = 0x04;
    pub const LOGOUT_REQUEST: u8 = 0x06;
    pub const NOP_IN: u8 = 0x20;
    pub const SCSI_RESPONSE: u8 = 0x21;
    pub const LOGIN_RESPONSE: u8 = 0x23;
    pub const TEXT_RESPONSE: u8 = 0x24;
    pub const DATA_IN: u8 = 0x25;
    pub const LOGOUT_RESPONSE: u8 = 0x26;
}

/// iSCSI Login / Full-Feature phase stage identifiers (RFC 3720 §10.12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    SecurityNegotiation = 0,
    LoginOperational = 1,
    FullFeature = 3,
}

impl Stage {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Stage::SecurityNegotiation),
            1 => Some(Stage::LoginOperational),
            3 => Some(Stage::FullFeature),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Received PDU types (initiator → target)
// ---------------------------------------------------------------------------

/// RFC 3720 §10.12
#[derive(Debug)]
pub struct LoginRequest {
    /// T (Transit) bit: initiator requests transition to `nsg`.
    pub transit: bool,
    /// C (Continue) bit: more text data follows in a subsequent PDU.
    pub continue_: bool,
    /// Current Stage Group (0=Security, 1=LoginOperational, 3=FullFeature).
    pub csg: u8,
    /// Next Stage Group (valid only when `transit=true`).
    pub nsg: u8,
    pub version_max: u8,
    pub version_min: u8,
    /// Initiator Session ID (6 bytes).
    pub isid: [u8; 6],
    /// Target Session Identifying Handle (0 for new sessions).
    pub tsih: u16,
    pub initiator_task_tag: u32,
    pub cid: u16,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    /// Text parameters (null-delimited `key=value\0` pairs).
    pub data: Vec<u8>,
}

/// RFC 3720 §10.5
#[derive(Debug)]
pub struct TextRequest {
    pub final_: bool,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub cmd_sn: u32,
    /// Text data (e.g. `SendTargets=All\0`).
    pub data: Vec<u8>,
}

/// RFC 3720 §10.3
#[derive(Debug)]
pub struct SCSICommand {
    pub final_: bool,
    /// R bit: command expects data to be transferred from target (DataIn).
    pub read: bool,
    /// W bit: command includes write data from initiator.
    pub write: bool,
    /// 8-byte LUN (we only serve LUN 0).
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub expected_data_len: u32,
    pub cmd_sn: u32,
    /// CDB padded to 16 bytes.
    pub cdb: [u8; 16],
    /// Immediate data (present only when W-bit set; we ignore writes).
    pub immediate_data: Vec<u8>,
}

/// RFC 3720 §10.14
#[derive(Debug)]
pub struct LogoutRequest {
    /// 0=close session, 1=close connection, 2=remove for recovery.
    pub reason: u8,
    pub initiator_task_tag: u32,
    pub cid: u16,
    pub cmd_sn: u32,
}

/// RFC 3720 §10.18
#[derive(Debug)]
pub struct NopOut {
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub cmd_sn: u32,
    /// Optional ping data; echo back in NopIn.
    pub data: Vec<u8>,
}

/// All PDU types the target can receive from an initiator.
#[derive(Debug)]
pub enum ReceivedPdu {
    Login(LoginRequest),
    Text(TextRequest),
    SCSICommand(SCSICommand),
    Logout(LogoutRequest),
    NopOut(NopOut),
}

// ---------------------------------------------------------------------------
// Sent PDU types (target → initiator)
// ---------------------------------------------------------------------------

/// RFC 3720 §10.13
#[derive(Debug)]
pub struct LoginResponse {
    pub transit: bool,
    pub continue_: bool,
    pub csg: u8,
    pub nsg: u8,
    pub version_max: u8,
    pub version_active: u8,
    pub isid: [u8; 6],
    pub tsih: u16,
    pub initiator_task_tag: u32,
    /// 0x00 = success, 0x02 = initiator error, 0x03 = target error.
    pub status_class: u8,
    pub status_detail: u8,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data: Vec<u8>,
}

/// RFC 3720 §10.6
#[derive(Debug)]
pub struct TextResponse {
    pub final_: bool,
    pub initiator_task_tag: u32,
    /// 0xFFFF_FFFF when no continuation is expected.
    pub target_transfer_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data: Vec<u8>,
}

/// RFC 3720 §10.4
#[derive(Debug)]
pub struct SCSIResponse {
    /// O bit: residual overflow.
    pub overflow: bool,
    /// U bit: residual underflow.
    pub underflow: bool,
    /// 0x00 = Command Completed at Target.
    pub response: u8,
    /// SCSI status byte (0=GOOD, 2=CHECK CONDITION).
    pub status: u8,
    pub initiator_task_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub residual_count: u32,
    /// Raw SCSI sense bytes (no length prefix — write_to prepends 2-byte length).
    pub sense_data: Vec<u8>,
}

/// RFC 3720 §10.7
#[derive(Debug)]
pub struct DataIn {
    /// F bit: this is the final DataIn PDU for this command.
    pub final_: bool,
    /// A bit: target requests acknowledgement.
    pub acknowledge: bool,
    /// O bit: residual overflow.
    pub overflow: bool,
    /// U bit: residual underflow.
    pub underflow: bool,
    /// S bit: this PDU carries SCSI status (combines with final DataIn).
    pub has_status: bool,
    /// SCSI status (valid when `has_status=true`).
    pub status: u8,
    pub lun: u64,
    pub initiator_task_tag: u32,
    /// StatSN (valid when `has_status=true`, else 0).
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    /// Sequence number within this read transfer (starts at 0).
    pub data_sn: u32,
    /// Byte offset from start of transfer buffer.
    pub buffer_offset: u32,
    pub residual_count: u32,
    pub data: Vec<u8>,
}

/// RFC 3720 §10.15
#[derive(Debug)]
pub struct LogoutResponse {
    /// 0=success, 1=CID not found, 2=cleanup failed.
    pub response: u8,
    pub initiator_task_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
}

/// RFC 3720 §10.19
#[derive(Debug)]
pub struct NopIn {
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    /// Echo of NopOut ping data.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// Read one iSCSI PDU from `stream`.
///
/// Reads the 48-byte BHS, skips any AHS, reads and returns the data segment
/// (without padding). Returns `InvalidData` for unknown opcodes or oversized
/// data segments.
pub fn read_pdu(stream: &mut impl Read) -> io::Result<ReceivedPdu> {
    let mut bhs = [0u8; BHS_SIZE];
    stream.read_exact(&mut bhs)?;

    let ahs_len = bhs[4] as usize * 4;
    let data_len = u32::from_be_bytes([0, bhs[5], bhs[6], bhs[7]]) as usize;

    if data_len > MAX_DATA_SEGMENT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("iSCSI data segment too large: {} bytes", data_len),
        ));
    }

    // AHS is defined by RFC 3720 but we never generate it; skip if present.
    if ahs_len > 0 {
        let mut discard = vec![0u8; ahs_len];
        stream.read_exact(&mut discard)?;
    }

    let data = read_data_segment(stream, data_len)?;

    let opcode = bhs[0] & 0x3F;

    match opcode {
        opcode::LOGIN_REQUEST => parse_login_request(&bhs, data),
        opcode::TEXT_REQUEST => parse_text_request(&bhs, data),
        opcode::SCSI_COMMAND => parse_scsi_command(&bhs, data),
        opcode::LOGOUT_REQUEST => parse_logout_request(&bhs),
        opcode::NOP_OUT => parse_nop_out(&bhs, data),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported iSCSI opcode: 0x{:02x}", opcode),
        )),
    }
}

fn read_data_segment(stream: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let pad = (4 - (len % 4)) % 4;
    let mut buf = vec![0u8; len + pad];
    stream.read_exact(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

fn parse_login_request(bhs: &[u8; BHS_SIZE], data: Vec<u8>) -> io::Result<ReceivedPdu> {
    let transit = bhs[1] & 0x80 != 0;
    let continue_ = bhs[1] & 0x40 != 0;
    let csg = (bhs[1] >> 2) & 0x03;
    let nsg = bhs[1] & 0x03;
    let version_max = bhs[2];
    let version_min = bhs[3];
    let isid = [bhs[8], bhs[9], bhs[10], bhs[11], bhs[12], bhs[13]];
    let tsih = u16::from_be_bytes([bhs[14], bhs[15]]);
    let initiator_task_tag = u32_from_bhs(bhs, 16)?;
    let cid = u16::from_be_bytes([bhs[20], bhs[21]]);
    let cmd_sn = u32_from_bhs(bhs, 24)?;
    let exp_stat_sn = u32_from_bhs(bhs, 28)?;
    Ok(ReceivedPdu::Login(LoginRequest {
        transit,
        continue_,
        csg,
        nsg,
        version_max,
        version_min,
        isid,
        tsih,
        initiator_task_tag,
        cid,
        cmd_sn,
        exp_stat_sn,
        data,
    }))
}

fn parse_text_request(bhs: &[u8; BHS_SIZE], data: Vec<u8>) -> io::Result<ReceivedPdu> {
    let final_ = bhs[1] & 0x80 != 0;
    let initiator_task_tag = u32_from_bhs(bhs, 16)?;
    let target_transfer_tag = u32_from_bhs(bhs, 20)?;
    let cmd_sn = u32_from_bhs(bhs, 24)?;
    Ok(ReceivedPdu::Text(TextRequest {
        final_,
        initiator_task_tag,
        target_transfer_tag,
        cmd_sn,
        data,
    }))
}

fn parse_scsi_command(bhs: &[u8; BHS_SIZE], data: Vec<u8>) -> io::Result<ReceivedPdu> {
    let final_ = bhs[1] & 0x80 != 0;
    let read = bhs[1] & 0x40 != 0;
    let write = bhs[1] & 0x20 != 0;
    let lun = u64::from_be_bytes(
        bhs[8..16]
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    );
    let initiator_task_tag = u32_from_bhs(bhs, 16)?;
    let expected_data_len = u32_from_bhs(bhs, 20)?;
    let cmd_sn = u32_from_bhs(bhs, 24)?;
    let mut cdb = [0u8; 16];
    cdb.copy_from_slice(&bhs[32..48]);
    Ok(ReceivedPdu::SCSICommand(SCSICommand {
        final_,
        read,
        write,
        lun,
        initiator_task_tag,
        expected_data_len,
        cmd_sn,
        cdb,
        immediate_data: data,
    }))
}

fn parse_logout_request(bhs: &[u8; BHS_SIZE]) -> io::Result<ReceivedPdu> {
    // Byte 1: bit 7 = F (always 1), bits 6:0 = reason code.
    let reason = bhs[1] & 0x7F;
    let initiator_task_tag = u32_from_bhs(bhs, 16)?;
    let cid = u16::from_be_bytes([bhs[20], bhs[21]]);
    let cmd_sn = u32_from_bhs(bhs, 24)?;
    Ok(ReceivedPdu::Logout(LogoutRequest {
        reason,
        initiator_task_tag,
        cid,
        cmd_sn,
    }))
}

fn parse_nop_out(bhs: &[u8; BHS_SIZE], data: Vec<u8>) -> io::Result<ReceivedPdu> {
    let lun = u64::from_be_bytes(
        bhs[8..16]
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    );
    let initiator_task_tag = u32_from_bhs(bhs, 16)?;
    let target_transfer_tag = u32_from_bhs(bhs, 20)?;
    let cmd_sn = u32_from_bhs(bhs, 24)?;
    Ok(ReceivedPdu::NopOut(NopOut {
        lun,
        initiator_task_tag,
        target_transfer_tag,
        cmd_sn,
        data,
    }))
}

// ---------------------------------------------------------------------------
// Write helpers
// ---------------------------------------------------------------------------

fn u32_from_bhs(bhs: &[u8; BHS_SIZE], offset: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        bhs[offset..offset + 4]
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    ))
}

fn set_dsl(bhs: &mut [u8; BHS_SIZE], len: usize) {
    let v = len as u32;
    bhs[5] = ((v >> 16) & 0xFF) as u8;
    bhs[6] = ((v >> 8) & 0xFF) as u8;
    bhs[7] = (v & 0xFF) as u8;
}

fn write_raw(w: &mut impl Write, bhs: &[u8; BHS_SIZE], data: &[u8]) -> io::Result<()> {
    w.write_all(bhs)?;
    if !data.is_empty() {
        w.write_all(data)?;
        let pad = (4 - (data.len() % 4)) % 4;
        if pad > 0 {
            w.write_all(&[0u8; 3][..pad])?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Write implementations
// ---------------------------------------------------------------------------

impl LoginResponse {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut bhs = [0u8; BHS_SIZE];
        bhs[0] = opcode::LOGIN_RESPONSE;
        bhs[1] = if self.transit { 0x80 } else { 0 }
            | if self.continue_ { 0x40 } else { 0 }
            | ((self.csg & 0x03) << 2)
            | (self.nsg & 0x03);
        bhs[2] = self.version_max;
        bhs[3] = self.version_active;
        set_dsl(&mut bhs, self.data.len());
        bhs[8..14].copy_from_slice(&self.isid);
        bhs[14..16].copy_from_slice(&self.tsih.to_be_bytes());
        bhs[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        bhs[22] = self.status_class;
        bhs[23] = self.status_detail;
        bhs[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        bhs[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        bhs[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        write_raw(w, &bhs, &self.data)
    }
}

impl TextResponse {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut bhs = [0u8; BHS_SIZE];
        bhs[0] = opcode::TEXT_RESPONSE;
        bhs[1] = if self.final_ { 0x80 } else { 0 };
        set_dsl(&mut bhs, self.data.len());
        bhs[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        bhs[20..24].copy_from_slice(&self.target_transfer_tag.to_be_bytes());
        bhs[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        bhs[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        bhs[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        write_raw(w, &bhs, &self.data)
    }
}

impl SCSIResponse {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        // If sense data present: data segment = 2-byte length prefix + sense bytes.
        let data: Vec<u8> = if self.sense_data.is_empty() {
            vec![]
        } else {
            let slen = self.sense_data.len() as u16;
            let mut d = Vec::with_capacity(2 + self.sense_data.len());
            d.extend_from_slice(&slen.to_be_bytes());
            d.extend_from_slice(&self.sense_data);
            d
        };

        let mut bhs = [0u8; BHS_SIZE];
        bhs[0] = opcode::SCSI_RESPONSE;
        bhs[1] = if self.overflow { 0x10 } else { 0 } | if self.underflow { 0x08 } else { 0 };
        bhs[2] = self.response;
        bhs[3] = self.status;
        set_dsl(&mut bhs, data.len());
        bhs[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        bhs[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        bhs[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        bhs[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        bhs[44..48].copy_from_slice(&self.residual_count.to_be_bytes());
        write_raw(w, &bhs, &data)
    }
}

impl DataIn {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut bhs = [0u8; BHS_SIZE];
        bhs[0] = opcode::DATA_IN;
        bhs[1] = if self.final_ { 0x80 } else { 0 }
            | if self.acknowledge { 0x40 } else { 0 }
            | if self.overflow { 0x10 } else { 0 }
            | if self.underflow { 0x08 } else { 0 }
            | if self.has_status { 0x04 } else { 0 };
        bhs[3] = if self.has_status { self.status } else { 0 };
        set_dsl(&mut bhs, self.data.len());
        bhs[8..16].copy_from_slice(&self.lun.to_be_bytes());
        bhs[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // TargetTransferTag
        if self.has_status {
            bhs[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        }
        bhs[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        bhs[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        bhs[36..40].copy_from_slice(&self.data_sn.to_be_bytes());
        bhs[40..44].copy_from_slice(&self.buffer_offset.to_be_bytes());
        bhs[44..48].copy_from_slice(&self.residual_count.to_be_bytes());
        write_raw(w, &bhs, &self.data)
    }
}

impl LogoutResponse {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut bhs = [0u8; BHS_SIZE];
        bhs[0] = opcode::LOGOUT_RESPONSE;
        bhs[1] = 0x80; // F-bit always set
        bhs[2] = self.response;
        bhs[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        bhs[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        bhs[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        bhs[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        write_raw(w, &bhs, &[])
    }
}

impl NopIn {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut bhs = [0u8; BHS_SIZE];
        bhs[0] = opcode::NOP_IN;
        bhs[1] = 0x80; // F-bit always set
        set_dsl(&mut bhs, self.data.len());
        bhs[8..16].copy_from_slice(&self.lun.to_be_bytes());
        bhs[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        bhs[20..24].copy_from_slice(&self.target_transfer_tag.to_be_bytes());
        bhs[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        bhs[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        bhs[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        write_raw(w, &bhs, &self.data)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_bhs(opcode: u8) -> [u8; BHS_SIZE] {
        let mut b = [0u8; BHS_SIZE];
        b[0] = opcode;
        b
    }

    fn set_dsl_bytes(bhs: &mut [u8; BHS_SIZE], len: u32) {
        bhs[5] = ((len >> 16) & 0xFF) as u8;
        bhs[6] = ((len >> 8) & 0xFF) as u8;
        bhs[7] = (len & 0xFF) as u8;
    }

    fn raw_pdu(bhs: &[u8; BHS_SIZE], data: &[u8]) -> Vec<u8> {
        let pad = (4 - (data.len() % 4)) % 4;
        let mut v = Vec::with_capacity(BHS_SIZE + data.len() + pad);
        v.extend_from_slice(bhs);
        v.extend_from_slice(data);
        v.extend(std::iter::repeat_n(0u8, pad));
        v
    }

    // --- LoginRequest ---

    #[test]
    fn parse_login_request_fields() {
        let mut bhs = make_bhs(opcode::LOGIN_REQUEST);
        // T=1, C=0, CSG=1 (LoginOperational), NSG=3 (FullFeature)
        bhs[1] = 0x80 | (1 << 2) | 3;
        bhs[2] = 0x00; // VersionMax
        bhs[3] = 0x00; // VersionMin
        bhs[8..14].copy_from_slice(&[0x40, 0x01, 0x02, 0x03, 0x04, 0x05]); // ISID
        bhs[14..16].copy_from_slice(&42u16.to_be_bytes()); // TSIH
        bhs[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // ITT
        bhs[20..22].copy_from_slice(&7u16.to_be_bytes()); // CID
        bhs[24..28].copy_from_slice(&100u32.to_be_bytes()); // CmdSN
        bhs[28..32].copy_from_slice(&0u32.to_be_bytes()); // ExpStatSN

        let data = b"InitiatorName=iqn.test\0";
        set_dsl_bytes(&mut bhs, data.len() as u32);

        let raw = raw_pdu(&bhs, data);
        let pdu = read_pdu(&mut Cursor::new(raw)).unwrap();

        let ReceivedPdu::Login(req) = pdu else {
            panic!("wrong variant")
        };
        assert!(req.transit);
        assert!(!req.continue_);
        assert_eq!(req.csg, 1);
        assert_eq!(req.nsg, 3);
        assert_eq!(req.isid, [0x40, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(req.tsih, 42);
        assert_eq!(req.initiator_task_tag, 0xDEAD_BEEF);
        assert_eq!(req.cid, 7);
        assert_eq!(req.cmd_sn, 100);
        assert_eq!(req.data, data);
    }

    // --- SCSICommand ---

    #[test]
    fn parse_scsi_command_cdb() {
        let mut bhs = make_bhs(opcode::SCSI_COMMAND);
        bhs[1] = 0x80 | 0x40; // F=1, R=1
                              // LUN 0
        bhs[8..16].copy_from_slice(&0u64.to_be_bytes());
        bhs[16..20].copy_from_slice(&1u32.to_be_bytes()); // ITT
        bhs[20..24].copy_from_slice(&512u32.to_be_bytes()); // expected data len
        bhs[24..28].copy_from_slice(&1u32.to_be_bytes()); // CmdSN
                                                          // READ(10): 0x28, LBA=0x0000_0005, len=1 block
        let cdb: [u8; 16] = [0x28, 0, 0, 0, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        bhs[32..48].copy_from_slice(&cdb);

        let raw = raw_pdu(&bhs, &[]);
        let pdu = read_pdu(&mut Cursor::new(raw)).unwrap();

        let ReceivedPdu::SCSICommand(cmd) = pdu else {
            panic!("wrong variant")
        };
        assert!(cmd.final_);
        assert!(cmd.read);
        assert!(!cmd.write);
        assert_eq!(cmd.lun, 0);
        assert_eq!(cmd.initiator_task_tag, 1);
        assert_eq!(cmd.expected_data_len, 512);
        assert_eq!(cmd.cdb, cdb);
        assert!(cmd.immediate_data.is_empty());
    }

    // --- TextRequest ---

    #[test]
    fn parse_text_request_send_targets() {
        let mut bhs = make_bhs(opcode::TEXT_REQUEST);
        bhs[1] = 0x80; // F=1
        bhs[16..20].copy_from_slice(&99u32.to_be_bytes()); // ITT
        bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // TTT
        bhs[24..28].copy_from_slice(&2u32.to_be_bytes()); // CmdSN

        let data = b"SendTargets=All\0";
        set_dsl_bytes(&mut bhs, data.len() as u32);

        let raw = raw_pdu(&bhs, data);
        let pdu = read_pdu(&mut Cursor::new(raw)).unwrap();

        let ReceivedPdu::Text(req) = pdu else {
            panic!("wrong variant")
        };
        assert!(req.final_);
        assert_eq!(req.initiator_task_tag, 99);
        assert_eq!(req.target_transfer_tag, 0xFFFF_FFFF);
        assert_eq!(req.cmd_sn, 2);
        assert_eq!(req.data, data);
    }

    // --- LogoutRequest ---

    #[test]
    fn parse_logout_request_reason() {
        let mut bhs = make_bhs(opcode::LOGOUT_REQUEST);
        bhs[1] = 0x80; // F=1, reason=0 (close session)
        bhs[16..20].copy_from_slice(&5u32.to_be_bytes()); // ITT
        bhs[20..22].copy_from_slice(&1u16.to_be_bytes()); // CID
        bhs[24..28].copy_from_slice(&3u32.to_be_bytes()); // CmdSN

        let raw = raw_pdu(&bhs, &[]);
        let pdu = read_pdu(&mut Cursor::new(raw)).unwrap();

        let ReceivedPdu::Logout(req) = pdu else {
            panic!("wrong variant")
        };
        assert_eq!(req.reason, 0);
        assert_eq!(req.initiator_task_tag, 5);
        assert_eq!(req.cid, 1);
        assert_eq!(req.cmd_sn, 3);
    }

    #[test]
    fn parse_logout_request_close_connection() {
        let mut bhs = make_bhs(opcode::LOGOUT_REQUEST);
        bhs[1] = 0x80 | 1; // F=1, reason=1 (close connection)
        bhs[16..20].copy_from_slice(&0u32.to_be_bytes());

        let raw = raw_pdu(&bhs, &[]);
        let pdu = read_pdu(&mut Cursor::new(raw)).unwrap();

        let ReceivedPdu::Logout(req) = pdu else {
            panic!("wrong variant")
        };
        assert_eq!(req.reason, 1);
    }

    // --- NopOut ---

    #[test]
    fn parse_nop_out() {
        let mut bhs = make_bhs(opcode::NOP_OUT);
        bhs[1] = 0x80;
        bhs[8..16].copy_from_slice(&0u64.to_be_bytes());
        bhs[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // unsolicited
        bhs[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        bhs[24..28].copy_from_slice(&10u32.to_be_bytes()); // CmdSN

        let data = b"ping";
        set_dsl_bytes(&mut bhs, data.len() as u32);

        let raw = raw_pdu(&bhs, data);
        let pdu = read_pdu(&mut Cursor::new(raw)).unwrap();

        let ReceivedPdu::NopOut(n) = pdu else {
            panic!("wrong variant")
        };
        assert_eq!(n.initiator_task_tag, 0xFFFF_FFFF);
        assert_eq!(n.cmd_sn, 10);
        assert_eq!(n.data, b"ping");
    }

    // --- LoginResponse ---

    #[test]
    fn login_response_serializes_correctly() {
        let resp = LoginResponse {
            transit: true,
            continue_: false,
            csg: 1,
            nsg: 3,
            version_max: 0,
            version_active: 0,
            isid: [0x40, 1, 2, 3, 4, 5],
            tsih: 1,
            initiator_task_tag: 0xABCD_1234,
            status_class: 0,
            status_detail: 0,
            stat_sn: 1,
            exp_cmd_sn: 1,
            max_cmd_sn: 1,
            data: b"HeaderDigest=None\0".to_vec(),
        };

        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();

        assert_eq!(buf.len() % 4, 0, "total length must be 4-byte aligned");
        assert_eq!(buf[0], opcode::LOGIN_RESPONSE);
        // T=1, C=0, CSG=1, NSG=3  →  0x80 | 0x00 | 0x04 | 0x03 = 0x87
        assert_eq!(buf[1], 0x80 | (1 << 2) | 3);
        assert_eq!(&buf[8..14], &[0x40, 1, 2, 3, 4, 5]); // ISID
        assert_eq!(u16::from_be_bytes([buf[14], buf[15]]), 1); // TSIH
        assert_eq!(
            u32::from_be_bytes(buf[16..20].try_into().unwrap()),
            0xABCD_1234
        );
        assert_eq!(buf[22], 0); // status_class
        assert_eq!(buf[23], 0); // status_detail
                                // Data segment starts at offset 48
        assert_eq!(&buf[48..48 + 18], b"HeaderDigest=None\0");
    }

    // --- TextResponse ---

    #[test]
    fn text_response_serializes_correctly() {
        let data = b"TargetName=iqn.test\0TargetAddress=1.2.3.4:3260,1\0";
        let resp = TextResponse {
            final_: true,
            initiator_task_tag: 7,
            target_transfer_tag: 0xFFFF_FFFF,
            stat_sn: 2,
            exp_cmd_sn: 3,
            max_cmd_sn: 3,
            data: data.to_vec(),
        };

        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();

        assert_eq!(buf.len() % 4, 0);
        assert_eq!(buf[0], opcode::TEXT_RESPONSE);
        assert_eq!(buf[1] & 0x80, 0x80); // F-bit
        let dsl = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]) as usize;
        assert_eq!(dsl, data.len());
        assert_eq!(&buf[48..48 + data.len()], data);
    }

    // --- SCSIResponse ---

    #[test]
    fn scsi_response_good_no_data() {
        let resp = SCSIResponse {
            overflow: false,
            underflow: false,
            response: 0x00,
            status: 0x00,
            initiator_task_tag: 42,
            stat_sn: 5,
            exp_cmd_sn: 6,
            max_cmd_sn: 6,
            residual_count: 0,
            sense_data: vec![],
        };

        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();

        assert_eq!(buf.len(), BHS_SIZE); // no data segment
        assert_eq!(buf[0], opcode::SCSI_RESPONSE);
        assert_eq!(buf[2], 0x00); // response = Command Completed
        assert_eq!(buf[3], 0x00); // status = GOOD
        let dsl = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]);
        assert_eq!(dsl, 0);
    }

    #[test]
    fn scsi_response_check_condition_has_sense_length_prefix() {
        let sense = vec![0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x20, 0];
        let resp = SCSIResponse {
            overflow: false,
            underflow: false,
            response: 0x00,
            status: 0x02, // CHECK CONDITION
            initiator_task_tag: 1,
            stat_sn: 1,
            exp_cmd_sn: 1,
            max_cmd_sn: 1,
            residual_count: 0,
            sense_data: sense.clone(),
        };

        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();

        let dsl = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]) as usize;
        assert_eq!(dsl, 2 + sense.len());
        let prefix = u16::from_be_bytes([buf[48], buf[49]]);
        assert_eq!(prefix, sense.len() as u16);
        assert_eq!(&buf[50..50 + sense.len()], &sense);
    }

    // --- DataIn ---

    #[test]
    fn data_in_with_status_sets_s_bit() {
        let payload = vec![0u8; 2048];
        let pdu = DataIn {
            final_: true,
            acknowledge: false,
            overflow: false,
            underflow: false,
            has_status: true,
            status: 0x00,
            lun: 0,
            initiator_task_tag: 10,
            stat_sn: 3,
            exp_cmd_sn: 2,
            max_cmd_sn: 2,
            data_sn: 0,
            buffer_offset: 0,
            residual_count: 0,
            data: payload.clone(),
        };

        let mut buf = Vec::new();
        pdu.write_to(&mut buf).unwrap();

        assert_eq!(buf[0], opcode::DATA_IN);
        assert_ne!(buf[1] & 0x80, 0, "F-bit");
        assert_ne!(buf[1] & 0x04, 0, "S-bit");
        assert_eq!(buf[3], 0x00); // status GOOD
        let dsl = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]) as usize;
        assert_eq!(dsl, 2048);
        // stat_sn at offset 24
        assert_eq!(u32::from_be_bytes(buf[24..28].try_into().unwrap()), 3);
        assert_eq!(&buf[48..48 + 2048], payload.as_slice());
    }

    #[test]
    fn data_in_without_status_clears_s_bit_and_stat_sn() {
        let pdu = DataIn {
            final_: false,
            acknowledge: false,
            overflow: false,
            underflow: false,
            has_status: false,
            status: 0,
            lun: 0,
            initiator_task_tag: 1,
            stat_sn: 99, // should NOT appear in wire bytes
            exp_cmd_sn: 1,
            max_cmd_sn: 1,
            data_sn: 2,
            buffer_offset: 4096,
            residual_count: 0,
            data: vec![0xABu8; 512],
        };

        let mut buf = Vec::new();
        pdu.write_to(&mut buf).unwrap();

        assert_eq!(buf[1] & 0x04, 0, "S-bit must be clear");
        assert_eq!(u32::from_be_bytes(buf[24..28].try_into().unwrap()), 0); // stat_sn=0
        assert_eq!(u32::from_be_bytes(buf[36..40].try_into().unwrap()), 2); // data_sn
        assert_eq!(u32::from_be_bytes(buf[40..44].try_into().unwrap()), 4096); // buffer_offset
    }

    // --- LogoutResponse ---

    #[test]
    fn logout_response_serializes_correctly() {
        let resp = LogoutResponse {
            response: 0,
            initiator_task_tag: 55,
            stat_sn: 7,
            exp_cmd_sn: 8,
            max_cmd_sn: 8,
        };

        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();

        assert_eq!(buf.len(), BHS_SIZE);
        assert_eq!(buf[0], opcode::LOGOUT_RESPONSE);
        assert_ne!(buf[1] & 0x80, 0, "F-bit always set");
        assert_eq!(buf[2], 0); // response = success
        assert_eq!(u32::from_be_bytes(buf[16..20].try_into().unwrap()), 55); // ITT
    }

    // --- NopIn ---

    #[test]
    fn nop_in_echoes_data() {
        let pdu = NopIn {
            lun: 0,
            initiator_task_tag: 0xFFFF_FFFF,
            target_transfer_tag: 0xFFFF_FFFF,
            stat_sn: 1,
            exp_cmd_sn: 1,
            max_cmd_sn: 1,
            data: b"ping".to_vec(),
        };

        let mut buf = Vec::new();
        pdu.write_to(&mut buf).unwrap();

        assert_eq!(buf.len() % 4, 0);
        assert_eq!(buf[0], opcode::NOP_IN);
        assert_ne!(buf[1] & 0x80, 0, "F-bit");
        let dsl = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]) as usize;
        assert_eq!(dsl, 4);
        assert_eq!(&buf[48..52], b"ping");
    }

    // --- Padding ---

    #[test]
    fn write_raw_pads_to_four_byte_boundary() {
        for data_len in 0usize..=8 {
            let mut bhs = make_bhs(opcode::NOP_IN);
            bhs[1] = 0x80;
            set_dsl(&mut bhs, data_len);
            let data = vec![0xFFu8; data_len];
            let mut buf = Vec::new();
            write_raw(&mut buf, &bhs, &data).unwrap();
            assert_eq!(
                buf.len() % 4,
                0,
                "total length not 4-byte aligned for data_len={}",
                data_len
            );
            assert_eq!(
                buf.len(),
                BHS_SIZE
                    + data_len
                        .next_multiple_of(4)
                        .max(if data_len == 0 { 0 } else { 4 })
            );
        }
    }

    // --- Unknown opcode ---

    #[test]
    fn unknown_opcode_returns_error() {
        let bhs = make_bhs(0x7F);
        let raw = raw_pdu(&bhs, &[]);
        let err = read_pdu(&mut Cursor::new(raw)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // --- Oversized data segment ---

    #[test]
    fn oversized_data_segment_returns_error() {
        let mut bhs = make_bhs(opcode::LOGIN_REQUEST);
        // Set DSL to 0xFF_FFFF = 16,777,215 bytes (max 24-bit value, > 8 MiB limit).
        // Do not compute from MAX_DATA_SEGMENT: 16 MiB = 2^24 overflows the 24-bit field.
        bhs[5] = 0xFF;
        bhs[6] = 0xFF;
        bhs[7] = 0xFF;
        // Only write BHS — read_pdu should reject before trying to read data
        let err = read_pdu(&mut Cursor::new(&bhs[..])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
