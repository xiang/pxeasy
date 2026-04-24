use crate::pdu::{DataIn, SCSICommand, SCSIResponse};
use crate::{iso::IsoLun, MediaKind};
use std::io;

pub mod op {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const INQUIRY: u8 = 0x12;
    pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2A;
    pub const READ_16: u8 = 0x88;
    pub const WRITE_16: u8 = 0x8A;
    pub const SERVICE_ACTION_IN_16: u8 = 0x9E;
}

pub mod status {
    pub const GOOD: u8 = 0x00;
    pub const CHECK_CONDITION: u8 = 0x02;
}

pub mod sense {
    pub const NO_SENSE: u8 = 0x00;
    pub const ILLEGAL_REQUEST: u8 = 0x05;

    pub const ASC_INVALID_COMMAND_OPERATION_CODE: u8 = 0x20;
    pub const ASC_LBA_OUT_OF_RANGE: u8 = 0x21;
    pub const ASC_INVALID_FIELD_IN_CDB: u8 = 0x24;
}

/// Maximum bytes per DataIn PDU. Must be a multiple of the ISO block size (2048).
/// Keep this conservative until login negotiation tracks the initiator's
/// MaxRecvDataSegmentLength per session.
const MAX_DATA_BYTES_PER_PDU: u32 = 8_192;

/// Service action code for READ CAPACITY (16) within the SERVICE ACTION IN(16) opcode.
const SA_READ_CAPACITY_16: u8 = 0x10;

/// Handlers for SCSI commands.
/// Returns a list of PDUs (DataIn and/or SCSIResponse) to send back.
pub fn handle_command(
    cmd: &SCSICommand,
    iso: &IsoLun,
    stat_sn: &mut u32,
    exp_cmd_sn: u32,
    max_cmd_sn: u32,
    media_kind: MediaKind,
) -> io::Result<Vec<ScsiOutcome>> {
    let opcode = cmd.cdb[0];

    match opcode {
        op::TEST_UNIT_READY => Ok(vec![ScsiOutcome::Response(SCSIResponse {
            overflow: false,
            underflow: false,
            response: 0x00,
            status: status::GOOD,
            initiator_task_tag: cmd.initiator_task_tag,
            stat_sn: next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
            residual_count: 0,
            sense_data: vec![],
        })]),

        op::INQUIRY => {
            let evpd = cmd.cdb[1] & 0x01 != 0;
            let page = cmd.cdb[2];

            if evpd || page != 0 {
                // We only support standard inquiry
                return Ok(vec![check_condition(
                    cmd.initiator_task_tag,
                    next_stat_sn(stat_sn),
                    exp_cmd_sn,
                    max_cmd_sn,
                    sense::ILLEGAL_REQUEST,
                    sense::ASC_INVALID_FIELD_IN_CDB,
                    0,
                )]);
            }

            let mut data = vec![0u8; 36];
            let (device_type, removable) = match media_kind {
                MediaKind::Optical => (0x05, 0x80),
                MediaKind::Disk => (0x00, 0x00),
            };
            data[0] = device_type;
            data[1] = removable;
            data[2] = 0x05; // SPC-3
            data[3] = 0x02; // response data format
            data[4] = 31; // additional length
            data[8..16].copy_from_slice(b"PXEASY  ");
            data[16..32].copy_from_slice(match media_kind {
                MediaKind::Optical => b"ISO Boot Drive  ",
                MediaKind::Disk => b"Disk Boot Drive ",
            });
            data[32..36].copy_from_slice(b"1.00");

            let allocation_length = u16::from_be_bytes([cmd.cdb[3], cmd.cdb[4]]) as usize;
            if data.len() > allocation_length {
                data.truncate(allocation_length);
            }

            Ok(data_then_good(cmd, data, stat_sn, exp_cmd_sn, max_cmd_sn))
        }

        op::READ_CAPACITY_10 => {
            let mut data = vec![0u8; 8];
            let last_lba = (iso.block_count().saturating_sub(1)).min(u32::MAX as u64) as u32;
            data[0..4].copy_from_slice(&last_lba.to_be_bytes());
            data[4..8].copy_from_slice(&iso.block_size().to_be_bytes());

            Ok(data_then_good(cmd, data, stat_sn, exp_cmd_sn, max_cmd_sn))
        }

        op::SERVICE_ACTION_IN_16 => {
            let action = cmd.cdb[1] & 0x1F;
            if action == SA_READ_CAPACITY_16 {
                let mut data = vec![0u8; 32];
                let last_lba = iso.block_count().saturating_sub(1);
                data[0..8].copy_from_slice(&last_lba.to_be_bytes());
                data[8..12].copy_from_slice(&iso.block_size().to_be_bytes());
                // bytes 12-31 are 0

                Ok(data_then_good(cmd, data, stat_sn, exp_cmd_sn, max_cmd_sn))
            } else {
                Ok(vec![unsupported_command(
                    cmd.initiator_task_tag,
                    next_stat_sn(stat_sn),
                    exp_cmd_sn,
                    max_cmd_sn,
                )])
            }
        }

        op::READ_10 => {
            let lba = u32::from_be_bytes([cmd.cdb[2], cmd.cdb[3], cmd.cdb[4], cmd.cdb[5]]) as u64;
            let len = u16::from_be_bytes([cmd.cdb[7], cmd.cdb[8]]) as u32;
            handle_read(cmd, iso, lba, len, stat_sn, exp_cmd_sn, max_cmd_sn)
        }

        op::WRITE_10 => {
            let lba = u32::from_be_bytes([cmd.cdb[2], cmd.cdb[3], cmd.cdb[4], cmd.cdb[5]]) as u64;
            let len = u16::from_be_bytes([cmd.cdb[7], cmd.cdb[8]]) as u32;
            handle_write(cmd, iso, lba, len, stat_sn, exp_cmd_sn, max_cmd_sn)
        }

        op::READ_16 => {
            let lba = u64::from_be_bytes([
                cmd.cdb[2], cmd.cdb[3], cmd.cdb[4], cmd.cdb[5], cmd.cdb[6], cmd.cdb[7], cmd.cdb[8],
                cmd.cdb[9],
            ]);
            let len = u32::from_be_bytes([cmd.cdb[10], cmd.cdb[11], cmd.cdb[12], cmd.cdb[13]]);
            handle_read(cmd, iso, lba, len, stat_sn, exp_cmd_sn, max_cmd_sn)
        }

        op::WRITE_16 => {
            let lba = u64::from_be_bytes([
                cmd.cdb[2], cmd.cdb[3], cmd.cdb[4], cmd.cdb[5], cmd.cdb[6], cmd.cdb[7], cmd.cdb[8],
                cmd.cdb[9],
            ]);
            let len = u32::from_be_bytes([cmd.cdb[10], cmd.cdb[11], cmd.cdb[12], cmd.cdb[13]]);
            handle_write(cmd, iso, lba, len, stat_sn, exp_cmd_sn, max_cmd_sn)
        }

        op::REQUEST_SENSE => {
            // Return NO SENSE
            let mut data = vec![0u8; 18];
            data[0] = 0x70; // Current, fixed format
            data[2] = sense::NO_SENSE;
            data[7] = 10; // additional sense length

            let allocation_length = cmd.cdb[4] as usize;
            if data.len() > allocation_length {
                data.truncate(allocation_length);
            }

            Ok(data_then_good(cmd, data, stat_sn, exp_cmd_sn, max_cmd_sn))
        }

        op::SYNCHRONIZE_CACHE_10 => Ok(vec![good_response(
            cmd.initiator_task_tag,
            next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
        )]),

        _ => Ok(vec![unsupported_command(
            cmd.initiator_task_tag,
            next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
        )]),
    }
}

pub fn log_command(cmd: &SCSICommand) {
    let opcode = cmd.cdb[0];
    match opcode {
        op::READ_10 | op::WRITE_10 => {
            let lba = u32::from_be_bytes([cmd.cdb[2], cmd.cdb[3], cmd.cdb[4], cmd.cdb[5]]) as u64;
            let len = u16::from_be_bytes([cmd.cdb[7], cmd.cdb[8]]) as u32;
            log::trace!(
                "iscsi: scsi opcode=0x{:02x} lba={} blocks={} itt=0x{:08x} cmd_sn={} exp_len={} immediate_len={} flags=R{}W{}",
                opcode,
                lba,
                len,
                cmd.initiator_task_tag,
                cmd.cmd_sn,
                cmd.expected_data_len,
                cmd.immediate_data.len(),
                if cmd.read { "+" } else { "-" },
                if cmd.write { "+" } else { "-" }
            );
        }
        op::READ_16 | op::WRITE_16 => {
            let lba = u64::from_be_bytes([
                cmd.cdb[2], cmd.cdb[3], cmd.cdb[4], cmd.cdb[5], cmd.cdb[6], cmd.cdb[7], cmd.cdb[8],
                cmd.cdb[9],
            ]);
            let len = u32::from_be_bytes([cmd.cdb[10], cmd.cdb[11], cmd.cdb[12], cmd.cdb[13]]);
            log::trace!(
                "iscsi: scsi opcode=0x{:02x} lba={} blocks={} itt=0x{:08x} cmd_sn={} exp_len={} immediate_len={} flags=R{}W{}",
                opcode,
                lba,
                len,
                cmd.initiator_task_tag,
                cmd.cmd_sn,
                cmd.expected_data_len,
                cmd.immediate_data.len(),
                if cmd.read { "+" } else { "-" },
                if cmd.write { "+" } else { "-" }
            );
        }
        _ => {
            log::debug!(
                "iscsi: scsi opcode=0x{:02x} itt=0x{:08x} cmd_sn={} exp_len={} immediate_len={} flags=R{}W{}",
                opcode,
                cmd.initiator_task_tag,
                cmd.cmd_sn,
                cmd.expected_data_len,
                cmd.immediate_data.len(),
                if cmd.read { "+" } else { "-" },
                if cmd.write { "+" } else { "-" }
            );
        }
    }
}

pub fn command_blocks(cmd: &SCSICommand) -> Option<u32> {
    match cmd.cdb[0] {
        op::READ_10 | op::WRITE_10 => Some(u16::from_be_bytes([cmd.cdb[7], cmd.cdb[8]]) as u32),
        op::READ_16 | op::WRITE_16 => Some(u32::from_be_bytes([
            cmd.cdb[10],
            cmd.cdb[11],
            cmd.cdb[12],
            cmd.cdb[13],
        ])),
        _ => None,
    }
}

fn handle_read(
    cmd: &SCSICommand,
    iso: &IsoLun,
    lba: u64,
    len: u32,
    stat_sn: &mut u32,
    exp_cmd_sn: u32,
    max_cmd_sn: u32,
) -> io::Result<Vec<ScsiOutcome>> {
    if len == 0 {
        return Ok(vec![ScsiOutcome::Response(SCSIResponse {
            overflow: false,
            underflow: false,
            response: 0x00,
            status: status::GOOD,
            initiator_task_tag: cmd.initiator_task_tag,
            stat_sn: next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
            residual_count: 0,
            sense_data: vec![],
        })]);
    }

    if lba + (len as u64) > iso.block_count() {
        return Ok(vec![check_condition(
            cmd.initiator_task_tag,
            next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
            sense::ILLEGAL_REQUEST,
            sense::ASC_LBA_OUT_OF_RANGE,
            0,
        )]);
    }

    // Serve via DataIn PDUs capped at MAX_DATA_BYTES_PER_PDU each.
    // READ(10) allows up to 65535 blocks (128 MiB), so fragmentation is required.
    // Final DataIn carries the S-bit (has_status=true), eliminating a separate SCSIResponse.
    let mut outcomes = Vec::new();
    let total_blocks = len as u64;
    let mut blocks_sent = 0u64;
    let mut data_sn = 0u32;
    let blocks_per_pdu = (MAX_DATA_BYTES_PER_PDU / iso.block_size()) as u64;

    while blocks_sent < total_blocks {
        // Compute block count for this PDU first; chunk_bytes follows, guaranteeing
        // alignment to block_size regardless of MAX_DATA_BYTES_PER_PDU's value.
        let chunk_blocks = (total_blocks - blocks_sent).min(blocks_per_pdu) as u32;
        let chunk_bytes = chunk_blocks as u64 * iso.block_size() as u64;

        let mut data = Vec::with_capacity(chunk_bytes as usize);
        iso.read_blocks(lba + blocks_sent, chunk_blocks, &mut data)?;

        let buffer_offset = (blocks_sent * iso.block_size() as u64) as u32;
        blocks_sent += chunk_blocks as u64;
        let is_final = blocks_sent >= total_blocks;

        outcomes.push(ScsiOutcome::Data(DataIn {
            final_: is_final,
            acknowledge: false,
            overflow: false,
            underflow: false,
            has_status: false,
            status: 0,
            lun: cmd.lun,
            initiator_task_tag: cmd.initiator_task_tag,
            stat_sn: 0,
            exp_cmd_sn,
            max_cmd_sn,
            data_sn,
            buffer_offset,
            residual_count: 0,
            data,
        }));
        data_sn += 1;
    }

    outcomes.push(ScsiOutcome::Response(SCSIResponse {
        overflow: false,
        underflow: false,
        response: 0x00,
        status: status::GOOD,
        initiator_task_tag: cmd.initiator_task_tag,
        stat_sn: next_stat_sn(stat_sn),
        exp_cmd_sn,
        max_cmd_sn,
        residual_count: 0,
        sense_data: vec![],
    }));

    Ok(outcomes)
}

fn handle_write(
    cmd: &SCSICommand,
    iso: &IsoLun,
    lba: u64,
    len: u32,
    stat_sn: &mut u32,
    exp_cmd_sn: u32,
    max_cmd_sn: u32,
) -> io::Result<Vec<ScsiOutcome>> {
    if len == 0 {
        return Ok(vec![good_response(
            cmd.initiator_task_tag,
            next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
        )]);
    }

    if lba + (len as u64) > iso.block_count() {
        return Ok(vec![check_condition(
            cmd.initiator_task_tag,
            next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
            sense::ILLEGAL_REQUEST,
            sense::ASC_LBA_OUT_OF_RANGE,
            0,
        )]);
    }

    let expected_len = len as usize * iso.block_size() as usize;
    if cmd.immediate_data.len() != expected_len {
        return Ok(vec![check_condition(
            cmd.initiator_task_tag,
            next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
            sense::ILLEGAL_REQUEST,
            sense::ASC_INVALID_FIELD_IN_CDB,
            0,
        )]);
    }

    iso.write_blocks(lba, len, &cmd.immediate_data)?;

    Ok(vec![good_response(
        cmd.initiator_task_tag,
        next_stat_sn(stat_sn),
        exp_cmd_sn,
        max_cmd_sn,
    )])
}

fn data_then_good(
    cmd: &SCSICommand,
    data: Vec<u8>,
    stat_sn: &mut u32,
    exp_cmd_sn: u32,
    max_cmd_sn: u32,
) -> Vec<ScsiOutcome> {
    vec![
        ScsiOutcome::Data(DataIn {
            final_: true,
            acknowledge: false,
            overflow: false,
            underflow: false,
            has_status: false,
            status: 0,
            lun: cmd.lun,
            initiator_task_tag: cmd.initiator_task_tag,
            stat_sn: 0,
            exp_cmd_sn,
            max_cmd_sn,
            data_sn: 0,
            buffer_offset: 0,
            residual_count: 0,
            data,
        }),
        ScsiOutcome::Response(SCSIResponse {
            overflow: false,
            underflow: false,
            response: 0x00,
            status: status::GOOD,
            initiator_task_tag: cmd.initiator_task_tag,
            stat_sn: next_stat_sn(stat_sn),
            exp_cmd_sn,
            max_cmd_sn,
            residual_count: 0,
            sense_data: vec![],
        }),
    ]
}

pub enum ScsiOutcome {
    Data(DataIn),
    Response(SCSIResponse),
}

fn next_stat_sn(stat_sn: &mut u32) -> u32 {
    let val = *stat_sn;
    *stat_sn += 1;
    val
}

fn check_condition(
    itt: u32,
    stat_sn: u32,
    exp_cmd_sn: u32,
    max_cmd_sn: u32,
    key: u8,
    asc: u8,
    ascq: u8,
) -> ScsiOutcome {
    let mut sense_data = vec![0u8; 18];
    sense_data[0] = 0x70; // Fixed format, current errors
    sense_data[2] = key;
    sense_data[7] = 10; // Additional sense length
    sense_data[12] = asc;
    sense_data[13] = ascq;

    ScsiOutcome::Response(SCSIResponse {
        overflow: false,
        underflow: false,
        response: 0x00,
        status: status::CHECK_CONDITION,
        initiator_task_tag: itt,
        stat_sn,
        exp_cmd_sn,
        max_cmd_sn,
        residual_count: 0,
        sense_data,
    })
}

fn unsupported_command(itt: u32, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) -> ScsiOutcome {
    check_condition(
        itt,
        stat_sn,
        exp_cmd_sn,
        max_cmd_sn,
        sense::ILLEGAL_REQUEST,
        sense::ASC_INVALID_COMMAND_OPERATION_CODE,
        0,
    )
}

fn good_response(itt: u32, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) -> ScsiOutcome {
    ScsiOutcome::Response(SCSIResponse {
        overflow: false,
        underflow: false,
        response: 0x00,
        status: status::GOOD,
        initiator_task_tag: itt,
        stat_sn,
        exp_cmd_sn,
        max_cmd_sn,
        residual_count: 0,
        sense_data: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn mock_iso(size_blocks: u64) -> (NamedTempFile, IsoLun) {
        let mut file = NamedTempFile::new().unwrap();
        let content = vec![0u8; (size_blocks * 2048) as usize];
        file.write_all(&content).unwrap();
        let path = file.path().to_path_buf();
        (file, IsoLun::open(&path).unwrap())
    }

    fn mock_command(opcode: u8) -> SCSICommand {
        let mut cdb = [0u8; 16];
        cdb[0] = opcode;
        SCSICommand {
            final_: true,
            read: true,
            write: false,
            lun: 0,
            initiator_task_tag: 0x1234,
            expected_data_len: 0,
            cmd_sn: 1,
            cdb,
            immediate_data: vec![],
        }
    }

    #[test]
    fn test_test_unit_ready() {
        let (_f, iso) = mock_iso(1);
        let cmd = mock_command(op::TEST_UNIT_READY);
        let mut stat_sn = 10;
        let outcomes = handle_command(&cmd, &iso, &mut stat_sn, 1, 1, MediaKind::Optical).unwrap();

        assert_eq!(outcomes.len(), 1);
        if let ScsiOutcome::Response(resp) = &outcomes[0] {
            assert_eq!(resp.status, status::GOOD);
            assert_eq!(resp.stat_sn, 10);
            assert_eq!(stat_sn, 11);
        } else {
            panic!("expected response");
        }
    }

    #[test]
    fn test_inquiry() {
        let (_f, iso) = mock_iso(1);
        let mut cmd = mock_command(op::INQUIRY);
        cmd.cdb[4] = 36; // allocation length
        let mut stat_sn = 1;
        let outcomes = handle_command(&cmd, &iso, &mut stat_sn, 1, 1, MediaKind::Optical).unwrap();

        assert_eq!(outcomes.len(), 2);
        if let ScsiOutcome::Data(data) = &outcomes[0] {
            assert!(!data.has_status);
            assert_eq!(data.data.len(), 36);
            assert_eq!(&data.data[8..16], b"PXEASY  ");
        } else {
            panic!("expected data");
        }
        if let ScsiOutcome::Response(resp) = &outcomes[1] {
            assert_eq!(resp.status, status::GOOD);
        } else {
            panic!("expected response");
        }
    }

    #[test]
    fn test_read_capacity_10() {
        let (_f, iso) = mock_iso(100);
        let cmd = mock_command(op::READ_CAPACITY_10);
        let mut stat_sn = 1;
        let outcomes = handle_command(&cmd, &iso, &mut stat_sn, 1, 1, MediaKind::Optical).unwrap();

        assert_eq!(outcomes.len(), 2);
        if let ScsiOutcome::Data(data) = &outcomes[0] {
            assert_eq!(data.data.len(), 8);
            let last_lba =
                u32::from_be_bytes([data.data[0], data.data[1], data.data[2], data.data[3]]);
            let block_size =
                u32::from_be_bytes([data.data[4], data.data[5], data.data[6], data.data[7]]);
            assert_eq!(last_lba, 99);
            assert_eq!(block_size, 2048);
        } else {
            panic!("expected data");
        }
        if let ScsiOutcome::Response(resp) = &outcomes[1] {
            assert_eq!(resp.status, status::GOOD);
        } else {
            panic!("expected response");
        }
    }

    #[test]
    fn test_unsupported() {
        let (_f, iso) = mock_iso(1);
        let cmd = mock_command(0xFF);
        let mut stat_sn = 1;
        let outcomes = handle_command(&cmd, &iso, &mut stat_sn, 1, 1, MediaKind::Optical).unwrap();

        assert_eq!(outcomes.len(), 1);
        if let ScsiOutcome::Response(resp) = &outcomes[0] {
            assert_eq!(resp.status, status::CHECK_CONDITION);
            assert_eq!(resp.sense_data[2], sense::ILLEGAL_REQUEST);
            assert_eq!(
                resp.sense_data[12],
                sense::ASC_INVALID_COMMAND_OPERATION_CODE
            );
        } else {
            panic!("expected response");
        }
    }

    #[test]
    fn test_write_10_updates_overlay() {
        let (_f, iso) = mock_iso(4);
        let mut cmd = mock_command(op::WRITE_10);
        cmd.write = true;
        cmd.read = false;
        cmd.cdb[7..9].copy_from_slice(&1u16.to_be_bytes());
        cmd.expected_data_len = 2048;
        cmd.immediate_data = vec![0x5A; 2048];
        let mut stat_sn = 1;

        let outcomes = handle_command(&cmd, &iso, &mut stat_sn, 1, 1, MediaKind::Optical).unwrap();

        assert_eq!(outcomes.len(), 1);
        let mut buf = Vec::new();
        iso.read_blocks(0, 1, &mut buf).unwrap();
        assert_eq!(buf, vec![0x5A; 2048]);
    }
}
