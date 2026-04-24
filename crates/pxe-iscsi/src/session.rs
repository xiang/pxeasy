use std::io::{self, Read, Write};

use crate::{
    iso::IsoLun,
    login::{describe_text_parameters, LoginSession, SessionOutcome},
    pdu::{read_pdu, LogoutRequest, LogoutResponse, NopIn, ReceivedPdu},
    scsi, MediaKind, SessionTrace,
};

pub fn run_login_phase<S: Read + Write>(
    stream: &mut S,
    login: &mut LoginSession,
    trace: &mut SessionTrace,
) -> io::Result<SessionOutcome> {
    loop {
        match read_pdu(stream)? {
            ReceivedPdu::Login(req) => {
                trace.note_login_request();
                log::debug!(
                    "login request csg={} nsg={} transit={} itt=0x{:08x} cmd_sn={} params=[{}]",
                    req.csg,
                    req.nsg,
                    req.transit,
                    req.initiator_task_tag,
                    req.cmd_sn,
                    describe_text_parameters(&req.data)
                );
                let (resp, outcome) = login.handle_login_request(&req)?;
                resp.write_to(stream)?;
                if let Some(outcome) = outcome {
                    log::debug!("login complete -> {:?}", outcome);
                    return Ok(outcome);
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected PDU during iSCSI login phase",
                ));
            }
        }
    }
}

pub fn run_discovery_session<S: Read + Write>(
    stream: &mut S,
    login: &mut LoginSession,
    trace: &mut SessionTrace,
) -> io::Result<()> {
    loop {
        match read_pdu(stream)? {
            ReceivedPdu::Text(req) => {
                trace.note_discovery_text();
                log::debug!(
                    "discovery text itt=0x{:08x} cmd_sn={} params=[{}]",
                    req.initiator_task_tag,
                    req.cmd_sn,
                    describe_text_parameters(&req.data)
                );
                let resp = login.handle_text_request(&req)?;
                resp.write_to(stream)?;
            }
            ReceivedPdu::Logout(req) => {
                trace.note_logout_request();
                log::debug!(
                    "discovery logout itt=0x{:08x} cmd_sn={}",
                    req.initiator_task_tag,
                    req.cmd_sn
                );
                let exp_cmd_sn = req.cmd_sn.saturating_add(1);
                write_logout_response(stream, req, login.stat_sn(), exp_cmd_sn)?;
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected PDU during iSCSI discovery session",
                ));
            }
        }
    }
}

pub fn run_full_feature_session<S: Read + Write>(
    stream: &mut S,
    iso: &IsoLun,
    mut exp_cmd_sn: u32,
    mut stat_sn: u32,
    media_kind: MediaKind,
    trace: &mut SessionTrace,
) -> io::Result<()> {
    loop {
        match read_pdu(stream)? {
            ReceivedPdu::SCSICommand(cmd) => {
                trace.note_scsi_command(
                    cmd.cdb[0],
                    scsi::command_blocks(&cmd),
                    iso.block_size(),
                    cmd.write,
                );
                scsi::log_command(&cmd);
                // max_cmd_sn = exp_cmd_sn: command window of 1 (no pipelining in v1).
                exp_cmd_sn = advance_exp_cmd_sn(exp_cmd_sn, cmd.cmd_sn);
                let outcomes = scsi::handle_command(
                    &cmd,
                    iso,
                    &mut stat_sn,
                    exp_cmd_sn,
                    exp_cmd_sn,
                    media_kind,
                )?;
                for outcome in outcomes {
                    match outcome {
                        scsi::ScsiOutcome::Data(data) => data.write_to(stream)?,
                        scsi::ScsiOutcome::Response(resp) => resp.write_to(stream)?,
                    }
                }
            }
            ReceivedPdu::NopOut(nop) => {
                trace.note_nop_out();
                log::trace!(
                    "nop-out itt=0x{:08x} ttt=0x{:08x} cmd_sn={} data_len={}",
                    nop.initiator_task_tag,
                    nop.target_transfer_tag,
                    nop.cmd_sn,
                    nop.data.len()
                );
                // RFC 3720 §10.18: NopOut with ITT=0xFFFF_FFFF is a response to a
                // target-originated NopIn and carries no CmdSN. We never send
                // unsolicited NopIn, so every NopOut we receive is an initiator
                // keepalive ping (ITT != 0xFFFF_FFFF) and must carry a valid CmdSN.
                exp_cmd_sn = advance_exp_cmd_sn(exp_cmd_sn, nop.cmd_sn);
                let resp = NopIn {
                    lun: nop.lun,
                    initiator_task_tag: nop.initiator_task_tag,
                    target_transfer_tag: nop.target_transfer_tag,
                    stat_sn: next_stat_sn(&mut stat_sn),
                    exp_cmd_sn,
                    max_cmd_sn: exp_cmd_sn,
                    data: nop.data,
                };
                resp.write_to(stream)?;
            }
            ReceivedPdu::Logout(req) => {
                trace.note_logout_request();
                log::debug!(
                    "full-feature logout itt=0x{:08x} cmd_sn={}",
                    req.initiator_task_tag,
                    req.cmd_sn
                );
                exp_cmd_sn = advance_exp_cmd_sn(exp_cmd_sn, req.cmd_sn);
                write_logout_response(stream, req, next_stat_sn(&mut stat_sn), exp_cmd_sn)?;
                return Ok(());
            }
            ReceivedPdu::Login(_) | ReceivedPdu::Text(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected login/text PDU in iSCSI full feature phase",
                ));
            }
        }
    }
}

fn advance_exp_cmd_sn(current: u32, received: u32) -> u32 {
    let next = received.wrapping_add(1);
    if received >= current {
        next
    } else {
        current
    }
}

fn write_logout_response<S: Write>(
    stream: &mut S,
    req: LogoutRequest,
    stat_sn: u32,
    exp_cmd_sn: u32,
) -> io::Result<()> {
    LogoutResponse {
        response: 0,
        initiator_task_tag: req.initiator_task_tag,
        stat_sn,
        exp_cmd_sn,
        max_cmd_sn: exp_cmd_sn,
    }
    .write_to(stream)
}

fn next_stat_sn(stat_sn: &mut u32) -> u32 {
    let current = *stat_sn;
    *stat_sn = (*stat_sn).wrapping_add(1); // RFC 3720 §3.3.1: 32-bit modular counter
    current
}
