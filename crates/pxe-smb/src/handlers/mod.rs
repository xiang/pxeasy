pub mod file;
pub mod negotiate;
pub mod session;
pub mod tree;
pub mod utils;
pub mod vfs;

use crate::constants::*;
use crate::proto::{error_response, Smb2Header};
use crate::session::Session;
use crate::SmbConfig;
use std::io;
use std::time::Instant;

pub fn dispatch(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
    last_file_id: Option<u64>,
) -> io::Result<Option<Vec<u8>>> {
    let t0 = Instant::now();
    let result = dispatch_inner(hdr, body, session, config, last_file_id);
    let elapsed = t0.elapsed();
    if elapsed.as_millis() >= 100 {
        log::warn!("slow cmd={} elapsed={}ms", hdr.command, elapsed.as_millis());
    }
    result
}

fn dispatch_inner(
    hdr: &Smb2Header,
    body: &[u8],
    session: &mut Session,
    config: &SmbConfig,
    last_file_id: Option<u64>,
) -> io::Result<Option<Vec<u8>>> {
    match hdr.command.0 {
        SMB2_NEGOTIATE => Ok(Some(negotiate::handle_negotiate(hdr, body, session))),
        SMB2_SESSION_SETUP => Ok(Some(session::handle_session_setup(hdr, body, session))),
        SMB2_LOGOFF => Ok(Some(session::handle_logoff(hdr))),
        SMB2_TREE_CONNECT => Ok(Some(tree::handle_tree_connect(hdr, body, session, config))),
        SMB2_TREE_DISCONNECT => Ok(Some(tree::handle_tree_disconnect(hdr, session))),
        SMB2_CREATE => Ok(Some(file::handle_create(hdr, body, session, config))),
        SMB2_CLOSE => Ok(Some(file::handle_close(hdr, body, session, last_file_id))),
        SMB2_LOCK => Ok(Some(file::handle_lock(hdr, body, session, last_file_id))),
        SMB2_READ => file::handle_read(hdr, body, session, config, last_file_id),
        SMB2_ECHO => Ok(Some(file::handle_echo(hdr))),
        SMB2_QUERY_INFO => Ok(Some(file::handle_query_info(
            hdr,
            body,
            session,
            config,
            last_file_id,
        ))),
        SMB2_QUERY_DIRECTORY => Ok(Some(file::handle_query_directory(
            hdr,
            body,
            session,
            config,
            last_file_id,
        ))),
        SMB2_IOCTL => Ok(Some(file::handle_ioctl(hdr, body, session))),
        _ => {
            log::warn!("unhandled command 0x{:04x}", hdr.command);
            Ok(Some(error_response(hdr, STATUS_NOT_SUPPORTED)))
        }
    }
}
