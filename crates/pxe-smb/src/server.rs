use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use crate::constants::*;
use crate::handlers::dispatch;
use crate::handlers::negotiate::handle_smb1_negotiate;
use crate::proto::*;
use crate::session::*;
use crate::SmbConfig;

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

        let cache = pxe_profiles::build_metadata_map(&config.source_path)
            .map(Arc::new)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        log::info!("ISO metadata cache built ({} entries)", cache.len());

        let iso_file = if !config.source_path.is_dir() {
            Some(Arc::new(std::fs::File::open(&config.source_path)?))
        } else {
            None
        };

        let config = SmbConfig {
            iso_cache: Some(cache),
            iso_file,
            ..config
        };
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if let Err(e) = stream.set_nonblocking(false) {
                        log::warn!("set blocking failed for {peer}: {e}");
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    let config = Arc::clone(&self.config);
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, &config) {
                            if e.kind() != io::ErrorKind::BrokenPipe
                                && e.kind() != io::ErrorKind::ConnectionReset
                            {
                                log::warn!("connection from {peer} failed: {e}");
                            } else {
                                log::debug!("connection from {peer} closed with {}", e.kind());
                            }
                        }
                    });
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

pub fn handle_connection(mut stream: TcpStream, config: &SmbConfig) -> io::Result<()> {
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let mut default_session = Session::default();
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    log::debug!("{peer} connected");

    loop {
        let frame = match read_nbss_frame(&mut stream) {
            Ok(frame) => frame,
            Err(e) => {
                log::debug!("{peer} read failed: {e}");
                return Err(e);
            }
        };
        if frame.is_empty() {
            log::debug!("{peer} closed");
            return Ok(());
        }

        if frame.len() >= 4 && &frame[0..4] == SMB1_MAGIC {
            log::debug!("{peer} SMB1 negotiate -> SMB2 upgrade");
            let dummy_hdr = Smb2Header {
                command: Command(SMB2_NEGOTIATE),
                flags: 0,
                next_command: 0,
                message_id: 0,
                tree_id: 0,
                session_id: 0,
                credit_charge: 0,
                credit_request: 1,
                signature: [0u8; 16],
            };
            let resp = handle_smb1_negotiate(&dummy_hdr, &mut default_session);
            write_nbss_frame(&mut stream, &resp)?;
            continue;
        }

        if frame.len() < 64 {
            return Ok(());
        }

        log::trace!("{peer} frame_len={}", frame.len());
        let mut offset = 0usize;
        let mut responses: Vec<Vec<u8>> = Vec::new();
        let mut last_file_id: Option<u64> = None;
        let mut last_tree_id: u32 = 0;
        let mut last_session_id: u64 = 0;
        loop {
            let msg = &frame[offset..];
            let hdr = match Smb2Header::parse(msg) {
                Some(h) => h,
                None => break,
            };
            log::trace!(
                "{peer} frame_offset={} cmd={} next_command={} flags=0x{:08x}",
                offset,
                hdr.command,
                hdr.next_command,
                hdr.flags
            );
            let next = hdr.next_command as usize;
            let body = if next > 0 && next <= msg.len() {
                &msg[64..next]
            } else {
                &msg[64..]
            };
            let related = hdr.flags & 0x0000_0004 != 0 && !responses.is_empty();
            let effective_hdr = if related {
                Smb2Header {
                    session_id: last_session_id,
                    tree_id: last_tree_id,
                    ..hdr.clone()
                }
            } else {
                hdr.clone()
            };

            let request_session_id = effective_hdr.session_id;
            let response = {
                let session = if request_session_id == 0 {
                    &mut default_session
                } else {
                    sessions
                        .entry(request_session_id)
                        .or_insert_with(|| Session {
                            session_id: request_session_id,
                            ..Default::default()
                        })
                };

                log::trace!(
                    "{peer} request cmd={} msg_id={} tree_id={} session_id={} body_len={} next_command={} related={}",
                    effective_hdr.command,
                    effective_hdr.message_id,
                    effective_hdr.tree_id,
                    effective_hdr.session_id,
                    body.len(),
                    hdr.next_command,
                    (hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS) != 0
                );
                dispatch(&effective_hdr, body, session, config, last_file_id)?
            };

            // If the session was initialized (id changed from 0 to something else), move it to the map.
            if request_session_id == 0 && default_session.session_id != 0 {
                let sid = default_session.session_id;
                log::debug!("{peer} promoting session 0 to {sid}");
                sessions.insert(sid, std::mem::take(&mut default_session));
            }

            if let Some(mut resp) = response {
                if resp.len() >= 12 {
                    let status = Status(u32::from_le_bytes(
                        resp[8..12].try_into().unwrap_or_default(),
                    ));
                    log::trace!(
                        "{peer} response cmd={} msg_id={} status={}",
                        effective_hdr.command,
                        effective_hdr.message_id,
                        status
                    );
                    if effective_hdr.command.0 == SMB2_CREATE
                        && status.0 == STATUS_SUCCESS
                        && resp.len() >= 144
                    {
                        let hid = u64::from_le_bytes(resp[128..136].try_into().unwrap_or_default());
                        last_file_id = Some(hid);
                    }
                }

                // Always 8-byte align the response first.
                let aligned = (resp.len() + 7) & !7;
                resp.resize(aligned, 0);

                if resp.len() >= 64 {
                    last_session_id =
                        u64::from_le_bytes(resp[40..48].try_into().unwrap_or_default());
                    last_tree_id = u32::from_le_bytes(resp[36..40].try_into().unwrap_or_default());
                } else {
                    last_session_id = effective_hdr.session_id;
                    last_tree_id = effective_hdr.tree_id;
                }

                // Sign responses only when the client signed the corresponding request.
                // For SMB 2.0.2/2.1, an unsigned request gets an unsigned response even if
                // the session will require signing on subsequent messages.
                if last_session_id != 0 {
                    let status = u32::from_le_bytes(resp[8..12].try_into().unwrap_or_default());
                    let session = sessions
                        .get_mut(&last_session_id)
                        .unwrap_or(&mut default_session);
                    let request_was_signed = (effective_hdr.flags & SMB2_FLAGS_SIGNED) != 0;
                    if request_was_signed && session.is_signing_required {
                        if let Some(key) = session.session_key {
                            // IMPORTANT: MS-SMB2 says SESSION_SETUP response with
                            // MORE_PROCESSING_REQUIRED MUST NOT be signed.
                            let flags =
                                u32::from_le_bytes(resp[16..20].try_into().unwrap_or_default());
                            let is_session_setup = effective_hdr.command.0 == SMB2_SESSION_SETUP;
                            let is_more_processing = status == STATUS_MORE_PROCESSING_REQUIRED;

                            if (flags & SMB2_FLAGS_SIGNED) == 0
                                && !(is_session_setup && is_more_processing)
                            {
                                resp[16..20]
                                    .copy_from_slice(&(flags | SMB2_FLAGS_SIGNED).to_le_bytes());
                                crate::proto::sign_message(&key, &mut resp);
                            }
                        }
                    }
                }

                responses.push(resp);
            }
            if next == 0 || offset + next >= frame.len() {
                break;
            }
            offset += next;
        }
        if !responses.is_empty() {
            let mut combined = Vec::new();
            for (i, resp) in responses.iter().enumerate() {
                let mut chunk = resp.clone();
                if i + 1 < responses.len() {
                    chunk[20..24].copy_from_slice(&(resp.len() as u32).to_le_bytes());
                }
                combined.extend_from_slice(&chunk);
            }

            write_nbss_frame(&mut stream, &combined)?;
        }
    }
}
