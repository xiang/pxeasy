/// Mount protocol v3 — program 100005, port 20048.
///
/// Implements NULL (0), MNT (1), DUMP (2), and EXPORT (5). Returns the root
/// file handle for the export path and advertises AUTH_NULL as the only
/// supported flavor.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use crate::nfs3::id_to_fh;
use crate::rpc::{
    self, build_accepted_reply, build_proc_unavail_reply, parse_call, write_record, Reader, Writer,
};

const PROG_MOUNT: u32 = 100005;

const PROC_NULL: u32 = 0;
const PROC_MNT: u32 = 1;
const PROC_DUMP: u32 = 2;
const PROC_EXPORT: u32 = 5;

const MNT_OK: u32 = 0;
const MNT_ERR_ACCES: u32 = 13;

const AUTH_NULL: u32 = 0;

pub struct MountServer {
    listener: TcpListener,
    export_path: String,
    root_fh: Vec<u8>,
}

impl MountServer {
    pub fn bind(ip: Ipv4Addr, export_path: &str, root_id: u64) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(ip),
            crate::portmap::MOUNT_PORT as u16,
        ))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            export_path: export_path.to_string(),
            root_fh: id_to_fh(root_id),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    let _ = stream.set_nonblocking(false);
                    let export = self.export_path.clone();
                    let fh = self.root_fh.clone();
                    thread::spawn(move || handle_client(stream, export, fh));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(crate::SHUTDOWN_POLL);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn handle_client(mut stream: TcpStream, export_path: String, root_fh: Vec<u8>) {
    while let Ok(buf) = rpc::read_record(&mut stream) {
        let call = match parse_call(&buf) {
            Some(c) => c,
            None => break,
        };
        if call.prog != PROG_MOUNT {
            log::debug!("[nfs/mount] unknown prog={} proc={}", call.prog, call.proc);
            let _ = write_record(&mut stream, &build_proc_unavail_reply(call.xid));
            continue;
        }
        let reply = match call.proc {
            PROC_NULL => build_accepted_reply(call.xid, &[]),
            PROC_MNT => {
                if log::log_enabled!(log::Level::Debug) {
                    let mut r = Reader::new(&buf[call.args_offset..]);
                    let path = r.string().unwrap_or("<bad>");
                    let clean = path.split(',').next().unwrap_or(path);
                    let accepted = clean == export_path
                        || clean.trim_end_matches('/') == export_path.trim_end_matches('/');
                    log::debug!(
                        "[nfs/mount] MNT {path:?} → {}",
                        if accepted { "OK" } else { "ACCES" }
                    );
                }
                handle_mnt(&buf[call.args_offset..], call.xid, &export_path, &root_fh)
            }
            PROC_DUMP => handle_dump(call.xid),
            PROC_EXPORT => {
                log::debug!("[nfs/mount] EXPORT → {export_path}");
                handle_export(call.xid, &export_path)
            }
            _ => {
                log::debug!("[nfs/mount] proc_unavail proc={}", call.proc);
                build_proc_unavail_reply(call.xid)
            }
        };
        if write_record(&mut stream, &reply).is_err() {
            break;
        }
    }
}

fn handle_mnt(args: &[u8], xid: u32, export_path: &str, root_fh: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(args);
    let path = match r.string() {
        Some(p) => p,
        None => {
            let mut w = Writer::new();
            w.u32(MNT_ERR_ACCES);
            return build_accepted_reply(xid, &w.into_bytes());
        }
    };

    // Strip mount options that some clients append to the path (e.g. "/arm64,vers=3,proto=tcp").
    let path = path.split(',').next().unwrap_or(path);

    // Accept exact match or with trailing slash stripped.
    let accepted =
        path == export_path || path.trim_end_matches('/') == export_path.trim_end_matches('/');

    let mut w = Writer::new();
    if accepted {
        w.u32(MNT_OK);
        w.opaque(root_fh); // fhandle3
                           // auth_flavors: list of uint32 [AUTH_NULL]
        w.u32(1); // list length
        w.u32(AUTH_NULL);
    } else {
        w.u32(MNT_ERR_ACCES);
    }
    build_accepted_reply(xid, &w.into_bytes())
}

fn handle_dump(xid: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(0); // no mount list entries
    build_accepted_reply(xid, &w.into_bytes())
}

fn handle_export(xid: u32, export_path: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(1); // one export entry
    w.string(export_path);
    w.u32(0); // groups list: null
    w.u32(0); // next export: null
    build_accepted_reply(xid, &w.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{self, Reader};

    #[test]
    fn mnt_strips_client_options_from_path() {
        let root_fh = vec![0u8; 32];
        // Client sends "/arm64,vers=3,proto=tcp" — options must be stripped.
        let mut args = crate::rpc::Writer::new();
        args.string("/arm64,vers=3,proto=tcp");
        let reply = handle_mnt(&args.into_bytes(), 1, "/arm64", &root_fh);
        let mut r = Reader::new(&reply);
        // Skip RPC header to status field.
        for _ in 0..6 {
            r.u32();
        }
        assert_eq!(r.u32(), Some(MNT_OK));
    }

    #[test]
    fn export_reply_includes_export_path() {
        let reply = handle_export(0x1234_5678, "/ubuntu-live");
        let mut r = Reader::new(&reply);
        assert_eq!(r.u32(), Some(0x1234_5678));
        assert_eq!(r.u32(), Some(rpc::REPLY));
        assert_eq!(r.u32(), Some(rpc::MSG_ACCEPTED));
        assert_eq!(r.u32(), Some(rpc::AUTH_NULL));
        assert_eq!(r.u32(), Some(0));
        assert_eq!(r.u32(), Some(rpc::SUCCESS));
        assert_eq!(r.u32(), Some(1));
        assert_eq!(r.string(), Some("/ubuntu-live"));
        assert_eq!(r.u32(), Some(0));
        assert_eq!(r.u32(), Some(0));
    }
}
