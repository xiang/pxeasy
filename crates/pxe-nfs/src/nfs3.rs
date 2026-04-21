/// NFS v3 server — program 100003 version 3, port 2049.
///
/// Implements the read-only procedures needed to serve an ISO filesystem
/// to a casper/live-boot client: NULL, GETATTR, LOOKUP, ACCESS, READ,
/// READDIR, READDIRPLUS, FSSTAT, FSINFO, PATHCONF.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use crate::rpc::{
    self, build_accepted_reply, build_proc_unavail_reply, parse_call, write_record, Reader, Writer,
};
use crate::vfs::{FileAttr, NodeKind, Vfs};

const PROG_NFS: u32 = 100003;

const PROC_NULL: u32 = 0;
const PROC_GETATTR: u32 = 1;
const PROC_LOOKUP: u32 = 3;
const PROC_ACCESS: u32 = 4;
const PROC_READLINK: u32 = 5;
const PROC_READ: u32 = 6;
const PROC_READDIR: u32 = 16;
const PROC_READDIRPLUS: u32 = 17;
const PROC_FSSTAT: u32 = 18;
const PROC_FSINFO: u32 = 19;
const PROC_PATHCONF: u32 = 20;

// NFS v3 status codes
const NFS3_OK: u32 = 0;
const NFS3ERR_NOENT: u32 = 2;
const NFS3ERR_NOTDIR: u32 = 20;
const NFS3ERR_ISDIR: u32 = 21;
const NFS3ERR_INVAL: u32 = 22;
const NFS3ERR_BADHANDLE: u32 = 10001;
const NFS3ERR_SERVERFAULT: u32 = 10006;

const NF3REG: u32 = 1;
const NF3DIR: u32 = 2;
const NF3LNK: u32 = 5;

const ACCESS_READ: u32 = 0x0001;
const ACCESS_LOOKUP: u32 = 0x0002;
const ACCESS_EXECUTE: u32 = 0x0020;

const FSF3_HOMOGENEOUS: u32 = 0x0008;
// Fixed cookie verifier (VFS never changes)
const COOKIE_VERF: u64 = 0x7078_656e_6673_0000; // "pxenfs\0\0"

/// Encode a node ID into a 32-byte NFS file handle.
pub fn id_to_fh(id: u64) -> Vec<u8> {
    let mut fh = vec![0u8; 32];
    fh[0..8].copy_from_slice(&id.to_be_bytes());
    fh
}

/// Decode a node ID from an NFS file handle.
fn fh_to_id(fh: &[u8]) -> Option<u64> {
    if fh.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(fh[0..8].try_into().unwrap()))
}

fn write_fattr3(w: &mut Writer, attr: &FileAttr) {
    let (ftype, mode, used) = match attr.kind {
        NodeKind::Dir => (NF3DIR, 0o755, 4096),
        NodeKind::File => (NF3REG, 0o444, attr.size),
        NodeKind::Symlink => (NF3LNK, 0o777, attr.size),
    };
    w.u32(ftype);
    w.u32(mode);
    w.u32(attr.nlink);
    w.u32(0); // uid
    w.u32(0); // gid
    w.u64(attr.size);
    w.u64(used);
    w.u32(0);
    w.u32(0); // rdev specdata3
    w.u64(1); // fsid
    w.u64(attr.id);
    // atime / mtime / ctime (seconds + nanoseconds, all zero)
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
}

fn write_post_op_attr(w: &mut Writer, attr: Option<&FileAttr>) {
    match attr {
        Some(a) => {
            w.u32(1); // attributes_follow = TRUE
            write_fattr3(w, a);
        }
        None => w.u32(0),
    }
}

pub struct NfsServer {
    listener: TcpListener,
    vfs: Arc<Vfs>,
}

impl NfsServer {
    pub fn bind(ip: Ipv4Addr, vfs: Arc<Vfs>) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(ip),
            crate::portmap::NFS_PORT as u16,
        ))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, vfs })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    let _ = stream.set_nonblocking(false);
                    let vfs = Arc::clone(&self.vfs);
                    thread::spawn(move || handle_client(stream, vfs));
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

fn handle_client(mut stream: TcpStream, vfs: Arc<Vfs>) {
    while let Ok(buf) = rpc::read_record(&mut stream) {
        let call = match parse_call(&buf) {
            Some(c) => c,
            None => break,
        };
        if call.prog != PROG_NFS {
            log::debug!("[nfs/nfsd] unknown prog={} proc={}", call.prog, call.proc);
            let _ = write_record(&mut stream, &build_proc_unavail_reply(call.xid));
            continue;
        }
        let args = &buf[call.args_offset..];
        let reply = dispatch(call.xid, call.proc, args, &vfs);
        if write_record(&mut stream, &reply).is_err() {
            break;
        }
    }
}

fn dispatch(xid: u32, proc: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    match proc {
        PROC_NULL => build_accepted_reply(xid, &[]),
        PROC_GETATTR => proc_getattr(xid, args, vfs),
        PROC_LOOKUP => proc_lookup(xid, args, vfs),
        PROC_ACCESS => proc_access(xid, args, vfs),
        PROC_READLINK => proc_readlink(xid, args, vfs),
        PROC_READ => proc_read(xid, args, vfs),
        PROC_READDIR => proc_readdir(xid, args, vfs),
        PROC_READDIRPLUS => proc_readdirplus(xid, args, vfs),
        PROC_FSSTAT => proc_fsstat(xid, args, vfs),
        PROC_FSINFO => proc_fsinfo(xid, args, vfs),
        PROC_PATHCONF => proc_pathconf(xid, args, vfs),
        _ => {
            log::debug!("[nfs/nfsd] proc_unavail proc={proc}");
            build_proc_unavail_reply(xid)
        }
    }
}

// ---------------------------------------------------------------------------
// Procedure implementations
// ---------------------------------------------------------------------------

fn proc_getattr(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let id = match fh_to_id(fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let attr = match vfs.getattr(id) {
        Some(a) => a,
        None => {
            log::trace!("[nfs/nfsd] GETATTR id={id} → NOENT");
            return err_reply(xid, NFS3ERR_NOENT);
        }
    };
    let kind = match attr.kind {
        NodeKind::Dir => "dir",
        NodeKind::File => "file",
        NodeKind::Symlink => "symlink",
    };
    log::trace!("[nfs/nfsd] GETATTR id={id} → {kind} size={}", attr.size);
    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_fattr3(&mut w, &attr);
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_lookup(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let dir_fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let name = match r.string() {
        Some(n) => n,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };

    let dir_id = match fh_to_id(dir_fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let dir_attr = vfs.getattr(dir_id);
    if dir_attr.as_ref().is_none_or(|a| a.kind != NodeKind::Dir) {
        let mut w = Writer::new();
        w.u32(NFS3ERR_NOTDIR);
        write_post_op_attr(&mut w, dir_attr.as_ref());
        return build_accepted_reply(xid, &w.into_bytes());
    }

    let child_id = match vfs.lookup(dir_id, name) {
        Some(id) => id,
        None => {
            log::trace!("[nfs/nfsd] LOOKUP dir={dir_id} {name:?} → NOENT");
            let mut w = Writer::new();
            w.u32(NFS3ERR_NOENT);
            write_post_op_attr(&mut w, dir_attr.as_ref());
            return build_accepted_reply(xid, &w.into_bytes());
        }
    };
    log::trace!("[nfs/nfsd] LOOKUP dir={dir_id} {name:?} → id={child_id}");
    let child_attr = vfs.getattr(child_id);
    let child_fh = id_to_fh(child_id);

    let mut w = Writer::new();
    w.u32(NFS3_OK);
    w.opaque(&child_fh); // object fh (nfs_fh3 — no handle_follows discriminant)
    write_post_op_attr(&mut w, child_attr.as_ref()); // obj_attributes
    write_post_op_attr(&mut w, dir_attr.as_ref()); // dir_attributes
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_access(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let requested = r.u32().unwrap_or(0);

    let id = match fh_to_id(fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let attr = match vfs.getattr(id) {
        Some(a) => a,
        None => return err_reply(xid, NFS3ERR_NOENT),
    };
    let mut allowed = 0;
    if requested & ACCESS_READ != 0 {
        allowed |= ACCESS_READ;
    }
    if attr.kind == NodeKind::Dir {
        if requested & ACCESS_LOOKUP != 0 {
            allowed |= ACCESS_LOOKUP;
        }
    } else {
        if requested & ACCESS_EXECUTE != 0 {
            allowed |= ACCESS_EXECUTE;
        }
    }

    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, Some(&attr));
    w.u32(allowed);
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_readlink(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };

    let id = match fh_to_id(fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let attr = vfs.getattr(id);
    let target = match vfs.readlink(id) {
        Some(target) => target,
        None => {
            let mut w = Writer::new();
            w.u32(NFS3ERR_INVAL);
            write_post_op_attr(&mut w, attr.as_ref());
            return build_accepted_reply(xid, &w.into_bytes());
        }
    };

    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, attr.as_ref());
    w.string(target);
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_read(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let offset = r.u64().unwrap_or(0);
    let count = r.u32().unwrap_or(0);

    let id = match fh_to_id(fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };

    let attr = vfs.getattr(id);
    if attr.as_ref().is_some_and(|a| a.kind == NodeKind::Dir) {
        let mut w = Writer::new();
        w.u32(NFS3ERR_ISDIR);
        write_post_op_attr(&mut w, attr.as_ref());
        return build_accepted_reply(xid, &w.into_bytes());
    }

    // Cap reads to 1 MiB to bound memory usage per request
    let count = count.min(1024 * 1024);

    let (data, eof) = match vfs.read_file(id, offset, count) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[nfs/nfsd] READ id={id} off={offset} count={count} → error: {e}");
            if e.kind() == std::io::ErrorKind::NotFound {
                return err_reply(xid, NFS3ERR_NOENT);
            }
            let mut w = Writer::new();
            w.u32(if e.kind() == std::io::ErrorKind::InvalidInput {
                NFS3ERR_INVAL
            } else {
                NFS3ERR_SERVERFAULT
            });
            write_post_op_attr(&mut w, attr.as_ref());
            return build_accepted_reply(xid, &w.into_bytes());
        }
    };
    log::trace!(
        "[nfs/nfsd] READ id={id} off={offset} count={count} → {} bytes eof={eof}",
        data.len()
    );

    // Re-fetch attr after read (size may differ from pre-read attr for large files, but it's static)
    let attr = vfs.getattr(id);
    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, attr.as_ref());
    w.u32(data.len() as u32); // count
    w.u32(u32::from(eof)); // eof
    w.opaque(&data); // data
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_readdir(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let cookie = r.u64().unwrap_or(0) as usize;
    let _cookieverf = r.u64();
    let count = r.u32().unwrap_or(4096) as usize;

    let id = match fh_to_id(fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let dir_attr = vfs.getattr(id);
    let entries = match vfs.readdir(id, cookie) {
        Some(e) => e,
        None => {
            let mut w = Writer::new();
            w.u32(NFS3ERR_NOTDIR);
            write_post_op_attr(&mut w, dir_attr.as_ref());
            return build_accepted_reply(xid, &w.into_bytes());
        }
    };

    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, dir_attr.as_ref());
    w.u64(COOKIE_VERF);

    // Each entry: value_follows(4) + fileid(8) + name(4+n+pad) + cookie(8)
    // Overhead estimate: ~32 bytes fixed overhead in reply (status+attrs+verf+eof)
    let mut used: usize = 64;
    let mut n_emitted = 0;

    for (idx, (name, child_id)) in entries.iter().enumerate() {
        let entry_size = 4 + 8 + 4 + ((name.len() + 3) & !3) + 8;
        if used + entry_size + 8 > count {
            break;
        }
        used += entry_size;
        w.u32(1); // value_follows
        w.u64(*child_id); // fileid
        w.string(name); // name
        w.u64((cookie + idx + 1) as u64); // cookie
        n_emitted += 1;
    }
    w.u32(0); // no more entries
    w.u32(u32::from(n_emitted == entries.len())); // eof
    log::trace!(
        "[nfs/nfsd] READDIR id={id} cookie={cookie} → {n_emitted}/{} entries",
        entries.len()
    );
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_readdirplus(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let cookie = r.u64().unwrap_or(0) as usize;
    let _cookieverf = r.u64();
    let _dircount = r.u32().unwrap_or(4096);
    let maxcount = r.u32().unwrap_or(8192) as usize;

    let id = match fh_to_id(fh) {
        Some(id) => id,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let dir_attr = vfs.getattr(id);
    let entries = match vfs.readdir(id, cookie) {
        Some(e) => e,
        None => {
            let mut w = Writer::new();
            w.u32(NFS3ERR_NOTDIR);
            write_post_op_attr(&mut w, dir_attr.as_ref());
            return build_accepted_reply(xid, &w.into_bytes());
        }
    };

    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, dir_attr.as_ref());
    w.u64(COOKIE_VERF);

    // Each entry: value_follows(4) + fileid(8) + name(4+n+pad) + cookie(8)
    //           + name_attributes(post_op_attr: 4+84) + name_handle(post_op_fh3: 4+4+32)
    let fattr_size = 84; // 21 u32 fields
    let mut used: usize = 64;
    let mut n_emitted = 0;

    for (idx, (name, child_id)) in entries.iter().enumerate() {
        let name_padded = (name.len() + 3) & !3;
        let entry_size = 4 + 8 + 4 + name_padded + 8 + (4 + fattr_size) + (4 + 4 + 32);
        if used + entry_size + 8 > maxcount {
            break;
        }
        used += entry_size;

        let child_attr = vfs.getattr(*child_id);
        let child_fh = id_to_fh(*child_id);

        w.u32(1); // value_follows
        w.u64(*child_id); // fileid
        w.string(name); // name
        w.u64((cookie + idx + 1) as u64); // cookie
        write_post_op_attr(&mut w, child_attr.as_ref()); // name_attributes
                                                         // name_handle (post_op_fh3)
        w.u32(1); // handle_follows = TRUE
        w.opaque(&child_fh);
        n_emitted += 1;
    }
    w.u32(0); // no more entries
    w.u32(u32::from(n_emitted == entries.len())); // eof
    log::trace!(
        "[nfs/nfsd] READDIRPLUS id={id} cookie={cookie} → {n_emitted}/{} entries",
        entries.len()
    );
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_fsstat(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let id = fh_to_id(fh).unwrap_or(0);
    let attr = vfs.getattr(id);

    let total_files = vfs.node_count();
    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, attr.as_ref());
    // tbytes, fbytes, abytes — report as read-only, no free space
    w.u64(u64::MAX / 2); // tbytes
    w.u64(0); // fbytes
    w.u64(0); // abytes
              // tfiles, ffiles, afiles
    w.u64(total_files);
    w.u64(0);
    w.u64(0);
    w.u32(0); // invarsec
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_fsinfo(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let id = fh_to_id(fh).unwrap_or(0);
    let attr = vfs.getattr(id);

    let read_max: u32 = 1024 * 1024; // 1 MiB max read
    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, attr.as_ref());
    w.u32(read_max); // rtmax
    w.u32(read_max); // rtpref
    w.u32(512); // rtmult
    w.u32(0); // wtmax (read-only)
    w.u32(0); // wtpref
    w.u32(512); // wtmult
    w.u32(4096); // dtpref
    w.u64(u64::MAX / 2); // maxfilesize
                         // time_delta: 1 second resolution
    w.u32(1);
    w.u32(0);
    // properties: HOMOGENEOUS only. This server does not support changing metadata.
    w.u32(FSF3_HOMOGENEOUS);
    build_accepted_reply(xid, &w.into_bytes())
}

fn proc_pathconf(xid: u32, args: &[u8], vfs: &Vfs) -> Vec<u8> {
    let mut r = Reader::new(args);
    let fh = match r.opaque() {
        Some(f) => f,
        None => return err_reply(xid, NFS3ERR_BADHANDLE),
    };
    let id = fh_to_id(fh).unwrap_or(0);
    let attr = vfs.getattr(id);

    let mut w = Writer::new();
    w.u32(NFS3_OK);
    write_post_op_attr(&mut w, attr.as_ref());
    w.u32(0); // linkmax (no hard links)
    w.u32(255); // name_max
    w.u32(1); // no_trunc = TRUE
    w.u32(0); // chown_restricted = FALSE
    w.u32(0); // case_insensitive = FALSE
    w.u32(1); // case_preserving = TRUE
    build_accepted_reply(xid, &w.into_bytes())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn err_reply(xid: u32, status: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(status);
    // post_op_attr = FALSE for error replies without context
    w.u32(0);
    build_accepted_reply(xid, &w.into_bytes())
}
