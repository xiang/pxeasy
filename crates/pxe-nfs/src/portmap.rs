/// Portmapper (rpcbind) — program 100000 version 2, port 111.
///
/// Only implements GETPORT (proc 3). Returns fixed ports for mountd and nfsd.
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

const PROG_PORTMAP: u32 = 100000;
const PROG_NFS: u32 = 100003;
const PROG_MOUNT: u32 = 100005;

const PROC_NULL: u32 = 0;
const PROC_GETPORT: u32 = 3;
const PROC_GETADDR: u32 = 3;

const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

pub const NFS_PORT: u32 = 2049;
pub const MOUNT_PORT: u32 = 20048;

pub struct PortmapServer {
    listener: TcpListener,
    bind_ip: Ipv4Addr,
}

impl PortmapServer {
    pub fn bind(ip: Ipv4Addr) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), 111))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            bind_ip: ip,
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
                    let bind_ip = self.bind_ip;
                    thread::spawn(move || handle_client(stream, bind_ip));
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

fn handle_client(mut stream: TcpStream, bind_ip: Ipv4Addr) {
    while let Ok(buf) = rpc::read_record(&mut stream) {
        let call = match parse_call(&buf) {
            Some(c) => c,
            None => break,
        };
        if call.prog != PROG_PORTMAP {
            log::debug!("unknown prog={} proc={}", call.prog, call.proc);
            let _ = write_record(&mut stream, &build_proc_unavail_reply(call.xid));
            continue;
        }
        let reply = match call.proc {
            PROC_NULL => build_accepted_reply(call.xid, &[]),
            PROC_GETPORT if call.vers == 2 => {
                if log::log_enabled!(log::Level::Debug) {
                    let mut r = Reader::new(&buf[call.args_offset..]);
                    let prog = r.u32().unwrap_or(0);
                    let vers = r.u32().unwrap_or(0);
                    let prot = r.u32().unwrap_or(0);
                    let proto = if prot == IPPROTO_TCP {
                        "tcp"
                    } else if prot == IPPROTO_UDP {
                        "udp"
                    } else {
                        "?"
                    };
                    let port = match prog {
                        PROG_NFS => NFS_PORT,
                        PROG_MOUNT => MOUNT_PORT,
                        PROG_PORTMAP => 111,
                        _ => 0,
                    };
                    log::debug!("getport prog={prog} vers={vers} prot={proto} -> {port}");
                }
                handle_getport(&buf[call.args_offset..], call.xid)
            }
            PROC_GETADDR if call.vers >= 3 => {
                if log::log_enabled!(log::Level::Debug) {
                    let mut r = Reader::new(&buf[call.args_offset..]);
                    let prog = r.u32().unwrap_or(0);
                    let vers = r.u32().unwrap_or(0);
                    let port = match prog {
                        PROG_NFS => NFS_PORT,
                        PROG_MOUNT => MOUNT_PORT,
                        PROG_PORTMAP => 111,
                        _ => 0,
                    };
                    log::debug!("getaddr prog={prog} vers={vers} -> port={port}");
                }
                handle_getaddr(&buf[call.args_offset..], call.xid, bind_ip)
            }
            _ => {
                log::debug!("proc_unavail proc={} vers={}", call.proc, call.vers);
                build_proc_unavail_reply(call.xid)
            }
        };
        if write_record(&mut stream, &reply).is_err() {
            break;
        }
    }
}

fn handle_getport(args: &[u8], xid: u32) -> Vec<u8> {
    let mut r = Reader::new(args);
    let prog = match r.u32() {
        Some(v) => v,
        None => return build_proc_unavail_reply(xid),
    };
    let _vers = r.u32().unwrap_or(0);
    let prot = r.u32().unwrap_or(0);
    let _port = r.u32().unwrap_or(0);

    let port: u32 = if prot != IPPROTO_TCP && prot != IPPROTO_UDP {
        0
    } else {
        match prog {
            PROG_NFS => NFS_PORT,
            PROG_MOUNT => MOUNT_PORT,
            PROG_PORTMAP => 111,
            _ => 0,
        }
    };

    let mut w = Writer::new();
    w.u32(port);
    build_accepted_reply(xid, &w.into_bytes())
}

fn handle_getaddr(args: &[u8], xid: u32, bind_ip: Ipv4Addr) -> Vec<u8> {
    let mut r = Reader::new(args);
    let prog = match r.u32() {
        Some(v) => v,
        None => return build_proc_unavail_reply(xid),
    };
    let _vers = r.u32().unwrap_or(0);
    let _netid = r.string().unwrap_or("");
    let _addr = r.string().unwrap_or("");
    let _owner = r.string().unwrap_or("");

    let port: u32 = match prog {
        PROG_NFS => NFS_PORT,
        PROG_MOUNT => MOUNT_PORT,
        PROG_PORTMAP => 111,
        _ => 0,
    };

    // Universal address format: "a.b.c.d.p1.p2" where port = p1*256 + p2.
    let uaddr = if port == 0 {
        "".to_string()
    } else {
        let [a, b, c, d] = bind_ip.octets();
        format!("{}.{}.{}.{}.{}.{}", a, b, c, d, port >> 8, port & 0xff)
    };

    let mut w = Writer::new();
    w.string(&uaddr);
    build_accepted_reply(xid, &w.into_bytes())
}
