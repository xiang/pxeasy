use std::{
    fs::File,
    io::{self, Read, Write},
    net::TcpStream,
    path::PathBuf,
};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use crate::proto::*;

pub fn handle(mut stream: TcpStream, iso_path: PathBuf, export_size: u64) -> io::Result<()> {
    // Handshake
    stream.write_all(&NBDMAGIC.to_be_bytes())?;
    stream.write_all(&IHAVEOPT.to_be_bytes())?;
    let server_flags: u16 = FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES;
    stream.write_all(&server_flags.to_be_bytes())?;

    let mut client_flags_buf = [0u8; 4];
    stream.read_exact(&mut client_flags_buf)?;
    let client_flags = u32::from_be_bytes(client_flags_buf);
    let no_zeroes = (client_flags & CLIENT_FLAG_NO_ZEROES) != 0;

    // Option haggling
    loop {
        let mut magic_buf = [0u8; 8];
        stream.read_exact(&mut magic_buf)?;
        if u64::from_be_bytes(magic_buf) != IHAVEOPT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad option magic"));
        }

        let mut opt_buf = [0u8; 4];
        stream.read_exact(&mut opt_buf)?;
        let opt = u32::from_be_bytes(opt_buf);

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let data_len = u32::from_be_bytes(len_buf) as usize;

        // Read and discard option data (we don't need export names — single export)
        let mut opt_data = vec![0u8; data_len];
        stream.read_exact(&mut opt_data)?;

        match opt {
            OPT_EXPORT_NAME => {
                // Legacy: no reply, just send export info and enter transmission
                send_export_info(&mut stream, export_size, no_zeroes)?;
                break;
            }
            OPT_GO | OPT_INFO => {
                send_opt_reply_info(&mut stream, opt, export_size)?;
                send_opt_reply(&mut stream, opt, REP_ACK, &[])?;
                if opt == OPT_GO {
                    break;
                }
            }
            OPT_LIST => {
                // Advertise one unnamed export
                let name = b"";
                let mut payload = Vec::with_capacity(4 + name.len());
                payload.extend_from_slice(&(name.len() as u32).to_be_bytes());
                payload.extend_from_slice(name);
                send_opt_reply(&mut stream, OPT_LIST, REP_SERVER, &payload)?;
                send_opt_reply(&mut stream, OPT_LIST, REP_ACK, &[])?;
            }
            OPT_ABORT => {
                send_opt_reply(&mut stream, OPT_ABORT, REP_ACK, &[])?;
                return Ok(());
            }
            _ => {
                send_opt_reply(&mut stream, opt, REP_ERR_UNSUP, &[])?;
            }
        }
    }

    // Transmission phase
    let file = File::open(&iso_path)?;
    transmission_loop(&mut stream, &file, export_size)
}

fn send_export_info(stream: &mut TcpStream, export_size: u64, no_zeroes: bool) -> io::Result<()> {
    stream.write_all(&export_size.to_be_bytes())?;
    let flags: u16 = TRANS_HAS_FLAGS | TRANS_READ_ONLY;
    stream.write_all(&flags.to_be_bytes())?;
    if !no_zeroes {
        stream.write_all(&[0u8; 124])?;
    }
    Ok(())
}

fn send_opt_reply_info(stream: &mut TcpStream, opt: u32, export_size: u64) -> io::Result<()> {
    // NBD_REP_INFO with NBD_INFO_EXPORT: info_type(u16) + export_size(u64) + flags(u16) = 12 bytes
    let mut payload = [0u8; 12];
    payload[0..2].copy_from_slice(&INFO_EXPORT.to_be_bytes());
    payload[2..10].copy_from_slice(&export_size.to_be_bytes());
    let flags: u16 = TRANS_HAS_FLAGS | TRANS_READ_ONLY;
    payload[10..12].copy_from_slice(&flags.to_be_bytes());
    send_opt_reply(stream, opt, REP_INFO, &payload)
}

fn send_opt_reply(stream: &mut TcpStream, opt: u32, reply_type: u32, data: &[u8]) -> io::Result<()> {
    stream.write_all(&OPTS_REPLY_MAGIC.to_be_bytes())?;
    stream.write_all(&opt.to_be_bytes())?;
    stream.write_all(&reply_type.to_be_bytes())?;
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

fn transmission_loop(stream: &mut TcpStream, file: &File, export_size: u64) -> io::Result<()> {
    let mut req = [0u8; 28];
    loop {
        stream.read_exact(&mut req)?;

        let magic = u32::from_be_bytes(req[0..4].try_into().unwrap());
        if magic != REQUEST_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request magic"));
        }

        // flags: req[4..6] — not needed for read-only
        let cmd = u16::from_be_bytes(req[6..8].try_into().unwrap());
        let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
        let offset = u64::from_be_bytes(req[16..24].try_into().unwrap());
        let length = u32::from_be_bytes(req[24..28].try_into().unwrap()) as u64;

        match cmd {
            CMD_READ => {
                if offset.saturating_add(length) > export_size {
                    send_reply(stream, NBD_EINVAL, handle, &[])?;
                    continue;
                }
                let mut buf = vec![0u8; length as usize];
                match read_at(file, &mut buf, offset) {
                    Ok(()) => send_reply(stream, NBD_OK, handle, &buf)?,
                    Err(_) => send_reply(stream, NBD_EIO, handle, &[])?,
                }
            }
            CMD_WRITE => {
                // Read and discard write data, then return EPERM
                let mut discard = vec![0u8; length as usize];
                stream.read_exact(&mut discard)?;
                send_reply(stream, NBD_EPERM, handle, &[])?;
            }
            CMD_DISC => return Ok(()),
            _ => {
                send_reply(stream, NBD_EINVAL, handle, &[])?;
            }
        }
    }
}

fn send_reply(stream: &mut TcpStream, error: u32, handle: u64, data: &[u8]) -> io::Result<()> {
    stream.write_all(&SIMPLE_REPLY_MAGIC.to_be_bytes())?;
    stream.write_all(&error.to_be_bytes())?;
    stream.write_all(&handle.to_be_bytes())?;
    if !data.is_empty() {
        stream.write_all(data)?;
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut pos = offset;
    let mut remaining = buf;
    while !remaining.is_empty() {
        let n = file.seek_read(remaining, pos)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
        }
        pos += n as u64;
        remaining = &mut remaining[n..];
    }
    Ok(())
}
