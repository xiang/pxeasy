use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

mod handler;
pub mod proto;

pub const NBD_PORT: u16 = 10809;
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

pub struct NbdConfig {
    pub iso_path: PathBuf,
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
}

pub struct NbdServer {
    listener: TcpListener,
    iso_path: PathBuf,
    export_size: u64,
}

impl NbdServer {
    pub fn bind(config: NbdConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(config.bind_ip),
            config.bind_port,
        ))?;
        listener.set_nonblocking(true)?;

        let export_size = std::fs::metadata(&config.iso_path)?.len();

        Ok(Self {
            listener,
            iso_path: config.iso_path,
            export_size,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        let mut threads = Vec::new();

        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    if let Err(err) = stream.set_nonblocking(false) {
                        log::warn!("nbd: failed to set stream blocking: {}", err);
                        continue;
                    }

                    let iso_path = self.iso_path.clone();
                    let export_size = self.export_size;

                    let handle = thread::spawn(move || {
                        if let Err(err) = handler::handle(stream, iso_path, export_size) {
                            if err.kind() != io::ErrorKind::BrokenPipe
                                && err.kind() != io::ErrorKind::ConnectionReset
                                && err.kind() != io::ErrorKind::UnexpectedEof
                            {
                                log::warn!("nbd: connection failed: {}", err);
                            }
                        }
                    });
                    threads.push(handle);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(SHUTDOWN_POLL);
                }
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
}

/// Open `iso_path` as an NBD export on `server_ip:NBD_PORT`.
pub fn open(iso_path: &Path, bind_ip: Ipv4Addr) -> io::Result<NbdServer> {
    NbdServer::bind(NbdConfig {
        iso_path: iso_path.to_path_buf(),
        bind_ip,
        bind_port: NBD_PORT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_report_local_addr() {
        let dir = tempfile::tempdir().unwrap();
        let iso = dir.path().join("test.iso");
        std::fs::write(&iso, vec![0u8; 512]).unwrap();

        let server = NbdServer::bind(NbdConfig {
            iso_path: iso,
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 0,
        })
        .unwrap();

        let addr = server.local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn export_size_matches_file() {
        let dir = tempfile::tempdir().unwrap();
        let iso = dir.path().join("test.iso");
        std::fs::write(&iso, vec![0xABu8; 4096]).unwrap();

        let server = NbdServer::bind(NbdConfig {
            iso_path: iso,
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 0,
        })
        .unwrap();

        assert_eq!(server.export_size, 4096);
    }
}
