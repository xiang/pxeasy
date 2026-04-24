use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub mod iso;
pub mod login;
pub mod pdu;
pub mod scsi;
pub mod session;

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub struct SessionTrace {
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    target_iqn: String,
    media_kind: MediaKind,
    started_at: Instant,
    last_activity_at: Instant,
    login_requests: u64,
    discovery_texts: u64,
    full_feature_pdus: u64,
    nop_outs: u64,
    logout_requests: u64,
    scsi_commands: u64,
    test_unit_ready: u64,
    inquiry: u64,
    read_capacity_10: u64,
    read_capacity_16: u64,
    request_sense: u64,
    synchronize_cache_10: u64,
    read_ops: u64,
    read_blocks: u64,
    read_bytes: u64,
    write_ops: u64,
    write_blocks: u64,
    write_bytes: u64,
}

impl SessionTrace {
    pub(crate) fn new(
        peer_addr: SocketAddr,
        target_addr: SocketAddr,
        target_iqn: String,
        media_kind: MediaKind,
    ) -> Self {
        let now = Instant::now();
        Self {
            peer_addr,
            target_addr,
            target_iqn,
            media_kind,
            started_at: now,
            last_activity_at: now,
            login_requests: 0,
            discovery_texts: 0,
            full_feature_pdus: 0,
            nop_outs: 0,
            logout_requests: 0,
            scsi_commands: 0,
            test_unit_ready: 0,
            inquiry: 0,
            read_capacity_10: 0,
            read_capacity_16: 0,
            request_sense: 0,
            synchronize_cache_10: 0,
            read_ops: 0,
            read_blocks: 0,
            read_bytes: 0,
            write_ops: 0,
            write_blocks: 0,
            write_bytes: 0,
        }
    }

    pub(crate) fn note_activity(&mut self) {
        self.last_activity_at = Instant::now();
    }

    pub(crate) fn note_login_request(&mut self) {
        self.login_requests += 1;
        self.note_activity();
    }

    pub(crate) fn note_discovery_text(&mut self) {
        self.discovery_texts += 1;
        self.note_activity();
    }

    pub(crate) fn note_nop_out(&mut self) {
        self.full_feature_pdus += 1;
        self.nop_outs += 1;
        self.note_activity();
    }

    pub(crate) fn note_logout_request(&mut self) {
        self.logout_requests += 1;
        self.note_activity();
    }

    pub(crate) fn note_scsi_command(
        &mut self,
        opcode: u8,
        blocks: Option<u32>,
        block_size: u32,
        write: bool,
    ) {
        self.full_feature_pdus += 1;
        self.scsi_commands += 1;
        self.note_activity();

        match opcode {
            scsi::op::TEST_UNIT_READY => self.test_unit_ready += 1,
            scsi::op::INQUIRY => self.inquiry += 1,
            scsi::op::READ_CAPACITY_10 => self.read_capacity_10 += 1,
            scsi::op::SERVICE_ACTION_IN_16 => self.read_capacity_16 += 1,
            scsi::op::REQUEST_SENSE => self.request_sense += 1,
            scsi::op::SYNCHRONIZE_CACHE_10 => self.synchronize_cache_10 += 1,
            scsi::op::READ_10 | scsi::op::READ_16 => {
                self.read_ops += 1;
                if let Some(blocks) = blocks {
                    self.read_blocks += u64::from(blocks);
                    self.read_bytes += u64::from(blocks) * u64::from(block_size);
                }
            }
            scsi::op::WRITE_10 | scsi::op::WRITE_16 if write => {
                self.write_ops += 1;
                if let Some(blocks) = blocks {
                    self.write_blocks += u64::from(blocks);
                    self.write_bytes += u64::from(blocks) * u64::from(block_size);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn note_session_outcome(&mut self, outcome: &login::SessionOutcome) {
        self.note_activity();
        log::info!(
            "session established peer={} target={} media_kind={:?} outcome={:?}",
            self.peer_addr,
            self.target_iqn,
            self.media_kind,
            outcome
        );
    }

    pub(crate) fn log_open(&self) {
        log::info!(
            "connection opened peer={} local={} target={} media_kind={:?}",
            self.peer_addr,
            self.target_addr,
            self.target_iqn,
            self.media_kind
        );
    }

    pub(crate) fn log_close(&self, result: &io::Result<()>) {
        let elapsed = self.started_at.elapsed();
        let idle = self.last_activity_at.elapsed();
        match result {
            Ok(()) => log::info!(
                "connection closed peer={} target={} duration_ms={} idle_ms={} login={} discovery={} full_feature_pdus={} scsi={} tur={} inquiry={} rc10={} rc16={} sense={} sync_cache={} reads={} read_blocks={} read_bytes={} writes={} write_blocks={} write_bytes={} nop_outs={} logouts={}",
                self.peer_addr,
                self.target_iqn,
                elapsed.as_millis(),
                idle.as_millis(),
                self.login_requests,
                self.discovery_texts,
                self.full_feature_pdus,
                self.scsi_commands,
                self.test_unit_ready,
                self.inquiry,
                self.read_capacity_10,
                self.read_capacity_16,
                self.request_sense,
                self.synchronize_cache_10,
                self.read_ops,
                self.read_blocks,
                self.read_bytes,
                self.write_ops,
                self.write_blocks,
                self.write_bytes,
                self.nop_outs,
                self.logout_requests
            ),
            Err(err) => log::warn!(
                "connection failed peer={} target={} duration_ms={} idle_ms={} error={} login={} discovery={} full_feature_pdus={} scsi={} tur={} inquiry={} rc10={} rc16={} sense={} sync_cache={} reads={} read_blocks={} read_bytes={} writes={} write_blocks={} write_bytes={} nop_outs={} logouts={}",
                self.peer_addr,
                self.target_iqn,
                elapsed.as_millis(),
                idle.as_millis(),
                err,
                self.login_requests,
                self.discovery_texts,
                self.full_feature_pdus,
                self.scsi_commands,
                self.test_unit_ready,
                self.inquiry,
                self.read_capacity_10,
                self.read_capacity_16,
                self.request_sense,
                self.synchronize_cache_10,
                self.read_ops,
                self.read_blocks,
                self.read_bytes,
                self.write_ops,
                self.write_blocks,
                self.write_bytes,
                self.nop_outs,
                self.logout_requests
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Optical,
    Disk,
}

#[derive(Debug, Clone)]
pub struct IscsiConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    pub target_iqn: String,
    pub iso_path: PathBuf,
    pub media_kind: MediaKind,
}

pub struct IscsiTarget {
    listener: TcpListener,
    target_iqn: String,
    iso: Arc<iso::IsoLun>,
    media_kind: MediaKind,
}

impl IscsiTarget {
    pub fn bind(config: IscsiConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(config.bind_ip),
            config.bind_port,
        ))?;
        listener.set_nonblocking(true)?;

        let block_size = match config.media_kind {
            MediaKind::Optical => iso::optical_block_size(),
            MediaKind::Disk => iso::disk_block_size(),
        };
        let iso = iso::IsoLun::open_with_block_size(&config.iso_path, block_size)?;

        Ok(Self {
            listener,
            target_iqn: config.target_iqn,
            iso: Arc::new(iso),
            media_kind: config.media_kind,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        // Thread handles are collected to prevent the JoinHandle from being
        // silently dropped (which would detach the thread). We don't join on
        // shutdown — in-flight connections finish naturally; the OS reaps them.
        let mut threads = Vec::new();

        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, peer_addr)) => {
                    if let Err(err) = stream.set_nonblocking(false) {
                        log::warn!("failed to set stream blocking: {}", err);
                        continue;
                    }

                    let iso = Arc::clone(&self.iso);
                    let target_iqn = self.target_iqn.clone();
                    let target_addr = self.listener.local_addr()?;
                    let media_kind = self.media_kind;

                    let handle = thread::spawn(move || {
                        let mut trace = SessionTrace::new(
                            peer_addr,
                            target_addr,
                            target_iqn.clone(),
                            media_kind,
                        );
                        trace.log_open();
                        let result = handle_connection(
                            stream,
                            iso,
                            target_iqn,
                            target_addr,
                            media_kind,
                            &mut trace,
                        );
                        let log_result = match &result {
                            Err(err)
                                if err.kind() == io::ErrorKind::BrokenPipe
                                    || err.kind() == io::ErrorKind::ConnectionReset
                                    || err.kind() == io::ErrorKind::UnexpectedEof =>
                            {
                                Ok(())
                            }
                            _ => result,
                        };
                        trace.log_close(&log_result);
                    });
                    threads.push(handle);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(SHUTDOWN_POLL_INTERVAL);
                }
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }
}

fn handle_connection(
    mut stream: TcpStream,
    iso: Arc<iso::IsoLun>,
    target_iqn: String,
    target_addr: SocketAddr,
    media_kind: MediaKind,
    trace: &mut SessionTrace,
) -> io::Result<()> {
    let mut login = login::LoginSession::new(target_iqn, target_addr);
    let outcome = session::run_login_phase(&mut stream, &mut login, trace)?;
    trace.note_session_outcome(&outcome);

    match outcome {
        login::SessionOutcome::Discovery => {
            session::run_discovery_session(&mut stream, &mut login, trace)?;
        }
        login::SessionOutcome::Normal {
            tsih: _,
            cmd_sn_start,
        } => {
            session::run_full_feature_session(
                &mut stream,
                &iso,
                cmd_sn_start,
                login.stat_sn(),
                media_kind,
                trace,
            )?;
        }
    }

    Ok(())
}

pub struct IscsiServer {
    target: IscsiTarget,
}

impl IscsiServer {
    pub fn bind(source_path: &Path, bind_ip: Ipv4Addr, label: &str) -> io::Result<Self> {
        Self::bind_with_media(source_path, bind_ip, label, MediaKind::Optical)
    }

    pub fn bind_with_media(
        source_path: &Path,
        bind_ip: Ipv4Addr,
        label: &str,
        media_kind: MediaKind,
    ) -> io::Result<Self> {
        let target_name = build_target_name(label);
        let target = IscsiTarget::bind(IscsiConfig {
            bind_ip,
            bind_port: 3260,
            target_iqn: target_name,
            iso_path: source_path.to_path_buf(),
            media_kind,
        })?;
        Ok(Self { target })
    }

    pub fn target_name(&self) -> &str {
        &self.target.target_iqn
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.target.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        self.target.serve_until_shutdown(shutdown)
    }
}

pub fn build_sanboot_script(
    bind_ip: Ipv4Addr,
    target_name: &str,
    lun: u32,
    boot_filename: Option<&str>,
) -> String {
    let filename_arg = boot_filename
        .map(|filename| format!(" --filename {filename}"))
        .unwrap_or_default();
    format!(
        "#!ipxe\nset keep-san 1\nsanboot --drive 0{filename_arg} iscsi:{bind_ip}:::{lun}:{target_name}\nexit\n"
    )
}

pub fn build_direct_boot_script(
    bind_ip: Ipv4Addr,
    http_port: u16,
    target_name: &str,
    lun: u32,
    serial_console: &str,
) -> String {
    format!(
        "#!ipxe\n\
         set keep-san 1\n\
         set initiator-iqn iqn.2010-04.org.ipxe:${{mac}}\n\
         sanhook --drive 0x80 iscsi:{bind_ip}:::{lun}:{target_name}\n\
         kernel http://{bind_ip}:{http_port}/boot/linux boot=casper ip=dhcp iscsi_initiator=${{initiator-iqn}} iscsi_target_name={target_name} iscsi_target_ip={bind_ip} iscsi_target_port=3260 console=tty0 console={serial_console},115200n8\n\
         initrd http://{bind_ip}:{http_port}/boot/initrd\n\
         boot\n"
    )
}

fn build_target_name(label: &str) -> String {
    let mut slug = String::new();
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        slug.push_str("boot");
    }
    format!("iqn.2024-01.io.pxeasy:{slug}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_boot_script_hooks_iscsi_and_loads_kernel() {
        let script = build_direct_boot_script(
            Ipv4Addr::new(192, 168, 1, 10),
            8080,
            "iqn.2024-01.io.pxeasy:ubuntu",
            0,
            "ttyAMA0",
        );

        assert!(script
            .contains("sanhook --drive 0x80 iscsi:192.168.1.10:::0:iqn.2024-01.io.pxeasy:ubuntu"));
        assert!(script.contains("kernel http://192.168.1.10:8080/boot/linux"));
        assert!(script.contains("initrd http://192.168.1.10:8080/boot/initrd"));
        assert!(script.contains("iscsi_initiator=${initiator-iqn}"));
        assert!(script.contains("iscsi_target_name=iqn.2024-01.io.pxeasy:ubuntu"));
        assert!(script.contains("iscsi_target_ip=192.168.1.10"));
        assert!(script.contains("console=tty0 console=ttyAMA0,115200n8"));
    }

    #[test]
    fn sanboot_script_uses_provided_boot_filename() {
        let script = build_sanboot_script(
            Ipv4Addr::new(192, 168, 1, 10),
            "iqn.2024-01.io.pxeasy:freebsd",
            0,
            Some("\\boot\\loader.efi"),
        );

        assert!(script.contains(
            "sanboot --drive 0 --filename \\boot\\loader.efi iscsi:192.168.1.10:::0:iqn.2024-01.io.pxeasy:freebsd"
        ));
    }

    #[test]
    fn sanboot_script_can_use_platform_default_boot_filename() {
        let script = build_sanboot_script(
            Ipv4Addr::new(192, 168, 1, 10),
            "iqn.2024-01.io.pxeasy:freebsd",
            0,
            None,
        );

        assert_eq!(
            script,
            "#!ipxe\nset keep-san 1\nsanboot --drive 0 iscsi:192.168.1.10:::0:iqn.2024-01.io.pxeasy:freebsd\nexit\n"
        );
    }
}
