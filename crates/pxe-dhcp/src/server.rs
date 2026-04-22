use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::builder;
use pxe_proto::{DhcpPacket, MessageType};

const DEFAULT_CLIENT_PORT: u16 = 68;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    pub server_ip: Ipv4Addr,
    pub http_port: u16,
    pub first_stage_bootfile: String,
    pub bios_bootfile: Option<String>,
    pub x64_uefi_bootfile: Option<String>,
    pub arm64_uefi_bootfile: Option<String>,
    pub ipxe_bootfile: Option<String>,
    pub root_path: Option<String>,
}

pub struct ProxyDhcpServer {
    socket: UdpSocket,
    server_ip: Ipv4Addr,
    http_port: u16,
    first_stage_bootfile: String,
    bios_bootfile: Option<String>,
    x64_uefi_bootfile: Option<String>,
    arm64_uefi_bootfile: Option<String>,
    ipxe_bootfile: Option<String>,
    root_path: Option<String>,
}

impl ProxyDhcpServer {
    pub fn bind(config: DhcpConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(config.bind_ip),
            config.bind_port,
        ))?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(SHUTDOWN_POLL_INTERVAL))?;

        Ok(Self {
            socket,
            server_ip: config.server_ip,
            http_port: config.http_port,
            first_stage_bootfile: config.first_stage_bootfile,
            bios_bootfile: config.bios_bootfile,
            x64_uefi_bootfile: config.x64_uefi_bootfile,
            arm64_uefi_bootfile: config.arm64_uefi_bootfile,
            ipxe_bootfile: config.ipxe_bootfile,
            root_path: config.root_path,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        while !shutdown.load(Ordering::SeqCst) {
            match self.serve_once() {
                Ok(()) => {}
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    pub fn serve_once(&self) -> io::Result<()> {
        let mut buf = [0u8; 65_535];
        let (len, peer) = self.socket.recv_from(&mut buf)?;
        self.handle_packet(peer, &buf[..len])
    }

    fn handle_packet(&self, peer: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let packet = match DhcpPacket::parse(payload) {
            Ok(packet) => {
                if log::log_enabled!(log::Level::Debug) {
                    let msg_type_str = packet
                        .message_type()
                        .map(|m| format!("{:?}", m))
                        .unwrap_or_else(|| "Unknown".to_string());
                    let is_pxe = packet.is_pxe_client();
                    let vci = packet
                        .options
                        .iter()
                        .find_map(|o| {
                            if let pxe_proto::DhcpOption::VendorClassIdentifier(v) = o {
                                Some(String::from_utf8_lossy(v).to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "None".to_string());
                    log::debug!(
                        "DHCP: Received {} from {} (VCI: {}, is_pxe: {})",
                        msg_type_str,
                        peer,
                        vci,
                        is_pxe
                    );
                }
                packet
            }
            Err(err) => {
                log::warn!("dropping malformed packet from {}: {}", peer, err);
                return Ok(());
            }
        };

        let Some(response) = build_response(
            &packet,
            self.server_ip,
            self.http_port,
            &self.first_stage_bootfile,
            self.bios_bootfile.as_deref(),
            self.x64_uefi_bootfile.as_deref(),
            self.arm64_uefi_bootfile.as_deref(),
            self.ipxe_bootfile.as_deref(),
            self.root_path.as_deref(),
        ) else {
            return Ok(());
        };

        let target = response_target(&packet, peer);
        self.socket.send_to(&response.serialize(), target)?;
        Ok(())
    }
}

/// Build a ProxyDHCP response for supported PXE packets.
///
/// Returns `None` for non-PXE clients and for DHCP message types other than
/// DISCOVER and REQUEST.
#[allow(clippy::too_many_arguments)]
pub fn build_response(
    packet: &DhcpPacket,
    server_ip: Ipv4Addr,
    http_port: u16,
    boot_filename: &str,
    bios_bootfile: Option<&str>,
    x64_uefi_bootfile: Option<&str>,
    arm64_uefi_bootfile: Option<&str>,
    ipxe_bootfile: Option<&str>,
    root_path: Option<&str>,
) -> Option<DhcpPacket> {
    if !packet.is_pxe_client() {
        return None;
    }

    match packet.message_type() {
        Some(MessageType::Discover) => Some(builder::build_offer(
            packet,
            server_ip,
            http_port,
            boot_filename,
            bios_bootfile,
            x64_uefi_bootfile,
            arm64_uefi_bootfile,
            ipxe_bootfile,
            root_path,
        )),
        Some(MessageType::Request) => Some(builder::build_ack(
            packet,
            server_ip,
            http_port,
            boot_filename,
            bios_bootfile,
            x64_uefi_bootfile,
            arm64_uefi_bootfile,
            ipxe_bootfile,
            root_path,
        )),
        _ => None,
    }
}

fn response_target(packet: &DhcpPacket, peer: SocketAddr) -> SocketAddr {
    if packet.flags & 0x8000 != 0 || peer.ip().is_unspecified() {
        return SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DEFAULT_CLIENT_PORT);
    }

    if packet.ciaddr != Ipv4Addr::UNSPECIFIED {
        return SocketAddr::new(IpAddr::V4(packet.ciaddr), DEFAULT_CLIENT_PORT);
    }

    SocketAddr::new(peer.ip(), DEFAULT_CLIENT_PORT)
}
