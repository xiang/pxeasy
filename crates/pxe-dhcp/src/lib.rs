use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use pxe_proto::{DhcpOption, DhcpPacket, MessageType, Op, PxeVendorOptions};

const DEFAULT_CLIENT_PORT: u16 = 68;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Static server configuration for the ProxyDHCP service.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    pub server_ip: Ipv4Addr,
    pub first_stage_bootfile: String,
    pub second_stage_bootfile: String,
}

/// Runtime ProxyDHCP server.
pub struct ProxyDhcpServer {
    socket: UdpSocket,
    server_ip: Ipv4Addr,
    first_stage_bootfile: String,
    second_stage_bootfile: String,
}

impl ProxyDhcpServer {
    /// Bind the UDP socket for the ProxyDHCP listener.
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
            first_stage_bootfile: config.first_stage_bootfile,
            second_stage_bootfile: config.second_stage_bootfile,
        })
    }

    /// Return the socket address the server is listening on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Process incoming packets until the socket returns an error.
    pub fn serve(&self) -> io::Result<()> {
        loop {
            self.serve_once()?;
        }
    }

    /// Process incoming packets until shutdown is requested.
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

    /// Process a single incoming packet.
    pub fn serve_once(&self) -> io::Result<()> {
        let mut buf = [0u8; 65_535];
        let (len, peer) = self.socket.recv_from(&mut buf)?;
        self.handle_packet(peer, &buf[..len])
    }

    fn handle_packet(&self, peer: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let packet = match DhcpPacket::parse(payload) {
            Ok(packet) => packet,
            Err(err) => {
                eprintln!("dhcp: dropping malformed packet from {}: {}", peer, err);
                return Ok(());
            }
        };

        let bootfile = if is_ipxe_second_stage(&packet) {
            &self.second_stage_bootfile
        } else {
            &self.first_stage_bootfile
        };

        let Some(response) = build_response(&packet, self.server_ip, bootfile) else {
            return Ok(());
        };

        let target = response_target(&packet, peer);
        let bytes = response.serialize();
        self.socket.send_to(&bytes, target)?;
        Ok(())
    }
}

/// Build a ProxyDHCP response for supported PXE packets.
///
/// Returns `None` for non-PXE clients and for DHCP message types other than
/// DISCOVER and REQUEST.
pub fn build_response(
    packet: &DhcpPacket,
    server_ip: Ipv4Addr,
    boot_filename: &str,
) -> Option<DhcpPacket> {
    if !packet.is_pxe_client() {
        return None;
    }

    match packet.message_type() {
        Some(MessageType::Discover) => Some(build_offer(packet, server_ip, boot_filename)),
        Some(MessageType::Request) => Some(build_ack(packet, server_ip, boot_filename)),
        _ => None,
    }
}

/// Build a ProxyDHCP OFFER in response to a PXE DISCOVER.
pub fn build_offer(discover: &DhcpPacket, server_ip: Ipv4Addr, boot_filename: &str) -> DhcpPacket {
    build_reply(discover, MessageType::Offer, server_ip, boot_filename)
}

/// Build a ProxyDHCP ACK in response to a PXE REQUEST.
pub fn build_ack(request: &DhcpPacket, server_ip: Ipv4Addr, boot_filename: &str) -> DhcpPacket {
    build_reply(request, MessageType::Ack, server_ip, boot_filename)
}

fn is_ipxe_second_stage(packet: &DhcpPacket) -> bool {
    packet.options.iter().any(|option| match option {
        DhcpOption::VendorClassIdentifier(value) => value.eq_ignore_ascii_case(b"iPXE"),
        DhcpOption::Unknown(77, value) => value.eq_ignore_ascii_case(b"iPXE"),
        _ => false,
    })
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

fn build_reply(
    request: &DhcpPacket,
    reply_type: MessageType,
    server_ip: Ipv4Addr,
    boot_filename: &str,
) -> DhcpPacket {
    let mut file = [0u8; 128];
    let boot_filename_bytes = boot_filename.as_bytes();
    let copy_len = boot_filename_bytes.len().min(file.len());
    file[..copy_len].copy_from_slice(&boot_filename_bytes[..copy_len]);

    let server_octets = server_ip.octets();
    let mut boot_servers = Vec::with_capacity(6);
    boot_servers.extend_from_slice(&[0x00, 0x01]);
    boot_servers.extend_from_slice(&server_octets);

    let vendor_specific = PxeVendorOptions {
        discovery_control: Some(0x08),
        boot_servers: Some(boot_servers),
        ..Default::default()
    };

    DhcpPacket {
        op: Op::BootReply,
        htype: request.htype,
        hlen: request.hlen,
        hops: 0,
        xid: request.xid,
        secs: request.secs,
        flags: request.flags,
        ciaddr: request.ciaddr,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: server_ip,
        giaddr: request.giaddr,
        chaddr: request.chaddr,
        sname: [0u8; 64],
        file,
        options: vec![
            DhcpOption::MessageType(reply_type),
            DhcpOption::ServerIdentifier(server_octets),
            DhcpOption::BootfileName(boot_filename_bytes.to_vec()),
            DhcpOption::VendorSpecific(vendor_specific.serialize()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pxe_client_packet(message_type: MessageType) -> DhcpPacket {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

        DhcpPacket {
            op: Op::BootRequest,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x1234_5678,
            secs: 3,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::new(10, 0, 0, 1),
            chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            options: vec![
                DhcpOption::MessageType(message_type),
                DhcpOption::VendorClassIdentifier(b"PXEClient:Arch:00007:UNDI:003016".to_vec()),
            ],
        }
    }

    fn non_pxe_packet(message_type: MessageType) -> DhcpPacket {
        let mut packet = pxe_client_packet(message_type);
        packet.options = vec![DhcpOption::MessageType(message_type)];
        packet
    }

    fn bootfile_field(packet: &DhcpPacket) -> &[u8] {
        let len = packet
            .file
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(packet.file.len());
        &packet.file[..len]
    }

    fn vendor_options(packet: &DhcpPacket) -> PxeVendorOptions {
        let raw = packet
            .options
            .iter()
            .find_map(|option| match option {
                DhcpOption::VendorSpecific(data) => Some(data.as_slice()),
                _ => None,
            })
            .expect("missing option 43");
        PxeVendorOptions::parse(raw).expect("option 43 should parse")
    }

    #[test]
    fn second_stage_ipxe_requests_switch_to_script_bootfile() {
        let mut packet = pxe_client_packet(MessageType::Request);
        packet
            .options
            .push(DhcpOption::Unknown(77, b"iPXE".to_vec()));

        assert!(is_ipxe_second_stage(&packet));
    }

    #[test]
    fn broadcast_requests_reply_to_client_broadcast_port() {
        let packet = pxe_client_packet(MessageType::Discover);

        let target = response_target(
            &packet,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_CLIENT_PORT),
        );

        assert_eq!(
            target,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DEFAULT_CLIENT_PORT)
        );
    }

    #[test]
    fn offer_contains_expected_proxy_dhcp_fields() {
        let discover = pxe_client_packet(MessageType::Discover);
        let server_ip = Ipv4Addr::new(192, 168, 1, 10);

        let offer = build_offer(&discover, server_ip, "ipxe.efi");

        assert_eq!(offer.op, Op::BootReply);
        assert_eq!(offer.message_type(), Some(MessageType::Offer));
        assert_eq!(offer.xid, discover.xid);
        assert_eq!(offer.chaddr, discover.chaddr);
        assert_eq!(offer.siaddr, server_ip);
        assert_eq!(offer.giaddr, discover.giaddr);
        assert_eq!(bootfile_field(&offer), b"ipxe.efi");
        assert!(matches!(
            offer.get_option(67),
            Some(DhcpOption::BootfileName(name)) if name == b"ipxe.efi"
        ));

        let vendor_options = vendor_options(&offer);
        assert_eq!(vendor_options.discovery_control, Some(0x08));
        assert_eq!(
            vendor_options.boot_servers,
            Some(vec![0x00, 0x01, 192, 168, 1, 10])
        );
    }

    #[test]
    fn ack_contains_expected_proxy_dhcp_fields() {
        let request = pxe_client_packet(MessageType::Request);
        let server_ip = Ipv4Addr::new(192, 168, 1, 20);

        let ack = build_ack(&request, server_ip, "ipxe.efi");

        assert_eq!(ack.message_type(), Some(MessageType::Ack));
        assert_eq!(ack.siaddr, server_ip);
        assert!(matches!(
            ack.get_option(54),
            Some(DhcpOption::ServerIdentifier(ip)) if *ip == [192, 168, 1, 20]
        ));
    }

    #[test]
    fn build_response_ignores_non_pxe_packets() {
        let discover = non_pxe_packet(MessageType::Discover);
        assert!(build_response(&discover, Ipv4Addr::new(192, 168, 1, 10), "ipxe.efi").is_none());
    }

    #[test]
    fn build_response_ignores_other_message_types() {
        let inform = pxe_client_packet(MessageType::Inform);
        assert!(build_response(&inform, Ipv4Addr::new(192, 168, 1, 10), "ipxe.efi").is_none());
    }

    #[test]
    fn build_response_dispatches_discover_and_request() {
        let discover = pxe_client_packet(MessageType::Discover);
        let request = pxe_client_packet(MessageType::Request);
        let server_ip = Ipv4Addr::new(192, 168, 1, 10);

        let offer = build_response(&discover, server_ip, "ipxe.efi")
            .expect("discover should produce OFFER");
        let ack =
            build_response(&request, server_ip, "ipxe.efi").expect("request should produce ACK");

        assert_eq!(offer.message_type(), Some(MessageType::Offer));
        assert_eq!(ack.message_type(), Some(MessageType::Ack));
    }
}
