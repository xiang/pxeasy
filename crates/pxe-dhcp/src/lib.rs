use std::net::Ipv4Addr;

use pxe_proto::{DhcpOption, DhcpPacket, MessageType, Op, PxeVendorOptions};

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
