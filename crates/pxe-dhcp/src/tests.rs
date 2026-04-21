use super::builder::*;
use super::server::*;
use pxe_proto::{DhcpOption, DhcpPacket, MessageType, Op, PxeVendorOptions};
use std::net::Ipv4Addr;

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
            DhcpOption::Unknown(93, vec![0x00, 0x07]),
            DhcpOption::Unknown(94, vec![0x01, 0x03, 0x10]),
            DhcpOption::Unknown(97, vec![0x00; 17]),
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

    let offer = build_offer(
        &discover,
        server_ip,
        8080,
        "bootx64.efi",
        None,
        None,
        None,
        None,
        None,
    );

    assert_eq!(offer.op, Op::BootReply);
    assert_eq!(offer.message_type(), Some(MessageType::Offer));
    assert_eq!(offer.xid, discover.xid);
    assert_eq!(offer.chaddr, discover.chaddr);
    assert_eq!(offer.siaddr, server_ip);
    assert_eq!(offer.giaddr, discover.giaddr);
    assert_eq!(bootfile_field(&offer), b"bootx64.efi");
    assert!(matches!(
        offer.option(67),
        Some(DhcpOption::BootfileName(name)) if name == b"bootx64.efi"
    ));
    assert!(matches!(
        offer.option(66),
        Some(DhcpOption::TftpServerName(name)) if name == b"192.168.1.10"
    ));
    assert!(matches!(
        offer.option(93),
        Some(DhcpOption::Unknown(93, value)) if value == &[0x00, 0x07]
    ));

    let vendor_options = vendor_options(&offer);
    assert_eq!(vendor_options.discovery_control, Some(0x08));
    assert_eq!(
        vendor_options.boot_servers,
        Some(vec![0x00, 0x01, 1, 192, 168, 1, 10])
    );
}

#[test]
fn ack_contains_expected_proxy_dhcp_fields() {
    let request = pxe_client_packet(MessageType::Request);
    let server_ip = Ipv4Addr::new(192, 168, 1, 20);

    let ack = build_ack(
        &request,
        server_ip,
        8080,
        "bootx64.efi",
        None,
        None,
        None,
        None,
        None,
    );

    assert_eq!(ack.message_type(), Some(MessageType::Ack));
    assert_eq!(ack.siaddr, server_ip);
    assert!(matches!(
        ack.option(54),
        Some(DhcpOption::ServerIdentifier(ip)) if *ip == [192, 168, 1, 20]
    ));
}

#[test]
fn build_response_ignores_non_pxe_packets() {
    let discover = non_pxe_packet(MessageType::Discover);
    assert!(build_response(
        &discover,
        Ipv4Addr::new(192, 168, 1, 10),
        8080,
        "bootx64.efi",
        None,
        None,
        None,
        None,
        None
    )
    .is_none());
}

#[test]
fn ipxe_client_gets_ipxe_script() {
    let mut discover = pxe_client_packet(MessageType::Discover);
    discover
        .options
        .push(DhcpOption::Unknown(77, b"iPXE".to_vec()));
    let server_ip = Ipv4Addr::new(192, 168, 1, 10);

    let offer = build_response(
        &discover,
        server_ip,
        8080,
        "ipxe.efi",
        None,
        None,
        None,
        Some("boot.ipxe"),
        None,
    )
    .expect("discover should produce OFFER");

    assert_eq!(
        bootfile_field(&offer),
        b"http://192.168.1.10:8080/boot.ipxe"
    );
}

#[test]
fn architecture_specific_bootfile_and_root_path_are_applied() {
    let discover = pxe_client_packet(MessageType::Discover);
    let offer = build_offer(
        &discover,
        Ipv4Addr::new(192, 168, 1, 10),
        8080,
        "boot/default",
        Some("boot/pxeboot"),
        Some("boot/loader.efi"),
        Some("boot/loader.efi"),
        None,
        Some("192.168.1.10:/"),
    );

    assert_eq!(bootfile_field(&offer), b"boot/loader.efi");
    assert!(matches!(
        offer.option(17),
        Some(DhcpOption::Unknown(17, value)) if value == b"192.168.1.10:/"
    ));
}
