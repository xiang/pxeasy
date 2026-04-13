use pxe_proto::*;

/// Build a plausible PXEClient DISCOVER packet.
fn pxe_discover(xid: u32, mac: [u8; 6]) -> DhcpPacket {
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);

    DhcpPacket {
        op: Op::BootRequest,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: 0x8000, // broadcast flag
        ciaddr: "0.0.0.0".parse().unwrap(),
        yiaddr: "0.0.0.0".parse().unwrap(),
        siaddr: "0.0.0.0".parse().unwrap(),
        giaddr: "0.0.0.0".parse().unwrap(),
        chaddr,
        sname: [0u8; 64],
        file: [0u8; 128],
        options: vec![
            DhcpOption::MessageType(MessageType::Discover),
            DhcpOption::VendorClassIdentifier(b"PXEClient:Arch:00007:UNDI:003016".to_vec()),
            DhcpOption::ParameterRequestList(vec![1, 3, 43, 60, 66, 67]),
        ],
    }
}

/// Build a plausible proxyDHCP OFFER in response to a PXEClient DISCOVER.
fn proxy_offer(discover: &DhcpPacket, server_ip: [u8; 4]) -> DhcpPacket {
    let pxe_opts = PxeVendorOptions {
        discovery_control: Some(0x08),
        boot_menu: Some(vec![
            0x80, 0x00, 0x07, b'i', b'p', b'x', b'e', b'.', b'e', b'f', b'i',
        ]),
        menu_prompt: Some(b"PXE Boot".to_vec()),
        ..Default::default()
    };

    DhcpPacket {
        op: Op::BootReply,
        htype: discover.htype,
        hlen: discover.hlen,
        hops: 0,
        xid: discover.xid,
        secs: 0,
        flags: 0,
        ciaddr: "0.0.0.0".parse().unwrap(),
        yiaddr: "0.0.0.0".parse().unwrap(),
        siaddr: server_ip.into(),
        giaddr: "0.0.0.0".parse().unwrap(),
        chaddr: discover.chaddr,
        sname: [0u8; 64],
        file: [0u8; 128],
        options: vec![
            DhcpOption::MessageType(MessageType::Offer),
            DhcpOption::ServerIdentifier(server_ip),
            DhcpOption::TftpServerName(server_ip.map(|b| b).to_vec()),
            DhcpOption::BootfileName(b"ipxe.efi".to_vec()),
            DhcpOption::VendorSpecific(pxe_opts.serialize()),
        ],
    }
}

#[test]
fn discover_round_trip() {
    let original = pxe_discover(0xCAFEBABE, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    let bytes = original.serialize();
    let reparsed = DhcpPacket::parse(&bytes).unwrap();
    assert_eq!(original, reparsed);
}

#[test]
fn offer_round_trip() {
    let discover = pxe_discover(0x12345678, [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
    let offer = proxy_offer(&discover, [192, 168, 1, 10]);
    let bytes = offer.serialize();
    let reparsed = DhcpPacket::parse(&bytes).unwrap();
    assert_eq!(offer, reparsed);
}

#[test]
fn pxe_vendor_options_embedded_in_packet_round_trip() {
    let pxe_opts = PxeVendorOptions {
        discovery_control: Some(0x08),
        boot_servers: Some(vec![0x00, 0x01, 192, 168, 1, 10]),
        boot_menu: Some(b"\x80\x00\x08ipxe.efi".to_vec()),
        menu_prompt: Some(b"Network Boot".to_vec()),
    };

    let raw_option43 = pxe_opts.serialize();
    let decoded = PxeVendorOptions::parse(&raw_option43).unwrap();
    assert_eq!(pxe_opts, decoded);
}

#[test]
fn discover_is_pxe_client() {
    let pkt = pxe_discover(1, [0; 6]);
    assert!(pkt.is_pxe_client());
    assert_eq!(pkt.message_type(), Some(MessageType::Discover));
}

#[test]
fn offer_is_not_pxe_client() {
    let discover = pxe_discover(1, [0; 6]);
    let offer = proxy_offer(&discover, [10, 0, 0, 1]);
    assert!(!offer.is_pxe_client());
    assert_eq!(offer.message_type(), Some(MessageType::Offer));
}

#[test]
fn chaddr_preserved_in_offer() {
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let discover = pxe_discover(0xABCD, mac);
    let offer = proxy_offer(&discover, [10, 0, 0, 1]);
    assert_eq!(&offer.chaddr[..6], &mac);
}

// ── proptest round-trip ───────────────────────────────────────────────────────

use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_round_trip(
        xid in any::<u32>(),
        secs in any::<u16>(),
        flags in any::<u16>(),
        ci in any::<[u8; 4]>(),
        yi in any::<[u8; 4]>(),
        si in any::<[u8; 4]>(),
        gi in any::<[u8; 4]>(),
        chaddr in any::<[u8; 16]>(),
        // Generate 0–4 options from a safe subset
        opts in prop::collection::vec(
            prop_oneof![
                (1u8..=8u8).prop_map(|v| {
                    DhcpOption::MessageType(MessageType::from_u8(v).unwrap())
                }),
                any::<[u8; 4]>().prop_map(DhcpOption::ServerIdentifier),
                prop::collection::vec(any::<u8>(), 0..16usize)
                    .prop_map(DhcpOption::BootfileName),
                prop::collection::vec(any::<u8>(), 0..16usize)
                    .prop_map(DhcpOption::VendorClassIdentifier),
                (any::<u8>(), prop::collection::vec(any::<u8>(), 0..8usize))
                    .prop_filter("not pad/end tags", |(t, _)| *t != 0 && *t != 255)
                    .prop_map(|(t, d)| DhcpOption::Unknown(t, d)),
            ],
            0..5,
        ),
    ) {
        let pkt = DhcpPacket {
            op:     Op::BootRequest,
            htype:  1,
            hlen:   6,
            hops:   0,
            xid,
            secs,
            flags,
            ciaddr: ci.into(),
            yiaddr: yi.into(),
            siaddr: si.into(),
            giaddr: gi.into(),
            chaddr,
            sname:  [0u8; 64],
            file:   [0u8; 128],
            options: opts,
        };
        let bytes = pkt.serialize();
        let reparsed = DhcpPacket::parse(&bytes).unwrap();
        prop_assert_eq!(pkt, reparsed);
    }
}
