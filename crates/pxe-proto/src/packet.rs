use std::net::Ipv4Addr;

use crate::error::ParseError;
use crate::options::{parse_options, serialize_options, DhcpOption, MessageType};

// ── Constants ─────────────────────────────────────────────────────────────────

/// DHCP magic cookie per RFC 2131 §3.
const MAGIC_COOKIE: u32 = 0x6382_5363;

/// Fixed header size (op through file fields).
const FIXED_HEADER_LEN: usize = 236;

/// Minimum valid DHCP packet: fixed header + 4-byte magic cookie + End option.
pub const MIN_PACKET_LEN: usize = FIXED_HEADER_LEN + 4;

// ── Op ────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Op {
    #[default]
    BootRequest = 1,
    BootReply = 2,
}

// ── DhcpPacket ────────────────────────────────────────────────────────────────

/// A fully parsed DHCP packet (RFC 2131).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket {
    pub op: Op,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<DhcpOption>,
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self {
            op: Op::default(),
            htype: 1, // Ethernet
            hlen: 6,  // MAC
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }
}

impl DhcpPacket {
    /// Parse a DHCP packet from raw UDP payload bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < MIN_PACKET_LEN {
            return Err(ParseError::TooShort {
                need: MIN_PACKET_LEN,
                got: buf.len(),
            });
        }

        let op = match buf[0] {
            1 => Op::BootRequest,
            2 => Op::BootReply,
            v => return Err(ParseError::BadOp(v)),
        };

        let magic = u32::from_be_bytes([buf[236], buf[237], buf[238], buf[239]]);
        if magic != MAGIC_COOKIE {
            return Err(ParseError::BadMagicCookie(magic));
        }

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&buf[28..44]);

        let mut sname = [0u8; 64];
        sname.copy_from_slice(&buf[44..108]);

        let mut file = [0u8; 128];
        file.copy_from_slice(&buf[108..236]);

        let options = parse_options(&buf[240..])?;

        Ok(Self {
            op,
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16::from_be_bytes([buf[8], buf[9]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: Ipv4Addr::from([buf[12], buf[13], buf[14], buf[15]]),
            yiaddr: Ipv4Addr::from([buf[16], buf[17], buf[18], buf[19]]),
            siaddr: Ipv4Addr::from([buf[20], buf[21], buf[22], buf[23]]),
            giaddr: Ipv4Addr::from([buf[24], buf[25], buf[26], buf[27]]),
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Serialize the packet to bytes suitable for sending as a UDP payload.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_PACKET_LEN + self.options.len() * 8);
        out.push(self.op as u8);
        out.push(self.htype);
        out.push(self.hlen);
        out.push(self.hops);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.ciaddr.octets());
        out.extend_from_slice(&self.yiaddr.octets());
        out.extend_from_slice(&self.siaddr.octets());
        out.extend_from_slice(&self.giaddr.octets());
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        serialize_options(&self.options, &mut out);
        out
    }

    /// Return the first option with the given tag, if present.
    pub fn option(&self, tag: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|o: &&DhcpOption| o.tag() == tag)
    }

    /// Return the DHCP message type from option 53, if present.
    pub fn message_type(&self) -> Option<MessageType> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::MessageType(mt) = o {
                Some(*mt)
            } else {
                None
            }
        })
    }

    /// Returns `true` if option 60 starts with `PXEClient` or `HTTPClient`.
    pub fn is_pxe_client(&self) -> bool {
        self.options.iter().any(|o| {
            if let DhcpOption::VendorClassIdentifier(v) = o {
                v.starts_with(b"PXEClient") || v.starts_with(b"HTTPClient")
            } else {
                false
            }
        })
    }

    /// Returns `true` if option 60 starts with `HTTPClient`.
    pub fn is_http_client(&self) -> bool {
        self.options.iter().any(|o| {
            if let DhcpOption::VendorClassIdentifier(v) = o {
                v.starts_with(b"HTTPClient")
            } else {
                false
            }
        })
    }

    /// Returns `true` if the client is iPXE, identified natively via Option 77 (User Class).
    pub fn is_ipxe_client(&self) -> bool {
        self.options.iter().any(|o| {
            if let DhcpOption::Unknown(77, v) = o {
                v.starts_with(b"iPXE")
            } else {
                false
            }
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::MessageType;

    fn minimal_packet(op: u8) -> Vec<u8> {
        let mut buf = vec![0u8; MIN_PACKET_LEN + 1]; // +1 for End option
        buf[0] = op;
        buf[1] = 1; // htype: Ethernet
        buf[2] = 6; // hlen: 6-byte MAC
                    // xid
        buf[4] = 0xDE;
        buf[5] = 0xAD;
        buf[6] = 0xBE;
        buf[7] = 0xEF;
        // magic cookie
        buf[236] = 0x63;
        buf[237] = 0x82;
        buf[238] = 0x53;
        buf[239] = 0x63;
        // options: just End
        buf[240] = 255;
        buf
    }

    #[test]
    fn parse_minimal_request() {
        let buf = minimal_packet(1);
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.op, Op::BootRequest);
        assert_eq!(pkt.xid, 0xDEADBEEF);
        assert!(pkt.options.is_empty());
    }

    #[test]
    fn parse_minimal_reply() {
        let buf = minimal_packet(2);
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.op, Op::BootReply);
    }

    #[test]
    fn too_short() {
        let err = DhcpPacket::parse(&[0u8; 10]).unwrap_err();
        assert_eq!(
            err,
            ParseError::TooShort {
                need: MIN_PACKET_LEN,
                got: 10
            }
        );
    }

    #[test]
    fn bad_op() {
        let mut buf = minimal_packet(1);
        buf[0] = 5;
        assert_eq!(DhcpPacket::parse(&buf), Err(ParseError::BadOp(5)));
    }

    #[test]
    fn bad_magic() {
        let mut buf = minimal_packet(1);
        buf[236] = 0xFF;
        assert!(matches!(
            DhcpPacket::parse(&buf),
            Err(ParseError::BadMagicCookie(_))
        ));
    }

    #[test]
    fn round_trip_empty_options() {
        let buf = minimal_packet(1);
        let pkt = DhcpPacket::parse(&buf).unwrap();
        let serialized = pkt.serialize();
        let reparsed = DhcpPacket::parse(&serialized).unwrap();
        assert_eq!(pkt, reparsed);
    }

    #[test]
    fn round_trip_with_options() {
        let mut buf = minimal_packet(1);
        // Append options: MessageType=Discover, VendorClass=PXEClient, End
        buf.pop(); // remove old End
        buf.extend_from_slice(&[53, 1, 1]); // MessageType=Discover
        buf.extend_from_slice(&[60, 9]); // VendorClassIdentifier
        buf.extend_from_slice(b"PXEClient");
        buf.push(255); // End

        let pkt = DhcpPacket::parse(&buf).unwrap();
        let serialized = pkt.serialize();
        let reparsed = DhcpPacket::parse(&serialized).unwrap();
        assert_eq!(pkt, reparsed);
    }

    #[test]
    fn message_type_accessor() {
        let mut buf = minimal_packet(1);
        buf.pop();
        buf.extend_from_slice(&[53, 1, 1, 255]); // Discover + End
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn is_pxe_client_true() {
        let mut buf = minimal_packet(1);
        buf.pop();
        buf.extend_from_slice(&[60, 9]);
        buf.extend_from_slice(b"PXEClient");
        buf.push(255);
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert!(pkt.is_pxe_client());
    }

    #[test]
    fn is_pxe_client_false() {
        let buf = minimal_packet(1);
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert!(!pkt.is_pxe_client());
    }

    #[test]
    fn is_pxe_client_partial_prefix() {
        let mut buf = minimal_packet(1);
        buf.pop();
        buf.extend_from_slice(&[60, 3, b'P', b'X', b'E', 255]); // "PXE" not "PXEClient"
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert!(!pkt.is_pxe_client());
    }

    #[test]
    fn option_accessor() {
        let mut buf = minimal_packet(2);
        buf.pop();
        buf.extend_from_slice(&[54, 4, 192, 168, 1, 1, 255]); // ServerIdentifier
        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert!(pkt.option(54).is_some());
        assert!(pkt.option(53).is_none());
    }

    #[test]
    fn all_ip_fields_roundtrip() {
        let mut buf = minimal_packet(2);
        // Set all four IP fields to distinct values
        buf[12..16].copy_from_slice(&[10, 0, 0, 1]); // ciaddr
        buf[16..20].copy_from_slice(&[10, 0, 0, 2]); // yiaddr
        buf[20..24].copy_from_slice(&[10, 0, 0, 3]); // siaddr
        buf[24..28].copy_from_slice(&[10, 0, 0, 4]); // giaddr

        let pkt = DhcpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.ciaddr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.yiaddr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pkt.siaddr, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(pkt.giaddr, Ipv4Addr::new(10, 0, 0, 4));

        let reparsed = DhcpPacket::parse(&pkt.serialize()).unwrap();
        assert_eq!(pkt, reparsed);
    }
}
