use crate::error::ParseError;

// ── Message type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Result<Self, ParseError> {
        match v {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            _ => Err(ParseError::BadMessageType(v)),
        }
    }
}

// ── DHCP options ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// Option 43: Vendor-specific (PXE, stored raw; decode with `PxeVendorOptions`)
    VendorSpecific(Vec<u8>),
    /// Option 53: DHCP message type
    MessageType(MessageType),
    /// Option 54: Server identifier (IP address octets)
    ServerIdentifier([u8; 4]),
    /// Option 55: Parameter request list
    ParameterRequestList(Vec<u8>),
    /// Option 60: Vendor class identifier
    VendorClassIdentifier(Vec<u8>),
    /// Option 66: TFTP server name
    TftpServerName(Vec<u8>),
    /// Option 67: Bootfile name
    BootfileName(Vec<u8>),
    /// Any unrecognized option — preserved through round-trips unchanged.
    Unknown(u8, Vec<u8>),
}

impl DhcpOption {
    pub fn tag(&self) -> u8 {
        match self {
            Self::VendorSpecific(_) => 43,
            Self::MessageType(_) => 53,
            Self::ServerIdentifier(_) => 54,
            Self::ParameterRequestList(_) => 55,
            Self::VendorClassIdentifier(_) => 60,
            Self::TftpServerName(_) => 66,
            Self::BootfileName(_) => 67,
            Self::Unknown(t, _) => *t,
        }
    }

    pub(crate) fn parse_one(tag: u8, data: &[u8]) -> Result<Self, ParseError> {
        match tag {
            43 => Ok(Self::VendorSpecific(data.to_vec())),
            53 => {
                if data.len() != 1 {
                    return Err(ParseError::BadOptionLength {
                        tag,
                        need: 1,
                        got: data.len(),
                    });
                }
                Ok(Self::MessageType(MessageType::from_u8(data[0])?))
            }
            54 => {
                if data.len() != 4 {
                    return Err(ParseError::BadOptionLength {
                        tag,
                        need: 4,
                        got: data.len(),
                    });
                }
                Ok(Self::ServerIdentifier([data[0], data[1], data[2], data[3]]))
            }
            55 => Ok(Self::ParameterRequestList(data.to_vec())),
            60 => Ok(Self::VendorClassIdentifier(data.to_vec())),
            66 => Ok(Self::TftpServerName(data.to_vec())),
            67 => Ok(Self::BootfileName(data.to_vec())),
            _ => Ok(Self::Unknown(tag, data.to_vec())),
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        let tag = self.tag();
        match self {
            Self::MessageType(mt) => {
                out.extend_from_slice(&[53, 1, *mt as u8]);
            }
            Self::ServerIdentifier(ip) => {
                out.push(54);
                out.push(4);
                out.extend_from_slice(ip);
            }
            Self::VendorSpecific(data)
            | Self::ParameterRequestList(data)
            | Self::VendorClassIdentifier(data)
            | Self::TftpServerName(data)
            | Self::BootfileName(data) => {
                out.push(tag);
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
            Self::Unknown(_, data) => {
                out.push(tag);
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
        }
    }
}

// ── Option list parsing / serialization ──────────────────────────────────────

pub(crate) fn parse_options(data: &[u8]) -> Result<Vec<DhcpOption>, ParseError> {
    let mut opts = Vec::new();
    let mut i = 0;
    loop {
        if i >= data.len() {
            return Err(ParseError::UnterminatedOptions);
        }
        match data[i] {
            0 => {
                i += 1;
            } // Pad — skip, no length byte
            255 => return Ok(opts), // End — done
            tag => {
                i += 1;
                if i >= data.len() {
                    return Err(ParseError::UnterminatedOptions);
                }
                let len = data[i] as usize;
                i += 1;
                if i + len > data.len() {
                    return Err(ParseError::TooShort {
                        need: i + len,
                        got: data.len(),
                    });
                }
                opts.push(DhcpOption::parse_one(tag, &data[i..i + len])?);
                i += len;
            }
        }
    }
}

pub(crate) fn serialize_options(opts: &[DhcpOption], out: &mut Vec<u8>) {
    for opt in opts {
        opt.serialize(out);
    }
    out.push(255); // End
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_roundtrip() {
        for v in 1u8..=8 {
            let mt = MessageType::from_u8(v).unwrap();
            assert_eq!(mt as u8, v);
        }
    }

    #[test]
    fn bad_message_type() {
        assert_eq!(MessageType::from_u8(0), Err(ParseError::BadMessageType(0)));
        assert_eq!(MessageType::from_u8(9), Err(ParseError::BadMessageType(9)));
    }

    #[test]
    fn option_message_type_serialize_parse() {
        let opt = DhcpOption::MessageType(MessageType::Discover);
        let mut buf = Vec::new();
        opt.serialize(&mut buf);
        assert_eq!(buf, &[53, 1, 1]);

        let parsed = DhcpOption::parse_one(53, &[1]).unwrap();
        assert_eq!(parsed, opt);
    }

    #[test]
    fn option_server_id_serialize_parse() {
        let ip = [192, 168, 1, 10];
        let opt = DhcpOption::ServerIdentifier(ip);
        let mut buf = Vec::new();
        opt.serialize(&mut buf);
        assert_eq!(buf, &[54, 4, 192, 168, 1, 10]);

        let parsed = DhcpOption::parse_one(54, &ip).unwrap();
        assert_eq!(parsed, opt);
    }

    #[test]
    fn option_bootfile_name_roundtrip() {
        let opt = DhcpOption::BootfileName(b"ipxe.efi".to_vec());
        let mut buf = Vec::new();
        opt.serialize(&mut buf);
        assert_eq!(&buf[0..2], &[67, 8]);
        assert_eq!(&buf[2..], b"ipxe.efi");

        let parsed = DhcpOption::parse_one(67, b"ipxe.efi").unwrap();
        assert_eq!(parsed, opt);
    }

    #[test]
    fn option_vendor_class_pxeclient() {
        let opt = DhcpOption::VendorClassIdentifier(b"PXEClient:Arch:00007".to_vec());
        let mut buf = Vec::new();
        opt.serialize(&mut buf);
        let parsed = DhcpOption::parse_one(60, b"PXEClient:Arch:00007").unwrap();
        assert_eq!(parsed, opt);
    }

    #[test]
    fn option_unknown_preserved() {
        let opt = DhcpOption::Unknown(99, vec![0xDE, 0xAD]);
        let mut buf = Vec::new();
        opt.serialize(&mut buf);
        assert_eq!(buf, &[99, 2, 0xDE, 0xAD]);

        let parsed = DhcpOption::parse_one(99, &[0xDE, 0xAD]).unwrap();
        assert_eq!(parsed, opt);
    }

    #[test]
    fn option_bad_length_message_type() {
        let err = DhcpOption::parse_one(53, &[1, 2]).unwrap_err();
        assert_eq!(
            err,
            ParseError::BadOptionLength {
                tag: 53,
                need: 1,
                got: 2
            }
        );
    }

    #[test]
    fn option_bad_length_server_id() {
        let err = DhcpOption::parse_one(54, &[1, 2, 3]).unwrap_err();
        assert_eq!(
            err,
            ParseError::BadOptionLength {
                tag: 54,
                need: 4,
                got: 3
            }
        );
    }

    #[test]
    fn parse_options_basic() {
        let data = &[
            53, 1, 1, // MessageType = Discover
            60, 9, b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't', 255, // End
        ];
        let opts = parse_options(data).unwrap();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], DhcpOption::MessageType(MessageType::Discover));
        assert_eq!(
            opts[1],
            DhcpOption::VendorClassIdentifier(b"PXEClient".to_vec())
        );
    }

    #[test]
    fn parse_options_pad_skipped() {
        let data = &[0, 0, 53, 1, 2, 255]; // two Pad bytes, then MessageType=Offer
        let opts = parse_options(data).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0], DhcpOption::MessageType(MessageType::Offer));
    }

    #[test]
    fn parse_options_unterminated() {
        let data = &[53, 1, 1]; // no End marker
        assert_eq!(parse_options(data), Err(ParseError::UnterminatedOptions));
    }

    #[test]
    fn parse_options_truncated_data() {
        let data = &[67, 8, b'i', b'p', b'x', b'e']; // claims 8 bytes but only 4 present + no End
        assert!(matches!(
            parse_options(data),
            Err(ParseError::TooShort { .. }) | Err(ParseError::UnterminatedOptions)
        ));
    }

    #[test]
    fn serialize_options_roundtrip() {
        let opts = vec![
            DhcpOption::MessageType(MessageType::Offer),
            DhcpOption::ServerIdentifier([10, 0, 0, 1]),
            DhcpOption::BootfileName(b"ipxe.efi".to_vec()),
            DhcpOption::Unknown(99, vec![1, 2, 3]),
        ];
        let mut buf = Vec::new();
        serialize_options(&opts, &mut buf);
        let parsed = parse_options(&buf).unwrap();
        assert_eq!(parsed, opts);
    }
}
