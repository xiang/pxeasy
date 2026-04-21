use crate::error::ParseError;

/// Decoded contents of DHCP option 43 for PXE clients.
///
/// Source: RFC 4578 §2 and Intel PXE specification.
/// Obtained by calling `PxeVendorOptions::parse()` on a `DhcpOption::VendorSpecific` payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PxeVendorOptions {
    /// Sub-option 6: Discovery control bitmask.
    /// Bit 3 (0x08) = use only unicast/proxy boot server (suppress multicast discovery).
    pub discovery_control: Option<u8>,
    /// Sub-option 8: Boot server list (raw; variable-length per PXE spec).
    pub boot_servers: Option<Vec<u8>>,
    /// Sub-option 9: Boot menu entries (raw).
    pub boot_menu: Option<Vec<u8>>,
    /// Sub-option 10: Menu prompt string (raw).
    pub menu_prompt: Option<Vec<u8>>,
    /// Sub-option 71: Boot item (raw; 4 bytes: type (2), index (2)).
    pub boot_item: Option<Vec<u8>>,
}

impl PxeVendorOptions {
    /// Parse from the raw bytes of DHCP option 43.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut out = PxeVendorOptions::default();
        let mut i = 0;
        loop {
            if i >= data.len() {
                // Option 43 may or may not include a terminal 255; be lenient.
                break;
            }
            match data[i] {
                0 => {
                    i += 1;
                    continue;
                } // Pad
                255 => break, // End
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
                    let sub = &data[i..i + len];
                    i += len;
                    match tag {
                        6 => {
                            if len != 1 {
                                return Err(ParseError::BadOptionLength {
                                    tag,
                                    need: 1,
                                    got: len,
                                });
                            }
                            out.discovery_control = Some(sub[0]);
                        }
                        8 => out.boot_servers = Some(sub.to_vec()),
                        9 => out.boot_menu = Some(sub.to_vec()),
                        10 => out.menu_prompt = Some(sub.to_vec()),
                        71 => out.boot_item = Some(sub.to_vec()),
                        _ => {} // unknown sub-options are silently skipped
                    }
                }
            }
        }
        Ok(out)
    }

    /// Serialize to bytes suitable for use as the DHCP option 43 payload.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(dc) = self.discovery_control {
            out.extend_from_slice(&[6, 1, dc]);
        }
        if let Some(bs) = &self.boot_servers {
            out.push(8);
            out.push(bs.len() as u8);
            out.extend_from_slice(bs);
        }
        if let Some(bm) = &self.boot_menu {
            out.push(9);
            out.push(bm.len() as u8);
            out.extend_from_slice(bm);
        }
        if let Some(mp) = &self.menu_prompt {
            out.push(10);
            out.push(mp.len() as u8);
            out.extend_from_slice(mp);
        }
        if let Some(bi) = &self.boot_item {
            out.push(71);
            out.push(bi.len() as u8);
            out.extend_from_slice(bi);
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_control_only() {
        let opts = PxeVendorOptions {
            discovery_control: Some(0x08),
            ..Default::default()
        };
        let bytes = opts.serialize();
        let parsed = PxeVendorOptions::parse(&bytes).unwrap();
        assert_eq!(parsed, opts);
    }

    #[test]
    fn all_fields_roundtrip() {
        let opts = PxeVendorOptions {
            discovery_control: Some(0x08),
            boot_servers: Some(vec![0x00, 0x01, 0x02]),
            boot_menu: Some(vec![0x80, 0x00, 0x07, b'i', b'p', b'x', b'e']),
            menu_prompt: Some(b"Boot menu".to_vec()),
            boot_item: Some(vec![0x00, 0x01, 0x00, 0x01]),
        };
        let bytes = opts.serialize();
        let parsed = PxeVendorOptions::parse(&bytes).unwrap();
        assert_eq!(parsed, opts);
    }

    #[test]
    fn empty_is_default() {
        let parsed = PxeVendorOptions::parse(&[]).unwrap();
        assert_eq!(parsed, PxeVendorOptions::default());
    }

    #[test]
    fn empty_payload_ok() {
        let parsed = PxeVendorOptions::parse(&[]).unwrap();
        assert_eq!(parsed, PxeVendorOptions::default());
    }

    #[test]
    fn unknown_sub_options_skipped() {
        let data = &[
            99, 2, 0xDE, 0xAD, // unknown sub-option
            6, 1, 0x08, // discovery_control
            255,
        ];
        let parsed = PxeVendorOptions::parse(data).unwrap();
        assert_eq!(parsed.discovery_control, Some(0x08));
    }

    #[test]
    fn bad_discovery_control_length() {
        let data = &[6, 2, 0x08, 0x00, 255]; // sub-option 6 with length 2 (should be 1)
        let err = PxeVendorOptions::parse(data).unwrap_err();
        assert_eq!(
            err,
            ParseError::BadOptionLength {
                tag: 6,
                need: 1,
                got: 2
            }
        );
    }
}
