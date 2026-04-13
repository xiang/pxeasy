use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer too small to contain a valid packet or option.
    TooShort { need: usize, got: usize },
    /// Magic cookie field does not match 0x63825363.
    BadMagicCookie(u32),
    /// `op` field is not 1 (BootRequest) or 2 (BootReply).
    BadOp(u8),
    /// Option 53 value is outside [1, 8].
    BadMessageType(u8),
    /// A fixed-length option has the wrong length byte.
    BadOptionLength { tag: u8, need: usize, got: usize },
    /// Options section ends without an End (255) marker.
    UnterminatedOptions,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, got } => {
                write!(f, "packet too short: need {need} bytes, got {got}")
            }
            Self::BadMagicCookie(v) => write!(f, "invalid DHCP magic cookie: {v:#010x}"),
            Self::BadOp(v) => write!(f, "invalid op field: {v} (expected 1 or 2)"),
            Self::BadMessageType(v) => write!(f, "invalid message type: {v} (expected 1–8)"),
            Self::BadOptionLength { tag, need, got } => {
                write!(f, "option {tag}: expected {need} bytes, got {got}")
            }
            Self::UnterminatedOptions => write!(f, "options truncated before End marker (255)"),
        }
    }
}

impl std::error::Error for ParseError {}
