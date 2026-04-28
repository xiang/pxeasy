use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer too small to contain a valid packet or option.
    #[error("packet too short: need {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },
    /// Magic cookie field does not match 0x63825363.
    #[error("invalid DHCP magic cookie: {0:#010x}")]
    BadMagicCookie(u32),
    /// `op` field is not 1 (BootRequest) or 2 (BootReply).
    #[error("invalid op field: {0} (expected 1 or 2)")]
    BadOp(u8),
    /// Option 53 value is outside [1, 8].
    #[error("invalid message type: {0} (expected 1-8)")]
    BadMessageType(u8),
    /// A fixed-length option has the wrong length byte.
    #[error("option {tag}: expected {need} bytes, got {got}")]
    BadOptionLength { tag: u8, need: usize, got: usize },
    /// Options section ends without an End (255) marker.
    #[error("options truncated before End marker (255)")]
    UnterminatedOptions,
}
