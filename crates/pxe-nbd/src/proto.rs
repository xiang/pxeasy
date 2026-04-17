// NBD protocol constants (newstyle negotiation, RFC-style spec)
// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md

// Handshake magic
pub const NBDMAGIC: u64 = 0x4e42444d41474943;
pub const IHAVEOPT: u64 = 0x49484156454f5054;
pub const OPTS_REPLY_MAGIC: u64 = 0x0003e889045565a9;

// Transmission magic
pub const REQUEST_MAGIC: u32 = 0x25609513;
pub const SIMPLE_REPLY_MAGIC: u32 = 0x67446698;

// Server handshake flags
pub const FLAG_FIXED_NEWSTYLE: u16 = 0x0001;
pub const FLAG_NO_ZEROES: u16 = 0x0002;

// Client handshake flags
pub const CLIENT_FLAG_NO_ZEROES: u32 = 0x0002;

// Option codes
pub const OPT_EXPORT_NAME: u32 = 1;
pub const OPT_ABORT: u32 = 2;
pub const OPT_LIST: u32 = 3;
pub const OPT_INFO: u32 = 6;
pub const OPT_GO: u32 = 7;

// Option reply types
pub const REP_ACK: u32 = 1;
pub const REP_SERVER: u32 = 2;
pub const REP_INFO: u32 = 3;
pub const REP_ERR_UNSUP: u32 = 0x80000001;

// Info types (used in REP_INFO data)
pub const INFO_EXPORT: u16 = 0;

// Transmission flags
pub const TRANS_HAS_FLAGS: u16 = 0x0001;
pub const TRANS_READ_ONLY: u16 = 0x0002;

// Command types
pub const CMD_READ: u16 = 0;
pub const CMD_WRITE: u16 = 1;
pub const CMD_DISC: u16 = 2;

// Error codes (errno-style)
pub const NBD_OK: u32 = 0;
pub const NBD_EPERM: u32 = 1;
pub const NBD_EIO: u32 = 5;
pub const NBD_EINVAL: u32 = 22;
