//! Minimal read-only SMB2 server for serving Windows ISO contents over the network.
//!
//! Supports the protocol subset required for WinPE to connect and read installer files:
//! NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, QUERY_INFO, QUERY_DIRECTORY,
//! CLOSE, LOGOFF, TREE_DISCONNECT, IOCTL (returns error). All write-class commands return
//! STATUS_ACCESS_DENIED.

pub(crate) mod constants;
pub(crate) mod handlers;
pub(crate) mod proto;
pub(crate) mod server;
pub(crate) mod session;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

pub use server::SmbServer;

/// Configuration for the SMB server.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SmbConfig {
    pub(crate) bind_ip: Ipv4Addr,
    pub(crate) bind_port: u16,
    pub(crate) share_name: String,
    pub(crate) source_path: PathBuf,
    /// Metadata cache built from the ISO at server startup; None until populated.
    pub(crate) iso_cache: Option<Arc<HashMap<String, pxe_profiles::IsoEntryMeta>>>,
    /// Open file handle to the ISO image shared across all reads; None for dir sources.
    pub(crate) iso_file: Option<Arc<std::fs::File>>,
}

impl SmbConfig {
    /// Creates a new SMB server configuration.
    pub fn new(
        bind_ip: Ipv4Addr,
        bind_port: u16,
        share_name: String,
        source_path: PathBuf,
    ) -> Self {
        Self {
            bind_ip,
            bind_port,
            share_name,
            source_path,
            iso_cache: None,
            iso_file: None,
        }
    }
}

/// Runs an SMB server with the given configuration until the shutdown signal is received.
pub fn run_server(
    config: SmbConfig,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    let server = SmbServer::bind(config)?;
    server.serve_until_shutdown(&shutdown)
}
