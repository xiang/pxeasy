use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

mod mount;
mod nfs3;
mod portmap;
mod rpc;
mod vfs;

pub use portmap::{MOUNT_PORT, NFS_PORT};

/// The NFS export path that clients must mount.
pub const EXPORT_PATH: &str = "/ubuntu-live";

pub(crate) const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

pub struct NfsConfig {
    pub iso_path: std::path::PathBuf,
    pub bind_ip: Ipv4Addr,
    pub export_path: String,
}

pub struct NfsServer {
    portmap: portmap::PortmapServer,
    mount: mount::MountServer,
    nfs: nfs3::NfsServer,
}

impl NfsServer {
    /// Bind all three NFS-related services and build the in-memory VFS.
    pub fn bind(config: NfsConfig) -> io::Result<Self> {
        let mut vfs = vfs::Vfs::from_iso(&config.iso_path)?;

        let export_root_id = if config.export_path == "/arm64" {
            vfs.add_alias_tree(
                "/arm64",
                &[
                    ("/arm64/linux", "/casper/vmlinuz"),
                    ("/arm64/initrd", "/casper/initrd"),
                ],
            )?
        } else if config.export_path == "/ubuntu-installer/amd64" {
            vfs.add_alias_tree(
                "/ubuntu-installer/amd64",
                &[
                    ("/ubuntu-installer/amd64/linux", "/casper/vmlinuz"),
                    ("/ubuntu-installer/amd64/initrd.gz", "/casper/initrd"),
                ],
            )?
        } else {
            vfs.root_id()
        };

        let vfs = Arc::new(vfs);

        let portmap = portmap::PortmapServer::bind(config.bind_ip)?;
        let mount = mount::MountServer::bind(config.bind_ip, &config.export_path, export_root_id)?;
        let nfs = nfs3::NfsServer::bind(config.bind_ip, vfs)?;
        Ok(Self {
            portmap,
            mount,
            nfs,
        })
    }

    /// Address the NFS daemon is listening on.
    pub fn nfs_local_addr(&self) -> io::Result<SocketAddr> {
        self.nfs.local_addr()
    }

    /// Address the portmapper is listening on.
    pub fn portmap_local_addr(&self) -> io::Result<SocketAddr> {
        self.portmap.local_addr()
    }

    /// Address the mount daemon is listening on.
    pub fn mount_local_addr(&self) -> io::Result<SocketAddr> {
        self.mount.local_addr()
    }

    /// Run all three services until `shutdown` is set or a service fails.
    pub fn serve_until_shutdown(self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        let portmap_shutdown = Arc::clone(shutdown);
        let mount_shutdown = Arc::clone(shutdown);
        let nfs_shutdown = Arc::clone(shutdown);

        let portmap_handle = thread::spawn(move || {
            if let Err(e) = self.portmap.serve_until_shutdown(&portmap_shutdown) {
                log::error!("[nfs] portmap error: {e}");
            }
        });
        let mount_handle = thread::spawn(move || {
            if let Err(e) = self.mount.serve_until_shutdown(&mount_shutdown) {
                log::error!("[nfs] mountd error: {e}");
            }
        });
        let nfs_handle = thread::spawn(move || {
            if let Err(e) = self.nfs.serve_until_shutdown(&nfs_shutdown) {
                log::error!("[nfs] nfsd error: {e}");
            }
        });

        // Wait for shutdown then join all threads
        while !shutdown.load(Ordering::SeqCst) {
            thread::sleep(SHUTDOWN_POLL);
        }

        portmap_handle.join().ok();
        mount_handle.join().ok();
        nfs_handle.join().ok();
        Ok(())
    }
}
