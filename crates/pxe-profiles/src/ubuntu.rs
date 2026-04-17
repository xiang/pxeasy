use std::net::Ipv4Addr;

/// Ubuntu repo files we can stream directly from the ISO image.
pub fn should_stream_repo_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    path.starts_with("pool/") || path.starts_with("dists/")
}

/// Kernel command line for Ubuntu Live ISO boot via NBD.
///
/// The NBD server must export the ISO at `server_ip:nbd_port`.
/// `ip=dhcp` configures the network in initrd before connecting NBD.
pub fn nbd_boot_params(server_ip: Ipv4Addr, nbd_port: u16) -> String {
    format!(
        "ip=dhcp root=/dev/nbd0 nbdroot={}:{} boot=casper",
        server_ip, nbd_port
    )
}

/// Kernel command line for Ubuntu Live ISO boot via NFS (casper netboot=nfs).
///
/// The NFS server must export the ISO filesystem at `export_path`
/// (e.g. `/ubuntu-live`).
///
/// `toram` tells casper to copy the squashfs overlays into RAM before mounting
/// them. Without it, every squashfs compressed-block cache miss is an NFS READ,
/// and dpkg/apt metadata traversal during configure_apt causes the same blocks
/// to be evicted and re-fetched repeatedly, stalling the installer indefinitely.
pub fn nfs_boot_params(server_ip: Ipv4Addr, export_path: &str) -> String {
    format!(
        "root=/dev/nfs rw boot=casper netboot=nfs nfsroot={}:{},vers=3,proto=tcp ip=dhcp toram",
        server_ip, export_path
    )
}

/// Default kernel command line for Ubuntu netboot installer boot.
pub fn netboot_boot_params(server_ip: Ipv4Addr, http_port: u16) -> String {
    let seed = format!("http://{}:{}/seed/", server_ip, http_port);
    format!("autoinstall ds=nocloud-net;s={} ip=dhcp", seed)
}

/// Build iPXE script for Ubuntu netboot installer boot.
pub fn build_ipxe_script(server_ip: Ipv4Addr, http_port: u16, boot_params: &str) -> String {
    let boot_params = escape_kernel_cmdline(boot_params);
    format!(
        "#!ipxe\n\
         kernel http://{}:{}/boot/linux {}\n\
         initrd http://{}:{}/boot/initrd\n\
         boot",
        server_ip, http_port, boot_params, server_ip, http_port
    )
}

/// Build GRUB config for Ubuntu netboot installer boot.
pub fn build_grub_cfg(label: &str, boot_params: &str) -> String {
    let boot_params = escape_kernel_cmdline(boot_params);
    format!(
        "set timeout=5\n\
         set default=0\n\
         menuentry '{}' {{\n\
         \tlinux /linux {}\n\
         \tinitrd /initrd\n\
         }}",
        label, boot_params
    )
}

fn escape_kernel_cmdline(value: &str) -> String {
    value.replace(';', "\\;")
}

/// Build NoCloud user-data for Ubuntu autoinstall.
pub fn build_nocloud_user_data(mirror_uri: &str) -> String {
    format!(
        "#cloud-config\n\
autoinstall:\n\
  version: 1\n\
  apt:\n\
    preserve_sources_list: false\n\
    mirror-selection:\n\
      primary:\n\
        - uri: \"{}\"\n\
    fallback: offline-install\n\
    geoip: false\n",
        mirror_uri
    )
}

/// Build NoCloud meta-data for Ubuntu autoinstall.
pub fn build_nocloud_meta_data() -> String {
    "instance-id: pxeasy\nlocal-hostname: pxeasy\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netboot_boot_params_use_expected_autoinstall() {
        let params = netboot_boot_params(Ipv4Addr::new(192, 168, 1, 10), 8080);
        assert!(params.contains("autoinstall ds=nocloud-net;s=http://192.168.1.10:8080/seed/"));
        assert!(params.contains("ip=dhcp"));
    }

    #[test]
    fn nbd_boot_params_use_root_nbd0() {
        let params = nbd_boot_params(Ipv4Addr::new(192, 168, 1, 10), 10809);
        assert!(params.contains("ip=dhcp"));
        assert!(params.contains("root=/dev/nbd0"));
        assert!(params.contains("nbdroot=192.168.1.10:10809"));
        assert!(params.contains("boot=casper"));
    }

    #[test]
    fn nfs_boot_params_force_nfsv3_over_tcp() {
        let params = nfs_boot_params(Ipv4Addr::new(192, 168, 1, 10), "/ubuntu-live");
        assert!(params.contains("root=/dev/nfs"));
        assert!(params.contains("rw"));
        assert!(params.contains("boot=casper netboot=nfs"));
        assert!(params.contains("nfsroot=192.168.1.10:/ubuntu-live"));
        assert!(params.contains("vers=3,proto=tcp"));
        assert!(params.contains("ip=dhcp"));
        assert!(params.contains("toram"));
    }

    #[test]
    fn ipxe_script_embeds_kernel_and_initrd_urls() {
        let script = build_ipxe_script(Ipv4Addr::new(192, 168, 1, 10), 8080, "foo=bar");
        assert!(script.contains("kernel http://192.168.1.10:8080/boot/linux foo=bar"));
        assert!(script.contains("initrd http://192.168.1.10:8080/boot/initrd"));
    }

    #[test]
    fn bootloader_scripts_escape_semicolons() {
        let grub = build_grub_cfg("Ubuntu", "ds=nocloud-net;s=http://example/seed/");
        let ipxe = build_ipxe_script(
            Ipv4Addr::new(192, 168, 1, 10),
            8080,
            "ds=nocloud-net;s=http://example/seed/",
        );
        assert!(grub.contains("ds=nocloud-net\\;s=http://example/seed/"));
        assert!(ipxe.contains("ds=nocloud-net\\;s=http://example/seed/"));
    }

    #[test]
    fn nocloud_user_data_embeds_mirror() {
        let user_data = build_nocloud_user_data("http://192.168.1.10:8080/ubuntu");
        assert!(user_data.contains("uri: \"http://192.168.1.10:8080/ubuntu\""));
        assert!(user_data.contains("fallback: offline-install"));
    }

    #[test]
    fn repo_path_detection_matches_pool_and_dists() {
        assert!(should_stream_repo_path("/pool/main/a/foo.deb"));
        assert!(should_stream_repo_path("/dists/noble/Release"));
        assert!(!should_stream_repo_path("/casper/initrd"));
    }
}
