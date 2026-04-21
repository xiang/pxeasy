use std::net::Ipv4Addr;

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

/// Build iPXE script for Ubuntu boot.
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

/// Build GRUB config for Ubuntu boot.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
