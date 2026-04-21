use pxe_proto::{DhcpOption, DhcpPacket, MessageType, Op, PxeVendorOptions};
use std::net::Ipv4Addr;

/// Build a ProxyDHCP OFFER in response to a PXE DISCOVER.
#[allow(clippy::too_many_arguments)]
pub fn build_offer(
    discover: &DhcpPacket,
    server_ip: Ipv4Addr,
    http_port: u16,
    boot_filename: &str,
    bios_bootfile: Option<&str>,
    x64_uefi_bootfile: Option<&str>,
    arm64_uefi_bootfile: Option<&str>,
    ipxe_bootfile: Option<&str>,
    root_path: Option<&str>,
) -> DhcpPacket {
    build_reply(
        discover,
        MessageType::Offer,
        server_ip,
        http_port,
        boot_filename,
        bios_bootfile,
        x64_uefi_bootfile,
        arm64_uefi_bootfile,
        ipxe_bootfile,
        root_path,
    )
}

/// Build a ProxyDHCP ACK in response to a PXE REQUEST.
#[allow(clippy::too_many_arguments)]
pub fn build_ack(
    request: &DhcpPacket,
    server_ip: Ipv4Addr,
    http_port: u16,
    boot_filename: &str,
    bios_bootfile: Option<&str>,
    x64_uefi_bootfile: Option<&str>,
    arm64_uefi_bootfile: Option<&str>,
    ipxe_bootfile: Option<&str>,
    root_path: Option<&str>,
) -> DhcpPacket {
    build_reply(
        request,
        MessageType::Ack,
        server_ip,
        http_port,
        boot_filename,
        bios_bootfile,
        x64_uefi_bootfile,
        arm64_uefi_bootfile,
        ipxe_bootfile,
        root_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_reply(
    request: &DhcpPacket,
    reply_type: MessageType,
    server_ip: Ipv4Addr,
    http_port: u16,
    boot_filename: &str,
    bios_bootfile: Option<&str>,
    x64_uefi_bootfile: Option<&str>,
    arm64_uefi_bootfile: Option<&str>,
    ipxe_bootfile: Option<&str>,
    root_path: Option<&str>,
) -> DhcpPacket {
    let arch = client_architecture(request);
    let selected_bootfile = match arch {
        Some(0x0000) => bios_bootfile.unwrap_or(boot_filename),
        Some(0x0007) => x64_uefi_bootfile.unwrap_or(boot_filename),
        Some(0x000B) => arm64_uefi_bootfile.unwrap_or(boot_filename),
        _ => boot_filename,
    };

    let final_bootfile = if request.is_ipxe_client() {
        if let Some(script) = ipxe_bootfile {
            if script.starts_with("http://") || script.starts_with("https://") {
                script.to_string()
            } else {
                format!("http://{}:{}/{}", server_ip, http_port, script)
            }
        } else {
            selected_bootfile.to_string()
        }
    } else if request.is_http_client() {
        format!("http://{}:{}/{}", server_ip, http_port, selected_bootfile)
    } else {
        selected_bootfile.to_string()
    };

    let mut file = [0u8; 128];
    let boot_filename_bytes = final_bootfile.as_bytes();
    let copy_len = boot_filename_bytes.len().min(file.len());
    file[..copy_len].copy_from_slice(&boot_filename_bytes[..copy_len]);

    let server_octets = server_ip.octets();
    let mut boot_servers = Vec::with_capacity(7);
    boot_servers.extend_from_slice(&[0x00, 0x01]); // Type 1: PXE Bootstrap Server
    boot_servers.push(1); // Server count
    boot_servers.extend_from_slice(&server_octets); // Server IP

    let vendor_specific = PxeVendorOptions {
        discovery_control: Some(0x08),
        boot_servers: Some(boot_servers),
        ..Default::default()
    };

    let vendor_class = if request.is_http_client() {
        b"HTTPClient".to_vec()
    } else {
        b"PXEClient".to_vec()
    };

    let mut options = vec![
        DhcpOption::MessageType(reply_type),
        DhcpOption::ServerIdentifier(server_octets),
        DhcpOption::VendorClassIdentifier(vendor_class),
        DhcpOption::TftpServerName(server_ip.to_string().into_bytes()),
        DhcpOption::BootfileName(boot_filename_bytes.to_vec()),
        DhcpOption::VendorSpecific(vendor_specific.serialize()),
    ];

    if let Some(root_path) = root_path {
        options.push(DhcpOption::Unknown(17, root_path.as_bytes().to_vec()));
    }

    for option in &request.options {
        match option {
            DhcpOption::Unknown(93, _)
            | DhcpOption::Unknown(94, _)
            | DhcpOption::Unknown(97, _) => {
                options.push(option.clone());
            }
            _ => {}
        }
    }

    DhcpPacket {
        op: Op::BootReply,
        htype: request.htype,
        hlen: request.hlen,
        hops: 0,
        xid: request.xid,
        secs: request.secs,
        flags: request.flags,
        ciaddr: request.ciaddr,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: server_ip,
        giaddr: request.giaddr,
        chaddr: request.chaddr,
        sname: [0u8; 64],
        file,
        options,
    }
}

pub fn client_architecture(packet: &DhcpPacket) -> Option<u16> {
    packet.options.iter().find_map(|option| match option {
        DhcpOption::Unknown(93, value) if value.len() >= 2 => {
            Some(u16::from_be_bytes([value[0], value[1]]))
        }
        _ => None,
    })
}
