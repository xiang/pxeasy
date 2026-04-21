use std::net::Ipv4Addr;

use if_addrs::{get_if_addrs, IfAddr};

#[derive(Debug, Clone)]
pub struct NetworkSelection {
    pub name: String,
    pub ip: Ipv4Addr,
}

pub fn resolve_network(
    interface: Option<&str>,
    bind_ip: Option<Ipv4Addr>,
) -> Result<NetworkSelection, String> {
    let interfaces =
        get_if_addrs().map_err(|err| format!("error: failed to enumerate interfaces: {err}"))?;

    let mut matches = interfaces.into_iter().filter_map(|iface| {
        if iface.is_loopback() {
            return None;
        }

        let IfAddr::V4(addr) = iface.addr else {
            return None;
        };

        if let Some(expected_name) = interface {
            if iface.name != expected_name {
                return None;
            }
        }

        if let Some(expected_ip) = bind_ip {
            if addr.ip != expected_ip {
                return None;
            }
        }

        Some(NetworkSelection {
            name: iface.name,
            ip: addr.ip,
        })
    });

    if let Some(selection) = matches.next() {
        return Ok(selection);
    }

    match (interface, bind_ip) {
        (Some(name), Some(ip)) => Err(format!(
            "error: no IPv4 address {} found on interface {}; adjust --interface/--bind",
            ip, name
        )),
        (Some(name), None) => Err(format!(
            "error: interface {} has no usable IPv4 address",
            name
        )),
        (None, Some(ip)) => Err(format!(
            "error: bind address {} does not match any non-loopback interface",
            ip
        )),
        (None, None) => Err("error: no non-loopback interface found; use --interface".to_string()),
    }
}
