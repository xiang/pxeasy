use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
    thread,
    time::Duration,
};

use bytes::Bytes;

const OPCODE_RRQ: u16 = 1;
const OPCODE_WRQ: u16 = 2;
const OPCODE_DATA: u16 = 3;
const OPCODE_ACK: u16 = 4;
const OPCODE_ERROR: u16 = 5;
const OPCODE_OACK: u16 = 6;

const ERROR_FILE_NOT_FOUND: u16 = 1;
const ERROR_ACCESS_VIOLATION: u16 = 2;
const ERROR_ILLEGAL_OPERATION: u16 = 4;
const ERROR_OPTION_NEGOTIATION: u16 = 8;

const DEFAULT_BLOCK_SIZE: u16 = 512;
const MAX_BLOCK_SIZE: u16 = 65_464;
const DEFAULT_TIMEOUT_SECS: u16 = 5;

/// Static server configuration for the read-only TFTP service.
#[derive(Debug, Clone)]
pub struct TftpConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    pub file_map: HashMap<String, Bytes>,
}

/// Read-only TFTP server that serves files from an in-memory map.
pub struct TftpServer {
    socket: UdpSocket,
    file_map: Arc<HashMap<String, Bytes>>,
}

impl TftpServer {
    /// Bind the listening socket for the server.
    pub fn bind(config: TftpConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(config.bind_ip),
            config.bind_port,
        ))?;
        Ok(Self {
            socket,
            file_map: Arc::new(config.file_map),
        })
    }

    /// Return the socket address the server is listening on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Process incoming requests until the socket returns an error.
    pub fn serve(&self) -> io::Result<()> {
        loop {
            self.serve_once()?;
        }
    }

    /// Process a single incoming request packet.
    pub fn serve_once(&self) -> io::Result<()> {
        let mut buf = [0u8; 65_535];
        let (len, peer) = self.socket.recv_from(&mut buf)?;
        if let Err(err) = self.handle_packet(peer, &buf[..len]) {
            eprintln!("tftp: failed to handle packet from {}: {}", peer, err);
        }
        Ok(())
    }

    fn handle_packet(&self, peer: SocketAddr, packet: &[u8]) -> io::Result<()> {
        let request = match RequestPacket::parse(packet) {
            Ok(Some(request)) => request,
            Ok(None) => {
                eprintln!("tftp: dropping malformed packet from {}", peer);
                return Ok(());
            }
            Err(response) => {
                self.socket.send_to(&response, peer)?;
                return Ok(());
            }
        };

        match request.opcode {
            OPCODE_RRQ => self.handle_rrq(peer, request),
            OPCODE_WRQ => {
                let response =
                    encode_error(ERROR_ILLEGAL_OPERATION, "write requests are not supported");
                self.socket.send_to(&response, peer)?;
                Ok(())
            }
            _ => {
                let response = encode_error(ERROR_ILLEGAL_OPERATION, "unsupported operation");
                self.socket.send_to(&response, peer)?;
                Ok(())
            }
        }
    }

    fn handle_rrq(&self, peer: SocketAddr, request: RequestPacket) -> io::Result<()> {
        let path = match validate_path(&request.filename) {
            Ok(path) => path,
            Err((code, message)) => {
                let response = encode_error(code, message);
                self.socket.send_to(&response, peer)?;
                return Ok(());
            }
        };

        let file = match self.file_map.get(&path) {
            Some(file) => file.clone(),
            None => {
                eprintln!("tftp: requested unknown file {}", path);
                let response = encode_error(ERROR_FILE_NOT_FOUND, "file not found");
                self.socket.send_to(&response, peer)?;
                return Ok(());
            }
        };

        let transfer = match negotiate_transfer(&request.options, file.len()) {
            Ok(transfer) => transfer,
            Err((code, message)) => {
                let response = encode_error(code, message);
                self.socket.send_to(&response, peer)?;
                return Ok(());
            }
        };

        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        socket.set_read_timeout(Some(Duration::from_secs(u64::from(transfer.timeout_secs))))?;
        thread::spawn(move || {
            if let Err(err) = run_transfer(socket, peer, file, transfer) {
                eprintln!("tftp: transfer to {} failed: {}", peer, err);
            }
        });
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestPacket {
    opcode: u16,
    filename: String,
    options: Vec<(String, String)>,
}

impl RequestPacket {
    fn parse(packet: &[u8]) -> Result<Option<Self>, Vec<u8>> {
        if packet.len() < 4 {
            return Ok(None);
        }

        let opcode = u16::from_be_bytes([packet[0], packet[1]]);
        if opcode != OPCODE_RRQ && opcode != OPCODE_WRQ {
            return Err(encode_error(
                ERROR_ILLEGAL_OPERATION,
                "unsupported operation",
            ));
        }

        let parts = match split_nul_terminated(&packet[2..]) {
            Some(parts) => parts,
            None => return Ok(None),
        };

        if parts.len() < 2 {
            return Ok(None);
        }

        let filename = match String::from_utf8(parts[0].to_vec()) {
            Ok(value) if !value.is_empty() => value,
            _ => return Ok(None),
        };
        let mode = match String::from_utf8(parts[1].to_vec()) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };

        if !mode.eq_ignore_ascii_case("octet") {
            return Err(encode_error(
                ERROR_ILLEGAL_OPERATION,
                "only octet mode is supported",
            ));
        }

        let option_parts = &parts[2..];
        if option_parts.len() % 2 != 0 {
            return Ok(None);
        }

        let mut options = Vec::with_capacity(option_parts.len() / 2);
        for pair in option_parts.chunks_exact(2) {
            let key = match String::from_utf8(pair[0].to_vec()) {
                Ok(value) => value.to_ascii_lowercase(),
                Err(_) => return Ok(None),
            };
            let value = match String::from_utf8(pair[1].to_vec()) {
                Ok(value) => value,
                Err(_) => return Ok(None),
            };
            options.push((key, value));
        }

        Ok(Some(Self {
            opcode,
            filename,
            options,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferOptions {
    block_size: u16,
    timeout_secs: u16,
    response_options: Vec<(String, String)>,
}

fn negotiate_transfer(
    options: &[(String, String)],
    file_size: usize,
) -> Result<TransferOptions, (u16, &'static str)> {
    let mut block_size = DEFAULT_BLOCK_SIZE;
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
    let mut response_options = Vec::new();

    for (key, value) in options {
        match key.as_str() {
            "blksize" => {
                let requested = value
                    .parse::<u16>()
                    .map_err(|_| (ERROR_OPTION_NEGOTIATION, "invalid blksize option"))?;
                if requested < 8 {
                    return Err((ERROR_OPTION_NEGOTIATION, "invalid blksize option"));
                }
                block_size = requested.min(MAX_BLOCK_SIZE);
                response_options.push(("blksize".to_string(), block_size.to_string()));
            }
            "timeout" => {
                let requested = value
                    .parse::<u16>()
                    .map_err(|_| (ERROR_OPTION_NEGOTIATION, "invalid timeout option"))?;
                if requested == 0 {
                    return Err((ERROR_OPTION_NEGOTIATION, "invalid timeout option"));
                }
                timeout_secs = requested;
                response_options.push(("timeout".to_string(), timeout_secs.to_string()));
            }
            "tsize" => {
                value
                    .parse::<usize>()
                    .map_err(|_| (ERROR_OPTION_NEGOTIATION, "invalid tsize option"))?;
                response_options.push(("tsize".to_string(), file_size.to_string()));
            }
            _ => {}
        }
    }

    Ok(TransferOptions {
        block_size,
        timeout_secs,
        response_options,
    })
}

fn run_transfer(
    socket: UdpSocket,
    peer: SocketAddr,
    file: Bytes,
    options: TransferOptions,
) -> io::Result<()> {
    if !options.response_options.is_empty() {
        let packet = encode_oack(&options.response_options);
        socket.send_to(&packet, peer)?;
        wait_for_ack(&socket, peer, 0)?;
    }

    let mut offset = 0usize;
    let mut block = 1u16;
    loop {
        let chunk_len = usize::from(options.block_size).min(file.len().saturating_sub(offset));
        let chunk = &file[offset..offset + chunk_len];
        send_data_block(&socket, peer, block, chunk)?;

        wait_for_ack(&socket, peer, block)?;
        offset += chunk_len;

        if chunk_len < usize::from(options.block_size) {
            break;
        }

        block = block.wrapping_add(1);
    }

    Ok(())
}

fn wait_for_ack(socket: &UdpSocket, peer: SocketAddr, expected_block: u16) -> io::Result<()> {
    let mut buf = [0u8; 65_535];
    loop {
        let (len, from) = socket.recv_from(&mut buf)?;
        if from != peer {
            continue;
        }

        match AckPacket::parse(&buf[..len]) {
            Some(block) if block == expected_block => return Ok(()),
            Some(_) => continue,
            None => continue,
        }
    }
}

fn send_data_block(
    socket: &UdpSocket,
    peer: SocketAddr,
    block: u16,
    payload: &[u8],
) -> io::Result<()> {
    let packet = encode_data(block, payload);
    socket.send_to(&packet, peer)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AckPacket;

impl AckPacket {
    fn parse(packet: &[u8]) -> Option<u16> {
        if packet.len() != 4 {
            return None;
        }
        let opcode = u16::from_be_bytes([packet[0], packet[1]]);
        if opcode != OPCODE_ACK {
            return None;
        }
        Some(u16::from_be_bytes([packet[2], packet[3]]))
    }
}

fn validate_path(path: &str) -> Result<String, (u16, &'static str)> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err((ERROR_ACCESS_VIOLATION, "invalid path"));
    }

    let mut normalized = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err((ERROR_ACCESS_VIOLATION, "invalid path"));
        }
        normalized.push(component);
    }

    Ok(normalized.join("/"))
}

fn split_nul_terminated(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    if bytes.last().copied() != Some(0) {
        return None;
    }

    let mut parts = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == 0 {
            parts.push(&bytes[start..index]);
            start = index + 1;
        }
    }
    Some(parts)
}

fn encode_data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&OPCODE_DATA.to_be_bytes());
    packet.extend_from_slice(&block.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn encode_error(code: u16, message: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(5 + message.len());
    packet.extend_from_slice(&OPCODE_ERROR.to_be_bytes());
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend_from_slice(message.as_bytes());
    packet.push(0);
    packet
}

fn encode_oack(options: &[(String, String)]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&OPCODE_OACK.to_be_bytes());
    for (key, value) in options {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rrq(filename: &str, mode: &str, options: &[(&str, &str)]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&OPCODE_RRQ.to_be_bytes());
        packet.extend_from_slice(filename.as_bytes());
        packet.push(0);
        packet.extend_from_slice(mode.as_bytes());
        packet.push(0);
        for (key, value) in options {
            packet.extend_from_slice(key.as_bytes());
            packet.push(0);
            packet.extend_from_slice(value.as_bytes());
            packet.push(0);
        }
        packet
    }

    fn parse_error(packet: &[u8]) -> Option<(u16, String)> {
        if packet.len() < 5 || u16::from_be_bytes([packet[0], packet[1]]) != OPCODE_ERROR {
            return None;
        }
        let code = u16::from_be_bytes([packet[2], packet[3]]);
        let message = packet[4..packet.len() - 1].to_vec();
        String::from_utf8(message)
            .ok()
            .map(|message| (code, message))
    }

    #[test]
    fn request_parser_accepts_octet_mode_and_options() {
        let packet = rrq("boot.ipxe", "octet", &[("blksize", "1024"), ("tsize", "0")]);

        let request = RequestPacket::parse(&packet)
            .expect("request should not emit error response")
            .expect("request should parse");

        assert_eq!(request.opcode, OPCODE_RRQ);
        assert_eq!(request.filename, "boot.ipxe");
        assert_eq!(
            request.options,
            vec![
                ("blksize".to_string(), "1024".to_string()),
                ("tsize".to_string(), "0".to_string()),
            ]
        );
    }

    #[test]
    fn request_parser_rejects_non_octet_mode() {
        let packet = rrq("boot.ipxe", "netascii", &[]);

        let response = RequestPacket::parse(&packet).expect_err("mode should be rejected");

        assert_eq!(
            parse_error(&response),
            Some((
                ERROR_ILLEGAL_OPERATION,
                "only octet mode is supported".to_string()
            ))
        );
    }

    #[test]
    fn path_validation_rejects_parent_components() {
        let result = validate_path("../boot.ipxe");

        assert_eq!(result, Err((ERROR_ACCESS_VIOLATION, "invalid path")));
    }

    #[test]
    fn transfer_negotiation_clamps_block_size_and_reports_tsize() {
        let options = vec![
            ("blksize".to_string(), "65535".to_string()),
            ("tsize".to_string(), "0".to_string()),
            ("timeout".to_string(), "7".to_string()),
        ];

        let transfer = negotiate_transfer(&options, 4096).expect("options should negotiate");

        assert_eq!(transfer.block_size, MAX_BLOCK_SIZE);
        assert_eq!(transfer.timeout_secs, 7);
        assert_eq!(
            transfer.response_options,
            vec![
                ("blksize".to_string(), MAX_BLOCK_SIZE.to_string()),
                ("tsize".to_string(), "4096".to_string()),
                ("timeout".to_string(), "7".to_string()),
            ]
        );
    }

    #[test]
    fn server_rejects_unknown_file() {
        let server = TftpServer::bind(TftpConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 0,
            file_map: HashMap::new(),
        })
        .expect("bind should succeed");
        let server_addr = server.local_addr().expect("server should expose address");
        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("client bind should succeed");

        let handle = thread::spawn(move || server.serve_once());
        client
            .send_to(&rrq("missing.efi", "octet", &[]), server_addr)
            .expect("request should send");

        let mut buf = [0u8; 1024];
        let (len, _) = client.recv_from(&mut buf).expect("server should reply");
        let join_result = handle.join().expect("server thread should join");
        assert!(join_result.is_ok());

        assert_eq!(
            parse_error(&buf[..len]),
            Some((ERROR_FILE_NOT_FOUND, "file not found".to_string()))
        );
    }

    #[test]
    fn server_serves_file_with_oack_and_data() {
        let mut files = HashMap::new();
        files.insert(
            "boot.ipxe".to_string(),
            Bytes::from_static(b"chain http://boot\n"),
        );

        let server = TftpServer::bind(TftpConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 0,
            file_map: files,
        })
        .expect("bind should succeed");
        let server_addr = server.local_addr().expect("server should expose address");
        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("client bind should succeed");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout should be set");

        let handle = thread::spawn(move || server.serve_once());
        client
            .send_to(
                &rrq("boot.ipxe", "octet", &[("blksize", "8"), ("tsize", "0")]),
                server_addr,
            )
            .expect("request should send");

        let mut buf = [0u8; 1024];
        let (oack_len, transfer_addr) =
            client.recv_from(&mut buf).expect("server should send oack");
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), OPCODE_OACK);
        assert_eq!(
            &buf[2..oack_len],
            &[
                b'b', b'l', b'k', b's', b'i', b'z', b'e', 0, b'8', 0, b't', b's', b'i', b'z', b'e',
                0, b'1', b'8', 0,
            ]
        );

        client
            .send_to(&[0, OPCODE_ACK as u8, 0, 0], transfer_addr)
            .expect("ack 0 should send");

        let mut received = Vec::new();
        loop {
            let (len, from) = client.recv_from(&mut buf).expect("server should send data");
            assert_eq!(from, transfer_addr);
            assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), OPCODE_DATA);
            let block = u16::from_be_bytes([buf[2], buf[3]]);
            received.extend_from_slice(&buf[4..len]);

            client
                .send_to(
                    &[0, OPCODE_ACK as u8, (block >> 8) as u8, block as u8],
                    transfer_addr,
                )
                .expect("ack should send");

            if len < 12 {
                break;
            }
        }

        let join_result = handle.join().expect("server thread should join");
        assert!(join_result.is_ok());
        assert_eq!(received, b"chain http://boot\n");
    }
}
