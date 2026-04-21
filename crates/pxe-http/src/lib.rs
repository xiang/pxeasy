use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const FILE_STREAM_CHUNK: usize = 128 * 1024; // 128 KiB

use bytes::Bytes;

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    pub assets: HashMap<String, HttpAsset>,
}

#[derive(Debug, Clone)]
pub enum HttpAsset {
    Memory {
        content_type: &'static str,
        data: Bytes,
    },
    File {
        content_type: &'static str,
        path: PathBuf,
    },
    IsoSlice {
        content_type: &'static str,
        path: PathBuf,
        offset: u64,
        length: u64,
    },
}

pub struct HttpServer {
    listener: TcpListener,
    assets: Arc<HashMap<String, HttpAsset>>,
}

impl HttpServer {
    pub fn bind(config: HttpConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(config.bind_ip),
            config.bind_port,
        ))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            assets: Arc::new(config.assets),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn serve_until_shutdown(&self, shutdown: &Arc<AtomicBool>) -> io::Result<()> {
        let mut threads = Vec::new();
        while !shutdown.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // Accepted sockets inherit the listener's non-blocking flag on macOS.
                    // Connection threads use blocking I/O, so reset it explicitly.
                    if let Err(err) = stream.set_nonblocking(false) {
                        log::warn!("http: failed to set stream blocking: {}", err);
                        continue;
                    }
                    let assets = Arc::clone(&self.assets);
                    let handle = thread::spawn(move || {
                        if let Err(err) = handle_connection(stream, &assets) {
                            // Suppress generic broken pipe errors from clients closing early
                            if err.kind() != io::ErrorKind::BrokenPipe
                                && err.kind() != io::ErrorKind::ConnectionReset
                            {
                                log::warn!("http: connection failed: {}", err);
                            }
                        }
                    });
                    threads.push(handle);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(SHUTDOWN_POLL_INTERVAL);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn handle_connection(mut stream: TcpStream, assets: &HashMap<String, HttpAsset>) -> io::Result<()> {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    let mut buf = [0; 4096];
    let mut request_data = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        request_data.extend_from_slice(&buf[..n]);
        if request_data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if request_data.len() > 8192 {
            return Ok(()); // Avoid arbitrary large headers memory exhaustion
        }
    }

    let req_str = String::from_utf8_lossy(&request_data);
    let mut lines = req_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let head_only = method == "HEAD";
    if method != "GET" && method != "HEAD" {
        send_response(
            &mut stream,
            (405, "Method Not Allowed"),
            "text/plain; charset=utf-8",
            None,
            18,
            b"method not allowed",
            head_only,
        )?;
        log::debug!("http: {} {} from {} -> 405", method, path, peer);
        return Ok(());
    }

    if path == "/health" {
        send_response(
            &mut stream,
            (200, "OK"),
            "text/plain; charset=utf-8",
            None,
            3,
            b"ok\n",
            head_only,
        )?;
        log::trace!("http: {} {} from {} -> 200", method, path, peer);
        return Ok(());
    }

    let mut range_header = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("range") {
                range_header = Some(v.trim().to_string());
            }
        }
    }

    let level = if range_header.is_none() {
        log::Level::Debug
    } else {
        log::Level::Trace
    };
    log::log!(
        level,
        "http: {} {} from {} range={:?}",
        method,
        path,
        peer,
        range_header
    );

    let asset = match assets.get(path) {
        Some(a) => a,
        None => {
            send_response(
                &mut stream,
                (404, "Not Found"),
                "text/plain; charset=utf-8",
                None,
                9,
                b"not found",
                head_only,
            )?;
            log::warn!("http: {} {} from {} -> 404", method, path, peer);
            return Ok(());
        }
    };

    match serve_asset(&mut stream, path, asset, range_header.as_deref(), head_only) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            log::warn!("http: {} {} from {} -> 416 ({})", method, path, peer, err);
            send_response(
                &mut stream,
                (416, "Range Not Satisfiable"),
                "text/plain; charset=utf-8",
                None,
                21,
                b"range not satisfiable",
                head_only,
            )
        }
        Err(err) => {
            log::warn!("http: {} {} from {} -> 500 ({})", method, path, peer, err);
            send_response(
                &mut stream,
                (500, "Internal Server Error"),
                "text/plain; charset=utf-8",
                None,
                21,
                b"internal server error",
                head_only,
            )
        }
    }
}

fn serve_asset(
    stream: &mut TcpStream,
    request_path: &str,
    asset: &HttpAsset,
    range_header: Option<&str>,
    head_only: bool,
) -> io::Result<()> {
    match asset {
        HttpAsset::Memory { content_type, data } => {
            let full_len = data.len() as u64;
            let range = parse_range(range_header, full_len)?;
            let status_code = if range.is_some() { 206 } else { 200 };
            let status_msg = if range.is_some() {
                "Partial Content"
            } else {
                "OK"
            };
            let (start, end) = range.unwrap_or((0, full_len.saturating_sub(1)));
            let body_len = if full_len == 0 {
                0
            } else {
                end.saturating_sub(start).saturating_add(1)
            };
            let range_hdr = range.map(|(s, e)| format!("bytes {}-{}/{}", s, e, full_len));
            let level = if range_header.is_none() {
                log::Level::Debug
            } else {
                log::Level::Trace
            };
            log::log!(
                level,
                "http: serving memory {} len={} body_len={} range={:?} head_only={}",
                request_path,
                full_len,
                body_len,
                range_header,
                head_only
            );
            let body = if head_only || full_len == 0 {
                Bytes::new()
            } else {
                data.slice(start as usize..=end as usize)
            };
            send_response(
                stream,
                (status_code, status_msg),
                content_type,
                range_hdr.as_deref(),
                body_len,
                &body,
                head_only,
            )
        }
        HttpAsset::File { content_type, path } => {
            let full_len = std::fs::metadata(path)?.len();
            serve_sliced_file(
                stream,
                request_path,
                content_type,
                path,
                0,
                full_len,
                range_header,
                head_only,
            )
        }
        HttpAsset::IsoSlice {
            content_type,
            path,
            offset,
            length,
        } => serve_sliced_file(
            stream,
            request_path,
            content_type,
            path,
            *offset,
            *length,
            range_header,
            head_only,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_sliced_file(
    stream: &mut TcpStream,
    request_path: &str,
    content_type: &str,
    path: &PathBuf,
    offset: u64,
    full_len: u64,
    range_header: Option<&str>,
    head_only: bool,
) -> io::Result<()> {
    let range = parse_range(range_header, full_len)?;
    let status_code = if range.is_some() { 206 } else { 200 };
    let status_msg = if range.is_some() {
        "Partial Content"
    } else {
        "OK"
    };
    let (start, end) = range.unwrap_or((0, full_len.saturating_sub(1)));
    let body_len = if full_len == 0 {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    };
    let range_hdr = range.map(|(s, e)| format!("bytes {}-{}/{}", s, e, full_len));
    let level = if range_header.is_none() {
        log::Level::Debug
    } else {
        log::Level::Trace
    };
    log::log!(
        level,
        "http: serving file {} src={} offset={} len={} body_len={} range={:?} head_only={}",
        request_path,
        path.display(),
        offset,
        full_len,
        body_len,
        range_header,
        head_only
    );
    // Send headers first, then stream body in chunks — avoids reading entire file into RAM.
    send_response(
        stream,
        (status_code, status_msg),
        content_type,
        range_hdr.as_deref(),
        body_len,
        &[],
        head_only,
    )?;
    if !head_only && body_len > 0 {
        stream_file(stream, path, offset + start, body_len)?;
    }
    Ok(())
}

fn stream_file(stream: &mut TcpStream, path: &PathBuf, start: u64, len: u64) -> io::Result<()> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut writer = BufWriter::new(stream);
    let mut remaining = len;
    let mut buf = [0u8; FILE_STREAM_CHUNK];
    while remaining > 0 {
        let to_read = (remaining as usize).min(FILE_STREAM_CHUNK);
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    writer.flush()
}

fn send_response(
    stream: &mut TcpStream,
    status: (u16, &str),
    content_type: &str,
    content_range: Option<&str>,
    content_length: u64,
    body: &[u8],
    head_only: bool,
) -> io::Result<()> {
    let mut header = format!("HTTP/1.1 {} {}\r\n", status.0, status.1);
    header.push_str(&format!("Content-Type: {}\r\n", content_type));
    header.push_str(&format!("Content-Length: {}\r\n", content_length));
    header.push_str("Accept-Ranges: bytes\r\n");
    header.push_str("Connection: close\r\n");
    if let Some(cr) = content_range {
        header.push_str(&format!("Content-Range: {}\r\n", cr));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    Ok(())
}

fn parse_range(range_header: Option<&str>, length: u64) -> io::Result<Option<(u64, u64)>> {
    let Some(header) = range_header else {
        return Ok(None);
    };
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot serve ranges for empty content",
        ));
    }

    let Some(spec) = header.strip_prefix("bytes=") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported range unit",
        ));
    };
    if spec.contains(',') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multiple ranges are not supported",
        ));
    }

    let (start, end) = spec
        .split_once('-')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "malformed range"))?;
    let start = start
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid range start"))?;
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid range end"))?
    };

    if start > end || end >= length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range not satisfiable",
        ));
    }

    Ok(Some((start, end)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpStream,
        sync::atomic::AtomicBool,
        thread,
    };

    fn request(server: &HttpServer, raw_request: &str) -> String {
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let server = HttpServer {
            listener: server.listener.try_clone().expect("clone listener"),
            assets: Arc::clone(&server.assets),
        };
        let addr = server.local_addr().expect("local addr");

        let handle = thread::spawn(move || server.serve_until_shutdown(&server_shutdown));

        let mut stream;
        loop {
            if let Ok(s) = TcpStream::connect(addr) {
                stream = s;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        stream
            .write_all(raw_request.as_bytes())
            .expect("write request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");

        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        shutdown.store(true, Ordering::SeqCst);
        handle
            .join()
            .expect("server thread")
            .expect("server result");
        response
    }

    fn test_server() -> HttpServer {
        let mut assets = HashMap::new();
        assets.insert(
            "/boot/vmlinuz".to_string(),
            HttpAsset::Memory {
                content_type: "application/octet-stream",
                data: Bytes::from_static(b"abcdefgh"),
            },
        );
        HttpServer::bind(HttpConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_port: 0,
            assets,
        })
        .expect("bind")
    }

    fn test_iso_slice_server() -> (HttpServer, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "pxe-http-iso-slice-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, b"0123456789abcdef").expect("write temp file");

        let mut assets = HashMap::new();
        assets.insert(
            "/boot/slice".to_string(),
            HttpAsset::IsoSlice {
                content_type: "application/octet-stream",
                path: path.clone(),
                offset: 4,
                length: 6,
            },
        );

        (
            HttpServer::bind(HttpConfig {
                bind_ip: Ipv4Addr::LOCALHOST,
                bind_port: 0,
                assets,
            })
            .expect("bind"),
            path,
        )
    }

    #[test]
    fn health_returns_ok() {
        let server = test_server();
        let response = request(
            &server,
            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok\n"));
    }

    #[test]
    fn range_request_returns_partial_content() {
        let server = test_server();
        let response = request(
            &server,
            "GET /boot/vmlinuz HTTP/1.1\r\nHost: localhost\r\nRange: bytes=2-4\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(
            response.contains("Content-Range: bytes 2-4/8")
                || response.contains("content-range: bytes 2-4/8")
        );
        assert!(response.ends_with("cde"));
    }

    #[test]
    fn iso_slice_uses_base_offset_for_ranges() {
        let (server, path) = test_iso_slice_server();
        let response = request(
            &server,
            "GET /boot/slice HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1-3\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(
            response.contains("Content-Range: bytes 1-3/6")
                || response.contains("content-range: bytes 1-3/6")
        );
        assert!(response.ends_with("567"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_range_returns_416() {
        let server = test_server();
        let response = request(
            &server,
            "GET /boot/vmlinuz HTTP/1.1\r\nHost: localhost\r\nRange: bytes=999-1000\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 416 Range Not Satisfiable"));
    }

    #[test]
    fn unknown_path_returns_not_found() {
        let server = test_server();
        let response = request(
            &server,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }
}
