use std::time::SystemTime;

pub fn system_time_filetime() -> u64 {
    let now = SystemTime::now();
    let since_epoch = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // 1601 to 1970 is 11,644,473,600 seconds
    (since_epoch.as_secs() + 11_644_473_600) * 10_000_000
        + (since_epoch.as_nanos() as u64 % 1_000_000_000) / 100
}

pub fn encode_utf16_bytes(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    utf16.iter().flat_map(|c| c.to_le_bytes()).collect()
}

pub fn wildcard_match(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Simple case-insensitive match for now
    name.to_lowercase() == pattern.to_lowercase()
}
