use std::collections::HashMap;

use bytes::Bytes;
use pxe_http::HttpAsset;

/// Build the minimal HTTP asset map shared by NFS boot.
pub fn build_boot_assets(kernel: Vec<u8>, initrd: Vec<u8>) -> HashMap<String, HttpAsset> {
    let mut assets = HashMap::new();
    assets.insert(
        "/boot/linux".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(kernel),
        },
    );
    assets.insert(
        "/boot/initrd".to_string(),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: Bytes::from(initrd),
        },
    );
    assets
}

pub fn add_binary_asset(
    assets: &mut HashMap<String, HttpAsset>,
    path: &str,
    data: impl Into<Bytes>,
) {
    assets.insert(
        normalize_http_asset_path(path),
        HttpAsset::Memory {
            content_type: "application/octet-stream",
            data: data.into(),
        },
    );
}

pub fn add_ipxe_script_asset(
    assets: &mut HashMap<String, HttpAsset>,
    boot_file: &str,
    script: String,
) {
    if boot_file.starts_with("http://") || boot_file.starts_with("https://") {
        return;
    }

    let path = normalize_http_asset_path(boot_file);
    assets.insert(
        path,
        HttpAsset::Memory {
            content_type: "text/plain",
            data: Bytes::from(script),
        },
    );
}

fn normalize_http_asset_path(boot_file: &str) -> String {
    if boot_file.starts_with('/') {
        boot_file.to_string()
    } else {
        format!("/{}", boot_file)
    }
}
