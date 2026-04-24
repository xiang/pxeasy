use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use log::{debug, info};
use pxe_diskimg::{DiskImage, Partition, PartitionSource, PartitionType};
use pxe_http::HttpAsset;
use pxe_profiles::{Architecture, LinuxProfile};

use crate::boot::add_ipxe_script_asset;
use crate::host::iso::extract_iso;
use crate::network::NetworkSelection;
use crate::runtime::RuntimeSession;
use crate::services::DhcpBoot;
use crate::{
    default_ipxe_tftp_files, is_iso, pxeasy_home_dir, require_known_architecture, run_core_start,
    DEFAULT_HTTP_PORT,
};

const FREEBSD_MFS_DISK_SIZE: u64 = 1024 * 1024 * 1024; // 1GB default
const FREEBSD_UFS_BLOCK_SIZE: u64 = 32768; // 32KB

pub fn run_freebsd_start(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: LinuxProfile,
) -> Result<RuntimeSession, String> {
    if !is_freebsd_boot_image(&source_path) {
        return Err("error: FreeBSD boot requires an ISO or memstick disk image".to_string());
    }

    if is_iso(&source_path) {
        return run_freebsd_iso_start_sanboot(source_path, ipxe_boot_file, network, profile);
    }

    // Existing direct image boot (memstick)
    let arch = require_known_architecture(profile.architecture)?;

    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let sanboot_url = format!("http://{}:{}/disk.img", network.ip, DEFAULT_HTTP_PORT);
    let ipxe_script = format!("#!ipxe\nsanboot {sanboot_url}\n");

    let mut assets = HashMap::new();
    assets.insert(
        "/disk.img".to_string(),
        HttpAsset::File {
            content_type: "application/octet-stream",
            path: source_path,
        },
    );
    add_ipxe_script_asset(&mut assets, &ipxe_boot_file, ipxe_script);

    run_core_start(
        profile.label,
        network,
        assets,
        default_ipxe_tftp_files(arch)?,
        DhcpBoot {
            first_stage_bootfile: "ipxe.efi".to_string(),
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: None,
            ipxe_bootfile: Some(ipxe_boot_file),
            root_path: None,
        },
        None,
    )
}

fn run_freebsd_iso_start_sanboot(
    source_path: PathBuf,
    ipxe_boot_file: Option<String>,
    network: NetworkSelection,
    profile: LinuxProfile,
) -> Result<RuntimeSession, String> {
    let arch = require_known_architecture(profile.architecture)?;

    // 1. Check/Generate Custom MFS Image
    let cached_img = prepare_freebsd_mfs_image(&source_path, arch)?;

    // 2. Prepare HTTP assets
    let mut assets = HashMap::new();
    assets.insert(
        "/freebsd.img".to_string(),
        HttpAsset::File {
            content_type: "application/octet-stream",
            path: cached_img,
        },
    );

    let ipxe_boot_file = ipxe_boot_file.unwrap_or_else(|| "boot.ipxe".to_string());
    let sanboot_url = format!("http://{}:{}/freebsd.img", network.ip, DEFAULT_HTTP_PORT);
    let ipxe_script = format!("#!ipxe\nsanboot {sanboot_url}\n");
    add_ipxe_script_asset(&mut assets, &ipxe_boot_file, ipxe_script);

    run_core_start(
        profile.label,
        network,
        assets,
        default_ipxe_tftp_files(arch)?,
        DhcpBoot {
            first_stage_bootfile: "ipxe.efi".to_string(),
            bios_bootfile: None,
            x64_uefi_bootfile: None,
            arm64_uefi_bootfile: None,
            ipxe_bootfile: Some(ipxe_boot_file),
            root_path: None,
        },
        None,
    )
}

fn prepare_freebsd_mfs_image(source_path: &Path, arch: Architecture) -> Result<PathBuf, String> {
    let source_metadata = fs::metadata(source_path)
        .map_err(|err| format!("error: failed to stat {}: {err}", source_path.display()))?;
    let modified = source_metadata
        .modified()
        .map_err(|err| format!("error: failed to read ISO mtime: {err}"))?;
    let modified_secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("error: failed to normalize ISO mtime: {err}"))?
        .as_secs();

    let arch_slug = arch.slug().unwrap_or("unknown");
    let cache_dir = pxeasy_home_dir()?.join("freebsd");
    fs::create_dir_all(&cache_dir)
        .map_err(|err| format!("error: failed to create FreeBSD cache dir: {err}"))?;

    let cached_img = cache_dir.join(format!("freebsd-{}.img", arch_slug));
    let cached_meta = cache_dir.join(format!("freebsd-{}.meta", arch_slug));
    let expected_meta = format!(
        "iso_size={}\niso_mtime={}\narch={}\n",
        source_metadata.len(),
        modified_secs,
        arch_slug
    );

    if cached_img.exists() {
        if let Ok(existing_meta) = fs::read_to_string(&cached_meta) {
            if existing_meta == expected_meta {
                debug!(
                    "using cached FreeBSD sanboot image: {}",
                    cached_img.display()
                );
                return Ok(cached_img);
            }
        }
    }

    info!("generating custom FreeBSD sanboot image (this may take a minute)...");

    // 1. Extract ISO
    let extracted_iso = extract_iso(source_path)?;
    let iso_root = extracted_iso.path();

    // 2. Prepare ESP directory
    let tempdir = tempfile::tempdir()
        .map_err(|err| format!("error: failed to create temporary directory: {err}"))?;
    let esp_dir = tempdir.path().join("esp");
    let efi_boot_dir = esp_dir.join("EFI/BOOT");
    fs::create_dir_all(&efi_boot_dir).map_err(|e| e.to_string())?;

    let loader_efi_src = iso_root.join("boot/loader.efi");
    let efi_name = match arch {
        Architecture::Amd64 => "BOOTX64.EFI",
        Architecture::Arm64 => "BOOTAA64.EFI",
        _ => return Err("error: unsupported architecture for FreeBSD".to_string()),
    };
    fs::copy(&loader_efi_src, efi_boot_dir.join(efi_name)).map_err(|e| e.to_string())?;

    // 3. Prepare MFSROOT (UFS image of installer root)
    // We include everything EXCEPT /boot in the mfsroot
    let mfsroot_dir = tempdir.path().join("mfsroot_tree");
    fs::create_dir_all(&mfsroot_dir).map_err(|e| e.to_string())?;

    for entry in
        fs::read_dir(iso_root).map_err(|e| format!("error: failed to read ISO root: {e}"))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        if name == "boot" {
            continue;
        }
        let dest = mfsroot_dir.join(&name);
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            copy_dir_recursive(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest).map_err(|e| e.to_string())?;
        }
    }

    let mfsroot_img = tempdir.path().join("mfsroot.img");
    // Estimate size: sum of files + 20% overhead
    let mfsroot_size = dir_size(&mfsroot_dir)? + (50 * 1024 * 1024); // Add 50MB overhead
    let mfsroot_size = mfsroot_size.div_ceil(FREEBSD_UFS_BLOCK_SIZE) * FREEBSD_UFS_BLOCK_SIZE;
    let ufs_writer = pxe_ufs::UfsWriter::new(mfsroot_size, "mfsroot");
    ufs_writer
        .write(&mfsroot_dir, &mfsroot_img)
        .map_err(|e| format!("error: UFS write failed: {:?}", e))?;

    // 4. Gzip mfsroot
    let mfsroot_gz = tempdir.path().join("mfsroot.gz");
    let mut mfs_file = File::open(&mfsroot_img).map_err(|e| e.to_string())?;
    let gz_file = File::create(&mfsroot_gz).map_err(|e| e.to_string())?;
    let mut encoder = flate2::write::GzEncoder::new(gz_file, flate2::Compression::default());
    std::io::copy(&mut mfs_file, &mut encoder).map_err(|e| e.to_string())?;
    encoder.finish().map_err(|e| e.to_string())?;

    // 5. Prepare ROOT directory (contains /boot and mfsroot.gz)
    let root_dir = tempdir.path().join("root");
    fs::create_dir_all(&root_dir).map_err(|e| e.to_string())?;
    copy_dir_recursive(&iso_root.join("boot"), &root_dir.join("boot"))?;
    fs::copy(&mfsroot_gz, root_dir.join("mfsroot.gz")).map_err(|e| e.to_string())?;

    // 6. Create custom loader.conf
    let loader_conf = "mfsroot_load=\"YES\"\nmfsroot_type=\"mfs_root\"\nmfsroot_name=\"/mfsroot.gz\"\nvfs.root.mountfrom=\"ufs:/dev/md0\"\n".to_string();
    let mut f = File::create(root_dir.join("boot/loader.conf")).map_err(|e| e.to_string())?;
    f.write_all(loader_conf.as_bytes())
        .map_err(|e| e.to_string())?;

    // 7. Assemble final GPT disk image
    let mut disk = DiskImage::new(FREEBSD_MFS_DISK_SIZE);

    // ESP (32MB)
    disk.add_partition(Partition {
        name: "ESP".to_string(),
        part_type: PartitionType::EfiSystem,
        size_bytes: 32 * 1024 * 1024,
        source: PartitionSource::Directory(esp_dir),
    });

    // ROOT
    let root_size = dir_size(&root_dir)? + (64 * 1024 * 1024); // 64MB buffer
    let root_size = root_size.div_ceil(FREEBSD_UFS_BLOCK_SIZE) * FREEBSD_UFS_BLOCK_SIZE;
    disk.add_partition(Partition {
        name: "FREEBSD_ROOT".to_string(),
        part_type: PartitionType::FreeBsdUfs,
        size_bytes: root_size,
        source: PartitionSource::Directory(root_dir),
    });

    disk.write(&cached_img)
        .map_err(|e| format!("error: failed to write disk image: {e}"))?;
    fs::write(&cached_meta, expected_meta)
        .map_err(|err| format!("error: failed to write FreeBSD cache metadata: {err}"))?;

    info!("FreeBSD sanboot image prepared successfully");
    Ok(cached_img)
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest)
        .map_err(|e| format!("error: failed to create dir {}: {e}", dest.display()))?;
    for entry in fs::read_dir(src)
        .map_err(|e| format!("error: failed to read dir {}: {e}", src.display()))?
    {
        let entry = entry.map_err(|e| format!("error: failed to read entry: {e}"))?;
        let path = entry.path();
        let dest_path = dest.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|e| format!("error: failed to stat {}: {e}", path.display()))?
            .is_dir()
        {
            copy_dir_recursive(&path, &dest_path)?;
        } else {
            fs::copy(&path, &dest_path).map_err(|e| {
                format!(
                    "error: failed to copy {} to {}: {e}",
                    path.display(),
                    dest_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn dir_size(path: &Path) -> Result<u64, String> {
    let mut size = 0;
    for entry in fs::read_dir(path)
        .map_err(|e| format!("error: failed to read dir {}: {e}", path.display()))?
    {
        let entry = entry.map_err(|e| format!("error: failed to read entry: {e}"))?;
        let meta = entry
            .metadata()
            .map_err(|e| format!("error: failed to stat {}: {e}", entry.path().display()))?;
        if meta.is_dir() {
            size += dir_size(&entry.path())?;
        } else {
            size += meta.len();
        }
    }
    Ok(size)
}

pub fn is_freebsd_boot_image(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("iso")
                || ext.eq_ignore_ascii_case("img")
                || ext.eq_ignore_ascii_case("raw")
        })
}
