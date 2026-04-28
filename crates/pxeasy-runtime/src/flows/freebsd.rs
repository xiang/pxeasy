use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

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

const FREEBSD_UFS_BLOCK_SIZE: u64 = 32768; // 32KB
const FREEBSD_STAGE_PROGRESS_INTERVAL: u64 = 1_000;

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
        DhcpBoot::ipxe(ipxe_boot_file),
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
        DhcpBoot::ipxe(ipxe_boot_file),
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
        "format=uncompressed-mfsroot-v1\niso_size={}\niso_mtime={}\narch={}\n",
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
    info!("extracting FreeBSD bootonly ISO...");
    let extracted = extract_iso(source_path)?;
    let extracted_root = extracted.path();
    info!("staging FreeBSD boot assets from extracted ISO...");

    // 2. Prepare ESP directory
    let tempdir = tempfile::tempdir()
        .map_err(|err| format!("error: failed to create temporary directory: {err}"))?;
    let esp_dir = tempdir.path().join("esp");
    let efi_boot_dir = esp_dir.join("EFI/BOOT");
    fs::create_dir_all(&efi_boot_dir).map_err(|e| e.to_string())?;

    let efi_name = match arch {
        Architecture::Amd64 => "BOOTX64.EFI",
        Architecture::Arm64 => "BOOTAA64.EFI",
        _ => return Err("error: unsupported architecture for FreeBSD".to_string()),
    };
    fs::copy(
        extracted_root.join("boot/loader.efi"),
        efi_boot_dir.join(efi_name),
    )
    .map_err(|e| format!("error: failed to copy /boot/loader.efi from extracted ISO: {e}"))?;

    // 3. Prepare MFSROOT (UFS image of installer root)
    // We include everything EXCEPT /boot in the mfsroot
    let mfsroot_dir = tempdir.path().join("mfsroot_tree");
    fs::create_dir_all(&mfsroot_dir).map_err(|e| e.to_string())?;
    let mut stage_stats = StageStats::new("mfsroot staging");
    for entry in fs::read_dir(extracted_root)
        .map_err(|e| format!("error: failed to read extracted ISO root: {e}"))?
    {
        let entry = entry.map_err(|e| format!("error: failed to read extracted ISO entry: {e}"))?;
        if entry.file_name() == "boot" {
            continue;
        }
        info!(
            "staging FreeBSD entry {} into mfsroot...",
            entry.path().display()
        );
        copy_dir_entry(
            &entry.path(),
            &mfsroot_dir.join(entry.file_name()),
            &mut stage_stats,
        )?;
    }
    stage_stats.finish();

    // The ISO's /etc/fstab specifies root as cd9660. Override for UFS mfsroot boot.
    fs::write(
        mfsroot_dir.join("etc/fstab"),
        "/dev/md0\t/\tufs\trw\t1\t1\n",
    )
    .map_err(|e| format!("error: failed to write mfsroot fstab: {e}"))?;

    let mfsroot_img = tempdir.path().join("mfsroot.img");
    // Estimate size: sum of files + overhead for UFS fragments and metadata.
    // 27,000+ files require at least 100MB of fragment overhead (4KB min per file).
    info!("estimating staged FreeBSD mfsroot size...");
    let mfsroot_size = dir_size(&mfsroot_dir)? + (150 * 1024 * 1024); // 150MB buffer
    let mfsroot_size = mfsroot_size.div_ceil(FREEBSD_UFS_BLOCK_SIZE) * FREEBSD_UFS_BLOCK_SIZE;
    info!(
        "writing FreeBSD mfsroot UFS image ({} bytes)...",
        mfsroot_size
    );
    let ufs_writer = pxe_ufs::UfsWriter::new(mfsroot_size, "mfsroot");
    ufs_writer
        .write(&mfsroot_dir, &mfsroot_img)
        .map_err(|e| format!("error: UFS write failed: {:?}", e))?;

    // 4. Prepare ROOT directory (contains /boot and uncompressed mfsroot)
    let root_dir = tempdir.path().join("root");
    fs::create_dir_all(&root_dir).map_err(|e| e.to_string())?;
    info!("staging FreeBSD /boot tree into root partition...");
    let mut root_stage_stats = StageStats::new("root staging");
    copy_dir_entry(
        &extracted_root.join("boot"),
        &root_dir.join("boot"),
        &mut root_stage_stats,
    )?;
    root_stage_stats.finish();
    fs::copy(&mfsroot_img, root_dir.join("mfsroot")).map_err(|e| e.to_string())?;

    // 5. Create custom loader.conf
    let loader_conf = "mfsroot_load=\"YES\"\nmfsroot_type=\"mfs_root\"\nmfsroot_name=\"/mfsroot\"\nvfs.root.mountfrom=\"ufs:/dev/md0\"\n".to_string();
    let mut f = File::create(root_dir.join("boot/loader.conf")).map_err(|e| e.to_string())?;
    f.write_all(loader_conf.as_bytes())
        .map_err(|e| e.to_string())?;

    // 6. Assemble final GPT disk image
    let mut disk = DiskImage::new();

    // ESP (32MB)
    disk.add_partition(Partition {
        name: "ESP".to_string(),
        part_type: PartitionType::EfiSystem,
        size_bytes: 32 * 1024 * 1024,
        source: PartitionSource::Directory(esp_dir),
    });

    // ROOT
    info!("estimating FreeBSD root partition size...");
    let root_size = dir_size(&root_dir)? + (128 * 1024 * 1024); // 128MB buffer
    let root_size = root_size.div_ceil(FREEBSD_UFS_BLOCK_SIZE) * FREEBSD_UFS_BLOCK_SIZE;
    disk.add_partition(Partition {
        name: "FREEBSD_ROOT".to_string(),
        part_type: PartitionType::FreeBsdUfs,
        size_bytes: root_size,
        source: PartitionSource::Directory(root_dir),
    });

    info!("assembling final FreeBSD GPT disk image...");
    disk.write(&cached_img)
        .map_err(|e| format!("error: failed to write disk image: {e}"))?;
    fs::write(&cached_meta, expected_meta)
        .map_err(|err| format!("error: failed to write FreeBSD cache metadata: {err}"))?;

    info!("FreeBSD sanboot image prepared successfully");
    Ok(cached_img)
}

struct StageStats {
    label: &'static str,
    started_at: Instant,
    entries: u64,
}

impl StageStats {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            started_at: Instant::now(),
            entries: 0,
        }
    }

    fn record(&mut self, path: &Path) {
        self.entries += 1;
        if self.entries.is_multiple_of(FREEBSD_STAGE_PROGRESS_INTERVAL) {
            info!(
                "{} progress: {} entries processed in {:.1}s (latest: {})",
                self.label,
                self.entries,
                self.started_at.elapsed().as_secs_f32(),
                path.display()
            );
        }
    }

    fn finish(&self) {
        info!(
            "{} complete: {} entries processed in {:.1}s",
            self.label,
            self.entries,
            self.started_at.elapsed().as_secs_f32()
        );
    }
}

fn copy_dir_entry(src: &Path, dest: &Path, stats: &mut StageStats) -> Result<(), String> {
    let metadata = fs::symlink_metadata(src)
        .map_err(|e| format!("error: failed to stat {}: {e}", src.display()))?;
    stats.record(src);
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(src)
            .map_err(|e| format!("error: failed to read symlink {}: {e}", src.display()))?;
        #[cfg(unix)]
        {
            unix_fs::symlink(&target, dest).map_err(|e| {
                format!(
                    "error: failed to copy symlink {} to {}: {e}",
                    src.display(),
                    dest.display()
                )
            })?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            return Err(format!(
                "error: cannot copy symlink {} on this platform",
                src.display()
            ));
        }
    }

    if metadata.is_dir() {
        fs::create_dir_all(dest)
            .map_err(|e| format!("error: failed to create dir {}: {e}", dest.display()))?;
        for entry in fs::read_dir(src)
            .map_err(|e| format!("error: failed to read dir {}: {e}", src.display()))?
        {
            let entry = entry.map_err(|e| format!("error: failed to read entry: {e}"))?;
            copy_dir_entry(&entry.path(), &dest.join(entry.file_name()), stats)?;
        }
        return Ok(());
    }

    fs::copy(src, dest).map(|_| ()).map_err(|e| {
        format!(
            "error: failed to copy {} to {}: {e}",
            src.display(),
            dest.display()
        )
    })
}

fn dir_size(path: &Path) -> Result<u64, String> {
    let mut size = 0;
    for entry in fs::read_dir(path)
        .map_err(|e| format!("error: failed to read dir {}: {e}", path.display()))?
    {
        let entry = entry.map_err(|e| format!("error: failed to read entry: {e}"))?;
        let meta = fs::symlink_metadata(entry.path())
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

#[cfg(test)]
mod tests {
    use super::{copy_dir_entry, dir_size, StageStats};
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs as unix_fs;

    #[cfg(unix)]
    #[test]
    fn copy_dir_entry_preserves_directory_symlinks() {
        let src_root = tempdir().expect("tempdir");
        let dest_root = tempdir().expect("tempdir");

        let include_dir = src_root.path().join("include");
        fs::create_dir_all(&include_dir).expect("create include dir");
        fs::write(include_dir.join("header.h"), "test").expect("write include file");

        let usr_lib = src_root.path().join("usr/lib");
        fs::create_dir_all(&usr_lib).expect("create usr/lib");
        let link_path = usr_lib.join("include");
        unix_fs::symlink("../../include", &link_path).expect("create symlink");

        let copied_link = dest_root.path().join("include");
        let mut stats = StageStats::new("test");
        copy_dir_entry(&link_path, &copied_link, &mut stats).expect("copy symlink");

        let copied_meta = fs::symlink_metadata(&copied_link).expect("copied symlink metadata");
        assert!(copied_meta.file_type().is_symlink());
        assert_eq!(
            fs::read_link(&copied_link).expect("read copied symlink"),
            PathBuf::from("../../include")
        );
    }

    #[cfg(unix)]
    #[test]
    fn dir_size_does_not_follow_directory_symlinks() {
        let root = tempdir().expect("tempdir");
        let include_dir = root.path().join("include");
        fs::create_dir_all(&include_dir).expect("create include dir");
        fs::write(include_dir.join("header.h"), vec![0_u8; 1024]).expect("write include file");

        let usr_lib = root.path().join("usr/lib");
        fs::create_dir_all(&usr_lib).expect("create usr/lib");
        unix_fs::symlink("../../include", usr_lib.join("include")).expect("create symlink");

        let size = dir_size(root.path()).expect("dir size");
        assert!(size < 2048, "unexpected symlink-following size: {size}");
    }
}
