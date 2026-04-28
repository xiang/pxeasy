use anyhow::{Context, Result};
use gpt::GptConfig;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub enum PartitionType {
    EfiSystem,
    FreeBsdUfs,
    MsDosData,
}

pub enum PartitionSource {
    Directory(PathBuf),
    ImageFile(PathBuf),
}

pub struct Partition {
    pub name: String,
    pub part_type: PartitionType,
    pub size_bytes: u64,
    pub source: PartitionSource,
}

pub struct DiskImage {
    pub partitions: Vec<Partition>,
}

impl DiskImage {
    pub fn new() -> Self {
        Self {
            partitions: Vec::new(),
        }
    }
}

impl Default for DiskImage {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskImage {
    pub fn add_partition(&mut self, part: Partition) {
        self.partitions.push(part);
    }

    pub fn write(&self, output: &Path) -> Result<()> {
        let block_size = 512u64;
        let alignment = 1024 * 1024u64; // 1MiB alignment
        let gpt_overhead = 1024 * 1024u64; // 1MiB for primary GPT + 1MiB for backup

        // 1. Calculate layout and total size
        let mut current_offset = alignment; // Start first partition at 1MiB (LBA 2048)
        let mut partition_layouts = Vec::new();

        for part in &self.partitions {
            // Align start offset to 1MiB
            let start = current_offset.div_ceil(alignment) * alignment;
            partition_layouts.push((start, part.size_bytes));
            current_offset = start + part.size_bytes;
        }

        // Align total size and add space for backup GPT
        let total_size = current_offset.div_ceil(alignment) * alignment + gpt_overhead;

        log::debug!(
            "DiskImage: total size {}, overhead {}, {} partitions",
            total_size,
            gpt_overhead,
            self.partitions.len()
        );

        // 2. Create the base file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output)
            .context("Failed to create disk image file")?;
        file.set_len(total_size)?;

        // 3. Initialize GPT
        let mut disk = GptConfig::new()
            .initialized(false)
            .writable(true)
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open(output)?;

        disk.update_partitions(std::collections::BTreeMap::new())?;

        // 4. Add partitions
        for (i, part) in self.partitions.iter().enumerate() {
            let guid = match part.part_type {
                PartitionType::EfiSystem => gpt::partition_types::EFI,
                PartitionType::FreeBsdUfs => gpt::partition_types::Type {
                    guid: "516E7CB6-6ECF-11D6-8FF8-00022D09712B",
                    os: gpt::partition_types::OperatingSystem::FreeBsd,
                },
                PartitionType::MsDosData => gpt::partition_types::Type {
                    guid: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
                    os: gpt::partition_types::OperatingSystem::Custom("Windows".to_string()),
                },
            };

            let (start, size) = partition_layouts[i];
            let start_lba = start / block_size;
            log::debug!(
                "DiskImage: partition '{}' at LBA {} ({} bytes)",
                part.name,
                start_lba,
                size
            );

            disk.add_partition(&part.name, size, guid, 0, Some(start_lba))?;
        }

        let mut device = disk.write()?;
        gpt::mbr::ProtectiveMBR::with_lb_size((total_size / 512 - 1) as u32)
            .overwrite_lba0(&mut device)
            .context("Failed to write protective MBR")?;

        // 5. Fill partition contents
        // Re-open to get the TRUTH from the disk we just wrote
        let disk = GptConfig::new()
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open(output)
            .context("Failed to re-open disk for verification")?;
        let actual_parts = disk.partitions();

        for (i, part_spec) in self.partitions.iter().enumerate() {
            let gpt_part = actual_parts
                .get(&(i as u32 + 1))
                .context("Partition missing after write")?;

            let start_offset = gpt_part.first_lba * block_size;
            let (intended_start, _size) = partition_layouts[i];

            if start_offset != intended_start {
                log::warn!(
                    "DiskImage: partition '{}' alignment adjusted by crate: intended LBA {}, actual LBA {}",
                    part_spec.name,
                    intended_start / block_size,
                    gpt_part.first_lba
                );
            }

            log::debug!(
                "DiskImage: writing partition '{}' at offset {} (LBA {})",
                part_spec.name,
                start_offset,
                gpt_part.first_lba
            );

            match &part_spec.source {
                PartitionSource::ImageFile(img_path) => {
                    let mut src_file = File::open(img_path)?;
                    let mut dest_file = File::options().write(true).open(output)?;
                    dest_file.seek(SeekFrom::Start(start_offset))?;
                    std::io::copy(&mut src_file, &mut dest_file)?;
                }
                PartitionSource::Directory(dir_path) => {
                    match part_spec.part_type {
                        PartitionType::FreeBsdUfs => {
                            // Create temporary UFS image
                            let temp_ufs = output.with_extension("ufs.tmp");
                            let ufs_writer =
                                pxe_ufs::UfsWriter::new(part_spec.size_bytes, &part_spec.name);
                            ufs_writer
                                .write(dir_path, &temp_ufs)
                                .map_err(|e| anyhow::anyhow!("UFS write failed: {:?}", e))?;

                            let mut src_file = File::open(&temp_ufs)?;
                            let mut dest_file = File::options().write(true).open(output)?;
                            dest_file.seek(SeekFrom::Start(start_offset))?;
                            std::io::copy(&mut src_file, &mut dest_file)?;
                            let _ = std::fs::remove_file(temp_ufs);
                        }
                        _ => {
                            // Default to FAT (EFI System or MsDosData)
                            let temp_fat = output.with_extension("fat.tmp");
                            let fat_writer = FatWriter::new(part_spec.size_bytes, &part_spec.name);
                            fat_writer.write(dir_path, &temp_fat)?;

                            let mut src_file = File::open(&temp_fat)?;
                            let mut dest_file = File::options().write(true).open(output)?;
                            dest_file.seek(SeekFrom::Start(start_offset))?;
                            std::io::copy(&mut src_file, &mut dest_file)?;
                            let _ = std::fs::remove_file(temp_fat);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct FatWriter {
    pub size_bytes: u64,
    pub label: String,
}

impl FatWriter {
    pub fn new(size_bytes: u64, label: &str) -> Self {
        Self {
            size_bytes,
            label: label.to_string(),
        }
    }

    pub fn write(&self, source: &Path, output: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output)
            .context("Failed to create FAT image file")?;
        file.set_len(self.size_bytes)?;

        // Choose FAT16 or FAT32 based on size
        // FAT32 typically requires at least 65525 clusters.
        // With 4KB clusters, that's ~256MB.
        // For EFI System Partitions, 32MB is common and should be FAT16.
        if self.size_bytes < 260 * 1024 * 1024 {
            self.format_fat16(&file)?;
        } else {
            self.format_fat32(&file)?;
        }

        // Seek back to start before opening with fatfs
        file.seek(SeekFrom::Start(0))?;

        // Populate using fatfs
        let buf_file = fscommon::BufStream::new(file);
        let fs = fatfs::FileSystem::new(buf_file, fatfs::FsOptions::new())?;
        let root_dir = fs.root_dir();

        self.copy_dir_recursive(source, &root_dir)?;

        Ok(())
    }

    fn format_fat16(&self, mut file: &File) -> Result<()> {
        file.seek(SeekFrom::Start(0))?;
        let mut bpb = [0u8; 512];

        // Jump instruction
        bpb[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        // OEM Name
        bpb[3..11].copy_from_slice(b"PXEEASY ");
        // Bytes per sector
        bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
        // Sectors per cluster
        bpb[13] = 8; // 4KiB
                     // Reserved sectors
        bpb[14..16].copy_from_slice(&1u16.to_le_bytes());
        // Number of FATs
        bpb[16] = 2;
        // Root entries (512 for FAT16)
        bpb[17..19].copy_from_slice(&512u16.to_le_bytes());
        // Total sectors
        let total_sectors = (self.size_bytes / 512) as u32;
        if total_sectors < 65536 {
            bpb[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
        } else {
            bpb[19..21].copy_from_slice(&0u16.to_le_bytes());
            bpb[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        }
        // Media descriptor
        bpb[21] = 0xF8;
        // FAT size (sectors per FAT)
        // FAT16: 2 bytes per entry
        let root_dir_sectors = (512u32 * 32).div_ceil(512);
        let data_sectors = total_sectors.saturating_sub(1 + root_dir_sectors);
        let clusters = data_sectors / 8;
        let fat_size = (clusters * 2).div_ceil(512);
        bpb[22..24].copy_from_slice(&(fat_size as u16).to_le_bytes());
        // Sectors per track
        bpb[24..26].copy_from_slice(&63u16.to_le_bytes());
        // Number of heads
        bpb[26..28].copy_from_slice(&255u16.to_le_bytes());
        // Hidden sectors
        bpb[28..32].copy_from_slice(&0u32.to_le_bytes());

        // Extended Boot Record
        bpb[36] = 0x80; // Drive number
        bpb[38] = 0x29; // Signature
        bpb[39..43].copy_from_slice(&0x12345678u32.to_le_bytes()); // Vol ID
        let mut label = [b' '; 11];
        let label_bytes = self.label.as_bytes();
        let len = label_bytes.len().min(11);
        label[..len].copy_from_slice(&label_bytes[..len]);
        bpb[43..54].copy_from_slice(&label);
        bpb[54..62].copy_from_slice(b"FAT16   ");

        // Boot signature
        bpb[510] = 0x55;
        bpb[511] = 0xAA;

        file.write_all(&bpb)?;

        // Initialize FATs
        let fat_offset = 512;
        file.seek(SeekFrom::Start(fat_offset))?;
        let mut fat_init = [0u8; 4];
        fat_init[0] = 0xF8; // Media descriptor
        fat_init[1] = 0xFF;
        fat_init[2] = 0xFF; // Partition state
        fat_init[3] = 0xFF;
        file.write_all(&fat_init)?;

        // Write second FAT
        file.seek(SeekFrom::Start(fat_offset + (fat_size as u64 * 512)))?;
        file.write_all(&fat_init)?;

        Ok(())
    }

    fn format_fat32(&self, mut file: &File) -> Result<()> {
        file.seek(SeekFrom::Start(0))?;
        let mut bpb = [0u8; 512];

        // Jump instruction
        bpb[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        // OEM Name
        bpb[3..11].copy_from_slice(b"PXEEASY ");
        // Bytes per sector
        bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
        // Sectors per cluster
        bpb[13] = 8; // 4KiB
                     // Reserved sectors
        bpb[14..16].copy_from_slice(&32u16.to_le_bytes());
        // Number of FATs
        bpb[16] = 2;
        // Root entries (0 for FAT32)
        bpb[17..19].copy_from_slice(&0u16.to_le_bytes());
        // Total sectors (small)
        bpb[19..21].copy_from_slice(&0u16.to_le_bytes());
        // Media descriptor
        bpb[21] = 0xF8;
        // FAT size (small)
        bpb[22..24].copy_from_slice(&0u16.to_le_bytes());
        // Sectors per track
        bpb[24..26].copy_from_slice(&63u16.to_le_bytes());
        // Number of heads
        bpb[26..28].copy_from_slice(&255u16.to_le_bytes());
        // Hidden sectors
        bpb[28..32].copy_from_slice(&0u32.to_le_bytes());
        // Total sectors (large)
        let total_sectors = (self.size_bytes / 512) as u32;
        bpb[32..36].copy_from_slice(&total_sectors.to_le_bytes());

        // FAT32 Extended fields
        let fat_size = (total_sectors / (8 * 512 / 4)) + 1;
        bpb[36..40].copy_from_slice(&fat_size.to_le_bytes());
        // Ext flags
        bpb[40..42].copy_from_slice(&0u16.to_le_bytes());
        // FS Version
        bpb[42..44].copy_from_slice(&0u16.to_le_bytes());
        // Root cluster
        bpb[44..48].copy_from_slice(&2u32.to_le_bytes());
        // FSInfo sector
        bpb[48..50].copy_from_slice(&1u16.to_le_bytes());
        // Backup boot sector
        bpb[50..52].copy_from_slice(&6u16.to_le_bytes());

        // Drive number
        bpb[64] = 0x80;
        // Signature
        bpb[66] = 0x29;
        // Vol ID
        bpb[67..71].copy_from_slice(&0x12345678u32.to_le_bytes());
        // Label
        let mut label = [b' '; 11];
        let label_bytes = self.label.as_bytes();
        let len = label_bytes.len().min(11);
        label[..len].copy_from_slice(&label_bytes[..len]);
        bpb[71..82].copy_from_slice(&label);
        // System ID
        bpb[82..90].copy_from_slice(b"FAT32   ");

        // Boot signature
        bpb[510] = 0x55;
        bpb[511] = 0xAA;

        file.write_all(&bpb)?;

        // Initialize FSInfo sector
        let mut fsinfo = [0u8; 512];
        fsinfo[0..4].copy_from_slice(b"RRaA");
        fsinfo[484..488].copy_from_slice(b"rrAa");
        fsinfo[488..492].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // Free count (unknown)
        fsinfo[492..496].copy_from_slice(&2u32.to_le_bytes()); // Next free cluster
        fsinfo[510] = 0x55;
        fsinfo[511] = 0xAA;
        file.seek(SeekFrom::Start(512))?;
        file.write_all(&fsinfo)?;

        // Initialize FATs with first two clusters reserved
        let fat_offset = 32 * 512;
        file.seek(SeekFrom::Start(fat_offset))?;
        let mut fat_init = [0u8; 12];
        fat_init[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes()); // Media descriptor
        fat_init[4..8].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // Partition state
        fat_init[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // Root dir end of chain
        file.write_all(&fat_init)?;

        // Write second FAT
        file.seek(SeekFrom::Start(fat_offset + (fat_size as u64 * 512)))?;
        file.write_all(&fat_init)?;

        Ok(())
    }

    fn copy_dir_recursive<T: fatfs::ReadWriteSeek>(
        &self,
        src: &Path,
        dest: &fatfs::Dir<T>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.file_name().unwrap().to_str().unwrap();

            if path.is_dir() {
                let new_dest = dest.create_dir(name)?;
                self.copy_dir_recursive(&path, &new_dest)?;
            } else {
                let mut src_file = File::open(&path)?;
                let mut dest_file = dest.create_file(name)?;
                std::io::copy(&mut src_file, &mut dest_file)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_create_disk_image() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let output_path = temp_dir.path().join("test_disk.img");

        let mut disk = DiskImage::new();

        // Create a dummy file for partition content
        let content_path = temp_dir.path().join("content.img");
        let mut content_file = File::create(&content_path)?;
        content_file.write_all(&[0xAA; 1024])?;

        disk.add_partition(Partition {
            name: "EFI".to_string(),
            part_type: PartitionType::EfiSystem,
            size_bytes: 1024 * 1024, // 1MB
            source: PartitionSource::ImageFile(content_path),
        });

        disk.write(&output_path)?;

        // Verify GPT
        let disk = GptConfig::new().open(&output_path)?;
        assert_eq!(disk.partitions().len(), 1);
        let part = disk.partitions().get(&1).unwrap();
        assert_eq!(part.name, "EFI");

        // Verify content
        let mut file = File::open(&output_path)?;
        let mut buffer = vec![0u8; 1024];
        file.seek(SeekFrom::Start(part.first_lba * 512))?;
        file.read_exact(&mut buffer)?;
        assert_eq!(buffer, vec![0xAA; 1024]);

        Ok(())
    }

    #[test]
    fn test_fat_writer() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir(&source_dir)?;
        std::fs::write(source_dir.join("test.txt"), "hello world")?;

        let output_path = temp_dir.path().join("fat.img");
        // Use a larger size to satisfy FAT32 cluster count requirements (min ~268MB with 4K clusters)
        let writer = FatWriter::new(300 * 1024 * 1024, "TEST");
        writer.write(&source_dir, &output_path)?;

        // Verify with fatfs
        let file = File::open(&output_path)?;
        let buf_file = fscommon::BufStream::new(file);
        let fs = fatfs::FileSystem::new(buf_file, fatfs::FsOptions::new())?;
        let root = fs.root_dir();
        let mut test_file = root.open_file("test.txt")?;
        let mut content = String::new();
        test_file.read_to_string(&mut content)?;
        assert_eq!(content, "hello world");

        Ok(())
    }
}
