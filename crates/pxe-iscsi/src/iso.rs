use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use std::collections::HashMap;

/// Default block size for optical media.
const OPTICAL_BLOCK_SIZE: u32 = 2048;
/// Default block size for disk media.
const DISK_BLOCK_SIZE: u32 = 512;

pub struct IsoLun {
    path: PathBuf,
    block_size: u32,
    block_count: u64,
    overlay: Mutex<HashMap<u64, Vec<u8>>>,
}

impl IsoLun {
    /// Opens the ISO file and initializes the block count.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_block_size(path, OPTICAL_BLOCK_SIZE)
    }

    pub fn open_with_block_size(path: &Path, block_size: u32) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ISO path must be a file",
            ));
        }

        let block_count = metadata.len() / (block_size as u64);

        Ok(Self {
            path: path.to_path_buf(),
            block_size,
            block_count,
            overlay: Mutex::new(HashMap::new()),
        })
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    /// Reads `count` blocks starting at `lba` into `buf` (which is resized to fit).
    /// Caller must ensure `lba + count <= block_count`; returns `InvalidInput` otherwise.
    ///
    /// Opens the file on each call — intentionally no caching. The iSCSI session layer
    /// reads sequentially during an install; OS page cache handles repeated access.
    pub fn read_blocks(&self, lba: u64, count: u32, buf: &mut Vec<u8>) -> io::Result<()> {
        if lba + (count as u64) > self.block_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Read request out of bounds",
            ));
        }

        let mut file = File::open(&self.path)?;
        let offset = lba * (self.block_size as u64);
        file.seek(SeekFrom::Start(offset))?;

        let bytes_to_read = (count as usize) * (self.block_size as usize);
        buf.resize(bytes_to_read, 0);
        file.read_exact(buf)?;

        let overlay = self
            .overlay
            .lock()
            .map_err(|_| io::Error::other("overlay lock poisoned"))?;
        for block in 0..count as u64 {
            if let Some(data) = overlay.get(&(lba + block)) {
                let start = (block as usize) * self.block_size as usize;
                let end = start + self.block_size as usize;
                buf[start..end].copy_from_slice(data);
            }
        }

        Ok(())
    }

    pub fn write_blocks(&self, lba: u64, count: u32, data: &[u8]) -> io::Result<()> {
        if lba + (count as u64) > self.block_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Write request out of bounds",
            ));
        }

        let expected_len = count as usize * self.block_size as usize;
        if data.len() != expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Write payload length does not match block count",
            ));
        }

        let mut overlay = self
            .overlay
            .lock()
            .map_err(|_| io::Error::other("overlay lock poisoned"))?;
        for block in 0..count as u64 {
            let start = block as usize * self.block_size as usize;
            let end = start + self.block_size as usize;
            overlay.insert(lba + block, data[start..end].to_vec());
        }

        Ok(())
    }
}

pub fn optical_block_size() -> u32 {
    OPTICAL_BLOCK_SIZE
}

pub fn disk_block_size() -> u32 {
    DISK_BLOCK_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_iso_lun_open_and_read() -> io::Result<()> {
        let mut file = NamedTempFile::new()?;
        let block_size = optical_block_size() as usize;
        let block_count = 10;
        let content = vec![0u8; block_size * block_count];
        file.write_all(&content)?;

        let iso = IsoLun::open(file.path())?;
        assert_eq!(iso.block_size(), block_size as u32);
        assert_eq!(iso.block_count(), block_count as u64);

        let mut buf = Vec::new();
        iso.read_blocks(0, 1, &mut buf)?;
        assert_eq!(buf.len(), block_size);
        assert_eq!(buf, vec![0u8; block_size]);

        iso.read_blocks(9, 1, &mut buf)?;
        assert_eq!(buf.len(), block_size);

        // Out of bounds
        assert!(iso.read_blocks(10, 1, &mut buf).is_err());
        assert!(iso.read_blocks(5, 6, &mut buf).is_err());

        Ok(())
    }

    #[test]
    fn test_iso_lun_with_actual_data() -> io::Result<()> {
        let mut file = NamedTempFile::new()?;
        let block_size = optical_block_size() as usize;
        let mut content = vec![0u8; block_size * 2];

        // Block 0
        for (i, byte) in content.iter_mut().take(block_size).enumerate() {
            *byte = (i % 256) as u8;
        }
        // Block 1
        for i in 0..block_size {
            content[block_size + i] = ((i + 1) % 256) as u8;
        }

        file.write_all(&content)?;

        let iso = IsoLun::open(file.path())?;
        let mut buf = Vec::new();

        iso.read_blocks(0, 1, &mut buf)?;
        assert_eq!(buf, &content[0..block_size]);

        iso.read_blocks(1, 1, &mut buf)?;
        assert_eq!(buf, &content[block_size..block_size * 2]);

        iso.read_blocks(0, 2, &mut buf)?;
        assert_eq!(buf, content);

        Ok(())
    }

    #[test]
    fn test_iso_lun_overlay_writes_round_trip() -> io::Result<()> {
        let mut file = NamedTempFile::new()?;
        let block_size = optical_block_size() as usize;
        let content = vec![0u8; block_size * 2];
        file.write_all(&content)?;

        let iso = IsoLun::open(file.path())?;
        let mut buf = Vec::new();
        let write_data = vec![0xAB; block_size];

        iso.write_blocks(1, 1, &write_data)?;
        iso.read_blocks(1, 1, &mut buf)?;

        assert_eq!(buf, write_data);
        Ok(())
    }
}
