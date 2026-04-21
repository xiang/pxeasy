use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
};

use crate::{normalize_path, IsoSlice, ProfileError, SourceFs};

const DEFAULT_AVDP_SECTOR: u64 = 256;

const TAG_PRIMARY_VOLUME_DESCRIPTOR: u16 = 1;
const TAG_ANCHOR_VOLUME_DESCRIPTOR_POINTER: u16 = 2;
const TAG_PARTITION_DESCRIPTOR: u16 = 5;
const TAG_LOGICAL_VOLUME_DESCRIPTOR: u16 = 6;
const TAG_TERMINATING_DESCRIPTOR: u16 = 8;
const TAG_FILE_SET_DESCRIPTOR: u16 = 256;
const TAG_FILE_IDENTIFIER_DESCRIPTOR: u16 = 257;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;

const FILE_TYPE_DIRECTORY: u8 = 4;
const FILE_TYPE_REGULAR: u8 = 5;

const ALLOCATION_SHORT: u8 = 0;
const ALLOCATION_LONG: u8 = 1;
const ALLOCATION_EMBEDDED: u8 = 3;

const FILE_CHARACTERISTIC_DIRECTORY: u8 = 0x02;
const FILE_CHARACTERISTIC_DELETED: u8 = 0x04;
const FILE_CHARACTERISTIC_PARENT: u8 = 0x08;

#[derive(Debug, Clone, Copy)]
struct LongAllocationDescriptor {
    extent_length: u32,
    logical_block_num: u32,
    partition_ref_num: u16,
}

impl LongAllocationDescriptor {
    fn length(self) -> usize {
        (self.extent_length & 0x3FFF_FFFF) as usize
    }
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    path: String,
    is_directory: bool,
    icb: LongAllocationDescriptor,
}

#[derive(Debug, Clone, Copy)]
struct NodeDescriptor {
    file_type: u8,
    allocation_type: u8,
    information_length: u64,
    allocation_descriptors_offset: usize,
    allocation_descriptors_length: usize,
}

pub(crate) struct UdfIso {
    file: Mutex<File>,
    path: PathBuf,
    block_size: u32,
    partition_start: u32,
    root_icb: LongAllocationDescriptor,
    volume_label: Option<String>,
}

impl UdfIso {
    pub(crate) fn open(path: &Path) -> Result<Self, io::Error> {
        let mut file = File::open(path)?;
        let vds_extent = read_anchor_vds_extent(&mut file)?;
        let (block_size, partition_start, file_set_icb, volume_label) =
            read_volume_descriptors(&mut file, vds_extent)?;
        let root_icb = read_root_icb(&mut file, partition_start, block_size, file_set_icb)?;

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            block_size,
            partition_start,
            root_icb,
            volume_label,
        })
    }

    pub(crate) fn volume_label(&self) -> Option<&str> {
        self.volume_label.as_deref()
    }

    fn resolve_path(&self, path: &str) -> Result<Option<DirEntry>, ProfileError> {
        let normalized = normalize_path(path);
        if normalized == "/" {
            return Ok(Some(DirEntry {
                name: String::new(),
                path: "/".to_string(),
                is_directory: true,
                icb: self.root_icb,
            }));
        }

        let mut current = DirEntry {
            name: String::new(),
            path: "/".to_string(),
            is_directory: true,
            icb: self.root_icb,
        };

        for segment in normalized.trim_start_matches('/').split('/') {
            if !current.is_directory {
                return Ok(None);
            }

            let entries = self.read_directory_entries(current.icb, &current.path)?;
            let wanted = segment.to_ascii_lowercase();
            let Some(entry) = entries
                .into_iter()
                .find(|entry| entry.name.to_ascii_lowercase() == wanted)
            else {
                return Ok(None);
            };

            current = entry;
        }

        Ok(Some(current))
    }

    fn walk_files(
        &self,
        dir_icb: LongAllocationDescriptor,
        dir_path: &str,
        prefix_lower: &str,
        out: &mut Vec<String>,
    ) -> Result<(), ProfileError> {
        for entry in self.read_directory_entries(dir_icb, dir_path)? {
            if entry.is_directory {
                self.walk_files(entry.icb, &entry.path, prefix_lower, out)?;
            } else if entry.path.to_ascii_lowercase().starts_with(prefix_lower) {
                out.push(entry.path);
            }
        }

        Ok(())
    }

    fn read_directory_entries(
        &self,
        dir_icb: LongAllocationDescriptor,
        dir_path: &str,
    ) -> Result<Vec<DirEntry>, ProfileError> {
        let descriptor = self.read_node_descriptor(dir_icb)?;
        if descriptor.file_type != FILE_TYPE_DIRECTORY {
            return Err(source_error(
                self.path.clone(),
                io::Error::new(io::ErrorKind::InvalidData, "UDF node is not a directory"),
            ));
        }

        let data = self.read_node_data(dir_icb, descriptor)?;
        parse_directory_entries(&data, dir_path).map_err(|err| source_error(self.path.clone(), err))
    }

    fn read_node_descriptor(
        &self,
        icb: LongAllocationDescriptor,
    ) -> Result<NodeDescriptor, ProfileError> {
        let mut file = self.file.lock().map_err(lock_error)?;
        let offset = self.block_offset(icb.logical_block_num);
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| source_error(self.path.clone(), err))?;

        let mut block = vec![0u8; self.block_size as usize];
        file.read_exact(&mut block)
            .map_err(|err| source_error(self.path.clone(), err))?;

        parse_node_descriptor(&block).map_err(|err| source_error(self.path.clone(), err))
    }

    fn read_node_data(
        &self,
        icb: LongAllocationDescriptor,
        descriptor: NodeDescriptor,
    ) -> Result<Vec<u8>, ProfileError> {
        let mut file = self.file.lock().map_err(lock_error)?;
        let offset = self.block_offset(icb.logical_block_num);
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| source_error(self.path.clone(), err))?;

        let mut block = vec![0u8; self.block_size as usize];
        file.read_exact(&mut block)
            .map_err(|err| source_error(self.path.clone(), err))?;

        let data = block
            .get(
                descriptor.allocation_descriptors_offset
                    ..descriptor.allocation_descriptors_offset
                        + descriptor.allocation_descriptors_length,
            )
            .ok_or_else(|| {
                source_error(
                    self.path.clone(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDF allocation descriptors exceed node size",
                    ),
                )
            })?;

        match descriptor.allocation_type {
            ALLOCATION_EMBEDDED => {
                let mut bytes = data.to_vec();
                bytes.truncate(descriptor.information_length as usize);
                Ok(bytes)
            }
            ALLOCATION_SHORT => {
                self.read_short_extents(&mut file, data, descriptor.information_length)
            }
            ALLOCATION_LONG => {
                self.read_long_extents(&mut file, data, descriptor.information_length)
            }
            other => Err(source_error(
                self.path.clone(),
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported UDF allocation type: {other}"),
                ),
            )),
        }
    }

    fn read_short_extents(
        &self,
        file: &mut File,
        descriptors: &[u8],
        total_length: u64,
    ) -> Result<Vec<u8>, ProfileError> {
        let mut out = Vec::new();
        for chunk in descriptors.chunks_exact(8) {
            let extent_length =
                le_u32(chunk, 0).map_err(|err| source_error(self.path.clone(), err))?;
            if extent_length == 0 {
                break;
            }

            let length = (extent_length & 0x3FFF_FFFF) as usize;
            let block_num = le_u32(chunk, 4).map_err(|err| source_error(self.path.clone(), err))?;
            out.extend(self.read_extent(file, block_num, length)?);
            if out.len() >= total_length as usize {
                break;
            }
        }

        out.truncate(total_length as usize);
        Ok(out)
    }

    fn read_long_extents(
        &self,
        file: &mut File,
        descriptors: &[u8],
        total_length: u64,
    ) -> Result<Vec<u8>, ProfileError> {
        let mut out = Vec::new();
        for chunk in descriptors.chunks_exact(16) {
            let ad = parse_long_ad(chunk).map_err(|err| source_error(self.path.clone(), err))?;
            if ad.length() == 0 {
                break;
            }
            if ad.partition_ref_num != 0 {
                return Err(source_error(
                    self.path.clone(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unsupported UDF partition reference: {}",
                            ad.partition_ref_num
                        ),
                    ),
                ));
            }

            out.extend(self.read_extent(file, ad.logical_block_num, ad.length())?);
            if out.len() >= total_length as usize {
                break;
            }
        }

        out.truncate(total_length as usize);
        Ok(out)
    }

    fn read_extent(
        &self,
        file: &mut File,
        block_num: u32,
        length: usize,
    ) -> Result<Vec<u8>, ProfileError> {
        let offset = self.block_offset(block_num);
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| source_error(self.path.clone(), err))?;

        let mut bytes = vec![0u8; length];
        file.read_exact(&mut bytes)
            .map_err(|err| source_error(self.path.clone(), err))?;
        Ok(bytes)
    }

    fn block_offset(&self, logical_block_num: u32) -> u64 {
        u64::from(self.partition_start + logical_block_num) * u64::from(self.block_size)
    }
}

impl SourceFs for UdfIso {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
        let Some(entry) = self.resolve_path(path)? else {
            return Ok(None);
        };
        if entry.is_directory {
            return Ok(None);
        }

        let descriptor = self.read_node_descriptor(entry.icb)?;
        if descriptor.file_type != FILE_TYPE_REGULAR {
            return Ok(None);
        }

        self.read_node_data(entry.icb, descriptor).map(Some)
    }

    fn path_exists(&self, path: &str) -> Result<bool, ProfileError> {
        Ok(self.resolve_path(path)?.is_some())
    }

    fn list_files(&self, prefix: &str) -> Result<Vec<String>, ProfileError> {
        let mut out = Vec::new();
        let prefix = normalize_path(prefix).to_ascii_lowercase();
        self.walk_files(self.root_icb, "/", &prefix, &mut out)?;
        out.sort();
        Ok(out)
    }

    fn file_slice(&self, _path: &str) -> Result<Option<IsoSlice>, ProfileError> {
        Ok(None)
    }
}

fn read_anchor_vds_extent(file: &mut File) -> Result<(u32, u32), io::Error> {
    let anchor = read_sector(file, DEFAULT_AVDP_SECTOR, 2048)?;
    if le_u16(&anchor, 0)? != TAG_ANCHOR_VOLUME_DESCRIPTOR_POINTER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDF anchor volume descriptor not found",
        ));
    }

    let length = le_u32(&anchor, 16)?;
    let location = le_u32(&anchor, 20)?;
    Ok((location, length))
}

fn read_volume_descriptors(
    file: &mut File,
    vds_extent: (u32, u32),
) -> Result<(u32, u32, LongAllocationDescriptor, Option<String>), io::Error> {
    let (extent_location, extent_length) = vds_extent;
    let sectors = u64::from(extent_length).div_ceil(2048);
    let mut volume_label = None;
    let mut block_size = None;
    let mut partition_start = None;
    let mut file_set_icb = None;

    for sector in extent_location as u64..extent_location as u64 + sectors {
        let descriptor = read_sector(file, sector, 2048)?;
        match le_u16(&descriptor, 0)? {
            TAG_PRIMARY_VOLUME_DESCRIPTOR => {
                let label = decode_dstring(&descriptor[24..56]);
                if !label.is_empty() {
                    volume_label = Some(label);
                }
            }
            TAG_PARTITION_DESCRIPTOR => {
                partition_start = Some(le_u32(&descriptor, 188)?);
            }
            TAG_LOGICAL_VOLUME_DESCRIPTOR => {
                block_size = Some(le_u32(&descriptor, 212)?);
                file_set_icb = Some(parse_long_ad(&descriptor[248..264])?);
            }
            TAG_TERMINATING_DESCRIPTOR => break,
            _ => {}
        }
    }

    let block_size = block_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "UDF logical volume descriptor missing",
        )
    })?;
    let partition_start = partition_start.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "UDF partition descriptor missing",
        )
    })?;
    let file_set_icb = file_set_icb.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "UDF file set location missing")
    })?;

    Ok((block_size, partition_start, file_set_icb, volume_label))
}

fn read_root_icb(
    file: &mut File,
    partition_start: u32,
    block_size: u32,
    file_set_icb: LongAllocationDescriptor,
) -> Result<LongAllocationDescriptor, io::Error> {
    let offset =
        u64::from(partition_start + file_set_icb.logical_block_num) * u64::from(block_size);
    file.seek(SeekFrom::Start(offset))?;
    let mut descriptor = vec![0u8; block_size as usize];
    file.read_exact(&mut descriptor)?;

    if le_u16(&descriptor, 0)? != TAG_FILE_SET_DESCRIPTOR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDF file set descriptor missing",
        ));
    }

    parse_long_ad(&descriptor[400..416])
}

fn parse_node_descriptor(block: &[u8]) -> io::Result<NodeDescriptor> {
    let tag = le_u16(block, 0)?;
    let file_type = *block.get(27).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "UDF node missing file type")
    })?;
    let allocation_type = le_u16(block, 34)? as u8 & 0x07;

    match tag {
        TAG_FILE_ENTRY => Ok(NodeDescriptor {
            file_type,
            allocation_type,
            information_length: le_u64(block, 56)?,
            allocation_descriptors_offset: 176 + le_u32(block, 168)? as usize,
            allocation_descriptors_length: le_u32(block, 172)? as usize,
        }),
        TAG_EXTENDED_FILE_ENTRY => Ok(NodeDescriptor {
            file_type,
            allocation_type,
            information_length: le_u64(block, 56)?,
            allocation_descriptors_offset: 216 + le_u32(block, 208)? as usize,
            allocation_descriptors_length: le_u32(block, 212)? as usize,
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported UDF node descriptor tag: {tag}"),
        )),
    }
}

fn parse_directory_entries(data: &[u8], dir_path: &str) -> io::Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 38 <= data.len() {
        if le_u16(data, offset)? != TAG_FILE_IDENTIFIER_DESCRIPTOR {
            break;
        }

        let characteristics = data[offset + 18];
        let file_id_len = data[offset + 19] as usize;
        let icb = parse_long_ad(&data[offset + 20..offset + 36])?;
        let impl_use_len = le_u16(data, offset + 36)? as usize;
        let total_size = (38 + impl_use_len + file_id_len + 3) & !3;
        if offset + total_size > data.len() {
            break;
        }

        let variable = &data[offset + 38..offset + total_size];
        let name = if characteristics & FILE_CHARACTERISTIC_PARENT != 0 {
            "..".to_string()
        } else {
            let name_start = impl_use_len;
            let name_end = name_start.saturating_add(file_id_len).min(variable.len());
            decode_filename(&variable[name_start..name_end])
        };

        if characteristics & FILE_CHARACTERISTIC_DELETED == 0
            && characteristics & FILE_CHARACTERISTIC_PARENT == 0
        {
            let is_directory = characteristics & FILE_CHARACTERISTIC_DIRECTORY != 0;
            let path = if dir_path == "/" {
                format!("/{}", name)
            } else {
                format!("{dir_path}/{}", name)
            };
            entries.push(DirEntry {
                name,
                path,
                is_directory,
                icb,
            });
        }

        offset += total_size;
    }

    Ok(entries)
}

fn parse_long_ad(bytes: &[u8]) -> io::Result<LongAllocationDescriptor> {
    if bytes.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UDF long allocation descriptor truncated",
        ));
    }

    Ok(LongAllocationDescriptor {
        extent_length: le_u32(bytes, 0)?,
        logical_block_num: le_u32(bytes, 4)?,
        partition_ref_num: le_u16(bytes, 8)?,
    })
}

fn decode_dstring(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }

    let compression = bytes[0];
    let length = bytes[bytes.len() - 1] as usize;
    if length == 0 {
        return String::new();
    }

    let end = (1 + length).min(bytes.len().saturating_sub(1));
    let content = &bytes[1..end];
    decode_compacted_string(compression, content)
}

fn decode_filename(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    decode_compacted_string(bytes[0], &bytes[1..])
}

fn decode_compacted_string(compression: u8, bytes: &[u8]) -> String {
    match compression {
        8 => String::from_utf8_lossy(bytes).into_owned(),
        16 => bytes
            .chunks_exact(2)
            .filter_map(|chunk| char::from_u32(u16::from_be_bytes([chunk[0], chunk[1]]) as u32))
            .collect(),
        _ => String::new(),
    }
}

fn read_sector(file: &mut File, sector: u64, block_size: u32) -> Result<Vec<u8>, io::Error> {
    file.seek(SeekFrom::Start(sector * u64::from(block_size)))?;
    let mut buf = vec![0u8; block_size as usize];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn le_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let slice = bytes.get(offset..offset + 2).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated little-endian u16")
    })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let slice = bytes.get(offset..offset + 4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated little-endian u32")
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn le_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let slice = bytes.get(offset..offset + 8).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated little-endian u64")
    })?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn lock_error(_: std::sync::PoisonError<std::sync::MutexGuard<'_, File>>) -> ProfileError {
    source_error(
        PathBuf::from("<udf>"),
        io::Error::other("UDF file lock poisoned"),
    )
}

fn source_error(path: PathBuf, err: io::Error) -> ProfileError {
    ProfileError::SourceUnreadable(path, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_udf_dstring() {
        let bytes = [8, b'T', b'E', b'S', b'T', 4];
        assert_eq!(decode_dstring(&bytes), "TEST");
    }

    #[test]
    fn decodes_udf_filename() {
        let bytes = [8, b'b', b'o', b'o', b't'];
        assert_eq!(decode_filename(&bytes), "boot");
    }
}
