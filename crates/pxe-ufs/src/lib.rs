pub mod builder;
pub mod format;
pub mod layout;

use crate::builder::{EntryKind, FileEntry, SourceTree};
use crate::format::*;
use crate::layout::FsLayout;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct UfsWriter {
    size: u64,
    label: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
pub enum UfsError {
    Io(std::io::Error),
    Layout(String),
    Other(String),
}

impl From<std::io::Error> for UfsError {
    fn from(err: std::io::Error) -> Self {
        UfsError::Io(err)
    }
}

impl UfsWriter {
    pub fn new(size: u64, label: &str) -> Self {
        Self {
            size,
            label: label.to_string(),
            uid: 0,
            gid: 0,
        }
    }

    pub fn with_ownership(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    pub fn write(&self, source: &Path, output: &Path) -> Result<(), UfsError> {
        let tree = SourceTree::scan(source).map_err(UfsError::Other)?;
        let layout = FsLayout::compute(self.size).map_err(UfsError::Layout)?;

        let mut buffer = vec![0u8; self.size as usize];

        // 1. Build Superblock
        let mut sb = Superblock {
            fs_firstfield: 0,
            fs_unused_1: 0,
            fs_sblkno: layout.sblkno,
            fs_cblkno: layout.cblkno,
            fs_iblkno: layout.iblkno,
            fs_dblkno: layout.dblkno,
            fs_old_cgoffset: 0,
            fs_old_cgmask: 0xFFFFFFFFu32 as i32,
            fs_old_time: 0,
            fs_old_size: 0,
            fs_old_dsize: 0,
            fs_ncg: layout.ncg,
            fs_bsize: layout.bsize as i32,
            fs_fsize: layout.fsize as i32,
            fs_frag: layout.frag as i32,
            fs_minfree: 8,
            fs_old_rotdelay: 0,
            fs_old_rps: 60,
            fs_bmask: !(layout.bsize as i32 - 1),
            fs_fmask: !(layout.fsize as i32 - 1),
            fs_bshift: 15,
            fs_fshift: 12,
            fs_maxcontig: 1,
            fs_maxbpg: 0,
            fs_fragshift: 3,
            fs_fsbtodb: 3,
            fs_sbsize: 8192,
            fs_spare1: [0; 2],
            fs_nindir: (layout.bsize / 8) as i32,
            fs_inopb: layout.inopb,
            fs_old_nspf: (layout.fsize / 512) as i32,
            fs_optim: 0,
            fs_old_npsect: 0,
            fs_old_interleave: 1,
            fs_old_trackskew: 0,
            fs_id: [0, 0],
            fs_old_csaddr: 0,
            fs_cssize: layout.cssize,
            fs_cgsize: layout.bsize as i32,
            fs_spare2: 0,
            fs_old_nsect: 0,
            fs_old_spc: 0,
            fs_old_ncyl: 0,
            fs_old_cpg: 1,
            fs_ipg: layout.ipg,
            fs_fpg: layout.fpg as i32,
            fs_old_cstotal: CgSummary {
                cs_ndir: 0,
                cs_nbfree: 0,
                cs_nifree: 0,
                cs_nffree: 0,
            },
            fs_fmod: 0,
            fs_clean: 1,
            fs_ronly: 0,
            fs_old_flags: 0x80u8 as i8, // FS_FLAGS_UPDATED
            fs_fsmnt: [0; MAXMNTLEN],
            fs_volname: [0; MAXVOLLEN],
            fs_swuid: 0,
            fs_pad: 0,
            fs_cgrotor: 0,
            fs_ocsp: [0; NOCSPTRS],
            fs_si: 0,
            fs_old_cpc: 0,
            fs_maxbsize: layout.bsize as i32,
            fs_unrefs: 0,
            fs_providersize: layout.fs_size,
            fs_metaspace: 0,
            fs_save_maxfilesize: 0,
            fs_sparecon64: [0; 12],
            fs_sblockactualloc: 65536,
            fs_sblockloc: 65536,
            fs_cstotal: CsumTotal {
                cs_ndir: 0,
                cs_nbfree: 0,
                cs_nifree: (layout.ncg * layout.ipg - 2) as i64,
                cs_nffree: 0,
                cs_numclusters: 0,
                cs_spare: [0; 3],
            },
            fs_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            fs_size: layout.fs_size,
            fs_dsize: layout.fs_dsize,
            fs_csaddr: layout.csaddr,
            fs_pendingblocks: 0,
            fs_pendinginodes: 0,
            fs_snapinum: [0; FSMAXSNAP],
            fs_avgfilesize: 16384,
            fs_avgfpdir: 64,
            fs_available_spare: 0,
            fs_mtime: 0,
            fs_sujfree: 0,
            fs_sparecon32: [0; 21],
            fs_ckhash: 0,
            fs_metackhash: 0,
            fs_flags: 0,
            fs_contigsumsize: 0,
            fs_maxsymlinklen: 120,
            fs_old_inodefmt: 2,
            fs_maxfilesize: 0x000fffffffffffff,
            fs_qbmask: (layout.bsize as i64 - 1),
            fs_qfmask: (layout.fsize as i64 - 1),
            fs_state: 0,
            fs_old_postblformat: 1,
            fs_old_nrpos: 1,
            fs_spare5: [0; 2],
            fs_magic: FS_UFS2_MAGIC,
        };

        let label_bytes = self.label.as_bytes();
        let len = label_bytes.len().min(MAXVOLLEN);
        sb.fs_volname[..len].copy_from_slice(&label_bytes[..len]);

        // 2. Allocation State
        let total_inodes = (layout.ncg * layout.ipg) as usize;
        let mut inodes = vec![
            Ufs2Dinode {
                di_mode: 0,
                di_nlink: 0,
                di_uid: 0,
                di_gid: 0,
                di_blksize: 0,
                di_size: 0,
                di_blocks: 0,
                di_atime: 0,
                di_mtime: 0,
                di_ctime: 0,
                di_birthtime: 0,
                di_mtimensec: 0,
                di_atimensec: 0,
                di_ctimensec: 0,
                di_birthnsec: 0,
                di_gen: 1,
                di_kernflags: 0,
                di_flags: 0,
                di_extsize: 0,
                di_extb: [0; 2],
                di_db: [0; 12],
                di_ib: [0; 3],
                di_modrev: 0,
                di_freelink: 0,
                di_ckhash: 0,
                di_spare: [0; 2],
            };
            total_inodes
        ];

        let mut cg_summaries = vec![
            CgSummary {
                cs_ndir: 0,
                cs_nbfree: (layout.fpg as i32 - layout.dblkno) / 8,
                cs_nifree: layout.ipg as i32,
                cs_nffree: 0,
            };
            layout.ncg as usize
        ];

        // Allocate root inode
        cg_summaries[0].cs_nifree -= 2; // Inode 0 and 1 are reserved
        cg_summaries[0].cs_nifree -= 1; // Inode 2 is root

        let mut allocator = Allocator::new(&layout);

        for entry in &tree.entries {
            let cg = (entry.ino / layout.ipg) as usize;
            if cg >= layout.ncg as usize {
                return Err(UfsError::Other(format!(
                    "Inode {} out of bounds",
                    entry.ino
                )));
            }

            let mut inode = Ufs2Dinode {
                di_mode: entry.mode,
                di_nlink: if let EntryKind::Dir = entry.kind {
                    2
                } else {
                    1
                },
                di_uid: self.uid,
                di_gid: self.gid,
                di_blksize: layout.bsize,
                di_size: entry.size,
                di_blocks: 0,
                di_atime: sb.fs_time,
                di_mtime: entry.mtime,
                di_ctime: entry.mtime,
                di_birthtime: entry.mtime,
                di_mtimensec: 0,
                di_atimensec: 0,
                di_ctimensec: 0,
                di_birthnsec: 0,
                di_gen: 1,
                di_kernflags: 0,
                di_flags: 0,
                di_extsize: 0,
                di_extb: [0; 2],
                di_db: [0; 12],
                di_ib: [0; 3],
                di_modrev: 0,
                di_freelink: 0,
                di_ckhash: 0,
                di_spare: [0; 2],
            };

            match &entry.kind {
                EntryKind::File => {
                    let data = fs::read(&entry.path)?;
                    self.allocate_data(
                        &mut inode,
                        &data,
                        &mut allocator,
                        &layout,
                        &mut buffer,
                        &mut cg_summaries,
                    )?;
                }
                EntryKind::Dir => {
                    let dir_data = self.build_dir_data(entry, &tree, &layout);
                    self.allocate_data(
                        &mut inode,
                        &dir_data,
                        &mut allocator,
                        &layout,
                        &mut buffer,
                        &mut cg_summaries,
                    )?;
                    cg_summaries[cg].cs_ndir += 1;
                }
                EntryKind::Symlink(target) => {
                    let target_bytes = target.to_str().unwrap().as_bytes();
                    if target_bytes.len() < 120 {
                        let mut shortlink = [0u8; 120];
                        let len = target_bytes.len();
                        shortlink[..len].copy_from_slice(target_bytes);
                        inode.di_db = unsafe {
                            std::mem::transmute::<[u8; 96], [i64; 12]>(
                                shortlink[..96].try_into().unwrap(),
                            )
                        };
                        inode.di_ib = unsafe {
                            std::mem::transmute::<[u8; 24], [i64; 3]>(
                                shortlink[96..].try_into().unwrap(),
                            )
                        };
                        inode.di_size = len as u64;
                        inode.di_blocks = 0;
                    } else {
                        self.allocate_data(
                            &mut inode,
                            target_bytes,
                            &mut allocator,
                            &layout,
                            &mut buffer,
                            &mut cg_summaries,
                        )?;
                    }
                }
                EntryKind::CharDev(rdev) | EntryKind::BlockDev(rdev) => {
                    inode.di_db[0] = *rdev as i64;
                    inode.di_size = 0;
                    inode.di_blocks = 0;
                }
                EntryKind::Fifo | EntryKind::Socket => {
                    inode.di_size = 0;
                    inode.di_blocks = 0;
                }
            }

            if entry.ino != UFS_ROOTINO {
                cg_summaries[cg].cs_nifree -= 1;
            }
            inodes[entry.ino as usize] = inode;
        }

        // 3. Finalize metadata and write to buffer
        let mut total_summary = CsumTotal {
            cs_ndir: 0,
            cs_nbfree: 0,
            cs_nifree: 0,
            cs_nffree: 0,
            cs_numclusters: 0,
            cs_spare: [0; 3],
        };
        for (i, summary) in cg_summaries.iter().enumerate() {
            total_summary.cs_ndir += summary.cs_ndir as i64;
            total_summary.cs_nifree += summary.cs_nifree as i64;
            total_summary.cs_nbfree += summary.cs_nbfree as i64;
            total_summary.cs_nffree += summary.cs_nffree as i64;

            let cg_header = CylGroupHeader {
                cg_firstfield: 0,
                cg_magic: CG_MAGIC,
                cg_old_time: 0,
                cg_cgx: i as u32,
                cg_old_ncyl: 0,
                cg_old_niblk: 0,
                cg_ndblk: layout.fpg - layout.dblkno as u32,
                cg_cs: *summary,
                cg_rotor: 0,
                cg_frotor: 0,
                cg_irotor: 0,
                cg_frsum: [0; MAXFRAG],
                cg_old_btotoff: 0,
                cg_old_boff: 0,
                cg_iusedoff: 168,
                cg_freeoff: 168 + howmany(layout.ipg as u64, 8) as u32,
                cg_nextfreeoff: 0, // Not strictly used by kernel
                cg_clustersumoff: 0,
                cg_clusteroff: 0,
                cg_nclusterblks: 0,
                cg_niblk: layout.ipg,
                cg_initediblk: layout.ipg,
                cg_unrefs: 0,
                cg_sparecon32: [0; 1],
                cg_ckhash: 0,
                cg_time: sb.fs_time,
                cg_sparecon64: [0; 3],
            };

            let cg_base = i as u64 * layout.fpg as u64 * layout.fsize as u64;
            let cg_block_off = (cg_base + (layout.cblkno as u64 * layout.fsize as u64)) as usize;
            buffer[cg_block_off..cg_block_off + 168].copy_from_slice(&cg_header.to_bytes());

            // Inode bitmap
            let start_ino = i as u32 * layout.ipg;
            for j in 0..layout.ipg {
                let ino = start_ino + j;
                if (ino as usize) < inodes.len() && inodes[ino as usize].di_mode != 0 {
                    let byte = j / 8;
                    let bit = j % 8;
                    buffer[cg_block_off + 168 + byte as usize] |= 1 << bit;
                }
            }
            if i == 0 {
                buffer[cg_block_off + 168] |= 0x07; // Mark 0, 1, 2 as used
            }

            // Block bitmap (1 = free, 0 = used)
            let free_off = cg_block_off + cg_header.cg_freeoff as usize;
            let fpg_bytes = howmany(layout.fpg as u64, 8) as usize;
            for j in 0..fpg_bytes {
                buffer[free_off + j] = 0xFF;
            }
            // Mark metadata used
            for j in 0..layout.dblkno as usize {
                buffer[free_off + (j / 8)] &= !(1 << (j % 8));
            }
            // Mark allocated blocks/frags used
            for &frag in allocator.used_frags_per_cg[i].iter() {
                let local_frag = frag - (i as u64 * layout.fpg as u64);
                buffer[free_off + (local_frag as usize / 8)] &= !(1 << (local_frag % 8));
            }

            // Inode table
            let inode_base = (cg_base + (layout.iblkno as u64 * layout.fsize as u64)) as usize;
            for j in 0..layout.ipg {
                let ino = start_ino + j;
                if (ino as usize) < inodes.len() {
                    let off = inode_base + (j as usize * 256);
                    buffer[off..off + 256].copy_from_slice(&inodes[ino as usize].to_bytes());
                }
            }

            // Superblock backup
            if i > 0 {
                let sb_off = (cg_base + (layout.sblkno as u64 * layout.fsize as u64)) as usize;
                buffer[sb_off..sb_off + 1376].copy_from_slice(&sb.to_bytes());
            }
        }

        // Write CG summary area
        let cs_off = (layout.csaddr * layout.fsize as i64) as usize;
        for (i, summary) in cg_summaries.iter().enumerate() {
            let off = cs_off + i * 16;
            buffer[off..off + 4].copy_from_slice(&summary.cs_ndir.to_le_bytes());
            buffer[off + 4..off + 8].copy_from_slice(&summary.cs_nbfree.to_le_bytes());
            buffer[off + 8..off + 12].copy_from_slice(&summary.cs_nifree.to_le_bytes());
            buffer[off + 12..off + 16].copy_from_slice(&summary.cs_nffree.to_le_bytes());
        }

        sb.fs_cstotal = total_summary;
        sb.fs_old_cstotal = CgSummary {
            cs_ndir: total_summary.cs_ndir as i32,
            cs_nbfree: total_summary.cs_nbfree as i32,
            cs_nifree: total_summary.cs_nifree as i32,
            cs_nffree: total_summary.cs_nffree as i32,
        };
        // Primary Superblock
        buffer[65536..65536 + 1376].copy_from_slice(&sb.to_bytes());

        let mut out = File::create(output)?;
        out.write_all(&buffer)?;
        Ok(())
    }

    fn build_dir_data(&self, entry: &FileEntry, tree: &SourceTree, _layout: &FsLayout) -> Vec<u8> {
        let mut chunks = Vec::new();
        let mut current_chunk = Vec::new();

        let add_entry = |ino: u32,
                         name: &str,
                         d_type: u8,
                         current_chunk: &mut Vec<u8>,
                         chunks: &mut Vec<Vec<u8>>| {
            let namelen = name.len();
            let reclen = (8 + namelen + 1).div_ceil(4) * 4;

            if current_chunk.len() + reclen > 512 {
                self.finalize_chunk(current_chunk);
                chunks.push(std::mem::take(current_chunk));
            }

            let mut entry_bytes = vec![0u8; reclen];
            entry_bytes[0..4].copy_from_slice(&ino.to_le_bytes());
            entry_bytes[4..6].copy_from_slice(&(reclen as u16).to_le_bytes());
            entry_bytes[6] = d_type;
            entry_bytes[7] = namelen as u8;
            entry_bytes[8..8 + namelen].copy_from_slice(name.as_bytes());
            current_chunk.extend_from_slice(&entry_bytes);
        };

        add_entry(entry.ino, ".", 4, &mut current_chunk, &mut chunks);
        add_entry(entry.parent_ino, "..", 4, &mut current_chunk, &mut chunks);

        for &child_ino in &entry.children {
            let child = tree.entries.iter().find(|e| e.ino == child_ino).unwrap();
            let d_type = match child.kind {
                EntryKind::Dir => 4,
                EntryKind::File => 8,
                EntryKind::Symlink(_) => 10,
                EntryKind::CharDev(_) => 2,
                EntryKind::BlockDev(_) => 3,
                EntryKind::Fifo => 1,
                EntryKind::Socket => 12,
            };
            let name = child.path.file_name().unwrap().to_str().unwrap();
            add_entry(child_ino, name, d_type, &mut current_chunk, &mut chunks);
        }

        if !current_chunk.is_empty() {
            self.finalize_chunk(&mut current_chunk);
            chunks.push(current_chunk);
        }

        let mut data = Vec::new();
        for chunk in chunks {
            data.extend_from_slice(&chunk);
        }
        data
    }

    fn finalize_chunk(&self, chunk: &mut Vec<u8>) {
        if chunk.is_empty() {
            return;
        }
        let mut last_off = 0;
        let mut curr = 0;
        while curr < chunk.len() {
            last_off = curr;
            let rec = u16::from_le_bytes([chunk[curr + 4], chunk[curr + 5]]);
            curr += rec as usize;
        }
        let padding = 512 - chunk.len();
        let old_reclen = u16::from_le_bytes([chunk[last_off + 4], chunk[last_off + 5]]);
        let new_reclen = old_reclen + padding as u16;
        chunk[last_off + 4..last_off + 6].copy_from_slice(&new_reclen.to_le_bytes());
        chunk.resize(512, 0);
    }

    fn allocate_data(
        &self,
        inode: &mut Ufs2Dinode,
        data: &[u8],
        allocator: &mut Allocator,
        layout: &FsLayout,
        buffer: &mut [u8],
        cg_summaries: &mut [CgSummary],
    ) -> Result<(), UfsError> {
        let mut remaining = data.len();
        let mut block_idx = 0;

        while remaining > 0 {
            let size = remaining.min(layout.bsize as usize);
            let frags = size.div_ceil(layout.fsize as usize) as u32;
            let (_cg, frag_addr) = allocator.alloc_frags(frags, layout, cg_summaries);

            let offset = (frag_addr * layout.fsize as u64) as usize;
            buffer[offset..offset + size]
                .copy_from_slice(&data[data.len() - remaining..data.len() - remaining + size]);

            if block_idx < 12 {
                inode.di_db[block_idx] = frag_addr as i64;
            } else {
                // Implement single indirect
                if inode.di_ib[0] == 0 {
                    let (_, ib_addr) = allocator.alloc_frags(layout.frag, layout, cg_summaries);
                    inode.di_ib[0] = ib_addr as i64;
                    inode.di_blocks += 64; // Indirect block itself
                }
                let ib_offset = (inode.di_ib[0] as u64 * layout.fsize as u64) as usize;
                let ib_idx = block_idx - 12;
                if ib_idx >= (layout.bsize / 8) as usize {
                    return Err(UfsError::Other("File too large for single indirect".into()));
                }
                buffer[ib_offset + ib_idx * 8..ib_offset + ib_idx * 8 + 8]
                    .copy_from_slice(&(frag_addr as i64).to_le_bytes());
            }

            inode.di_blocks += (frags * layout.fsize / 512) as u64;
            remaining -= size;
            block_idx += 1;
        }
        Ok(())
    }
}

struct Allocator {
    next_frag_per_cg: Vec<u64>,
    used_frags_per_cg: Vec<Vec<u64>>,
    current_cg: usize,
}

impl Allocator {
    fn new(layout: &FsLayout) -> Self {
        Self {
            next_frag_per_cg: (0..layout.ncg)
                .map(|i| i as u64 * layout.fpg as u64 + layout.dblkno as u64)
                .collect(),
            used_frags_per_cg: vec![Vec::new(); layout.ncg as usize],
            current_cg: 0,
        }
    }

    fn alloc_frags(
        &mut self,
        frags: u32,
        layout: &FsLayout,
        cg_summaries: &mut [CgSummary],
    ) -> (usize, u64) {
        loop {
            let cg = self.current_cg;
            let base = cg as u64 * layout.fpg as u64;
            let end = (base + layout.fpg as u64).min(layout.fs_size as u64);

            if self.next_frag_per_cg[cg] + frags as u64 <= end {
                let addr = self.next_frag_per_cg[cg];
                self.next_frag_per_cg[cg] += frags as u64;
                for i in 0..frags {
                    self.used_frags_per_cg[cg].push(addr + i as u64);
                }
                // Update summary
                if frags == layout.frag {
                    cg_summaries[cg].cs_nbfree -= 1;
                } else {
                    cg_summaries[cg].cs_nffree -= frags as i32; // This is a simplification
                }
                return (cg, addr);
            }
            self.current_cg = (self.current_cg + 1) % layout.ncg as usize;
            if self.current_cg == cg {
                panic!("Out of space");
            }
        }
    }
}

fn howmany(x: u64, y: u64) -> u64 {
    x.div_ceil(y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ufs_writer_basic() -> Result<(), UfsError> {
        let temp_source = tempdir().map_err(UfsError::Io)?;
        let source_path = temp_source.path();

        // Create some files and directories
        fs::create_dir(source_path.join("boot")).map_err(UfsError::Io)?;
        fs::write(source_path.join("boot/loader.conf"), b"test_content").map_err(UfsError::Io)?;
        fs::write(source_path.join("hello.txt"), b"world").map_err(UfsError::Io)?;

        let temp_out = tempdir().map_err(UfsError::Io)?;
        let output_img = temp_out.path().join("test.img");

        let writer = UfsWriter::new(10 * 1024 * 1024, "TESTVOL"); // 10MB
        writer.write(source_path, &output_img)?;

        assert!(output_img.exists());
        let meta = fs::metadata(&output_img).map_err(UfsError::Io)?;
        assert_eq!(meta.len(), 10 * 1024 * 1024);

        Ok(())
    }
}
