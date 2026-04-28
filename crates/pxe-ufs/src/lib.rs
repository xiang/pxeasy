pub mod builder;
pub mod format;
pub mod layout;

use crate::builder::{EntryKind, FileEntry, SourceTree};
use crate::format::*;
use crate::layout::FsLayout;
use crc::{Algorithm, Crc};
use log::{debug, info, trace};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

const FS_METACKHASH: i32 = 0x0000_0200;
const CK_SUPERBLOCK: u32 = 0x0001;
const CK_CYLGRP: u32 = 0x0002;
const FREEBSD_CRC32C: Crc<u32> = Crc::<u32>::new(&Algorithm {
    width: 32,
    poly: 0x1edc_6f41,
    init: u32::MAX,
    refin: true,
    refout: true,
    xorout: 0,
    check: 0,
    residue: 0,
});

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

struct WriteProgress {
    total_files: usize,
    files_written: usize,
    bytes_written: u64,
    started_at: Instant,
    last_logged_at: Instant,
}

impl WriteProgress {
    fn new(total_files: usize) -> Self {
        let now = Instant::now();
        Self {
            total_files,
            files_written: 0,
            bytes_written: 0,
            started_at: now,
            last_logged_at: now,
        }
    }

    fn file_written(&mut self, path: &Path, bytes: u64) {
        self.files_written += 1;
        self.bytes_written += bytes;

        let elapsed = self.last_logged_at.elapsed();
        if self.files_written == 1
            || self.files_written == self.total_files
            || self.files_written.is_multiple_of(1000)
            || elapsed >= Duration::from_secs(5)
        {
            self.last_logged_at = Instant::now();
            debug!(
                "UFS write progress: {}/{} files, {} written in {:.1}s (latest: {:?})",
                self.files_written,
                self.total_files,
                format_bytes(self.bytes_written),
                self.started_at.elapsed().as_secs_f32(),
                path.file_name().unwrap_or_default()
            );
        }
    }

    fn starting_file(&mut self, path: &Path) {
        let elapsed = self.last_logged_at.elapsed();
        if elapsed >= Duration::from_secs(5) {
            self.last_logged_at = Instant::now();
            trace!(
                "UFS write heartbeat: currently at {}/{} ({:?})",
                self.files_written + 1,
                self.total_files,
                path.file_name().unwrap_or_default()
            );
        }
    }

    fn finish(&self) {
        debug!(
            "UFS write finished: {} files, {} written in {:.1}s",
            self.files_written,
            format_bytes(self.bytes_written),
            self.started_at.elapsed().as_secs_f32()
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        format!("{:.1} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.1} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.1} KiB", bytes_f / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn calc_ufs_crc32c(bytes: &[u8]) -> u32 {
    FREEBSD_CRC32C.checksum(bytes)
}

fn superblock_hash(sb: &Superblock) -> u32 {
    let mut bytes = [0u8; SBLOCKSIZE];
    let mut sb_for_hash = *sb;
    sb_for_hash.fs_ckhash = 0;
    bytes[..1376].copy_from_slice(&sb_for_hash.to_bytes());
    calc_ufs_crc32c(&bytes[..sb.fs_sbsize as usize])
}

fn free_fragment_summary(
    bitmap: &[u8],
    frag_count: u32,
    frags_per_block: u32,
) -> (i32, i32, [u32; MAXFRAG]) {
    let mut full_blocks = 0i32;
    let mut free_frags = 0i32;
    let mut frsum = [0u32; MAXFRAG];
    let mut frag = 0;

    while frag < frag_count {
        let block_end = (frag + frags_per_block).min(frag_count);
        let mut block_free_frags = 0u32;

        for idx in frag..block_end {
            if (bitmap[idx as usize / 8] & (1 << (idx % 8))) != 0 {
                block_free_frags += 1;
            }
        }

        if block_end - frag == frags_per_block && block_free_frags == frags_per_block {
            full_blocks += 1;
        } else {
            free_frags += block_free_frags as i32;
            if block_free_frags > 0 {
                frsum[block_free_frags as usize] += 1;
            }
        }

        frag = block_end;
    }

    (full_blocks, free_frags, frsum)
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
        debug!("UFS write: scanning source tree...");
        let tree = SourceTree::scan(source).map_err(UfsError::Other)?;
        let entry_by_ino: HashMap<u32, &FileEntry> = tree
            .entries
            .iter()
            .map(|entry| (entry.ino, entry))
            .collect();
        let layout = FsLayout::compute(self.size).map_err(UfsError::Layout)?;

        info!(
            "UFS layout: {} CGs, {} frags/group, {} inodes/group, {} blocks/frag",
            layout.ncg, layout.fpg, layout.ipg, layout.frag
        );

        debug!("UFS write: allocating {} bytes buffer...", self.size);
        let mut buffer = vec![0u8; self.size as usize];

        let nindir = layout.bsize as u64 / 8; // ufs2_daddr_t is 8 bytes
        let maxfilesize =
            (12 + nindir + nindir * nindir + nindir * nindir * nindir) * layout.bsize as u64 - 1;

        // CGSIZE = FreeBSD's CGSIZE macro with fs_contigsumsize=0:
        //   sizeof(cg)=168 + 4 + howmany(ipg,8) + 2*howmany(fpg,8) + 4
        //   = 176 + howmany(ipg,8) + 2*howmany(fpg,8)
        // fs_cgsize must be CGSIZE rounded to a frag boundary.
        // The kernel checks CGSIZE(fs) <= fs_cgsize as a critical validation.
        let cgsize_raw = 176 + howmany(layout.ipg as u64, 8) + 2 * howmany(layout.fpg as u64, 8);
        let fs_cgsize = howmany(cgsize_raw, layout.fsize as u64) * layout.fsize as u64;

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
            // Max blocks per CG a new file may use; ffs_sbcheck requires > 0.
            fs_maxbpg: layout.fpg.div_ceil(layout.frag) as i32,
            fs_fragshift: 3,
            fs_fsbtodb: 3,
            fs_sbsize: 4096, // fragroundup(sizeof(Superblock)=1376, fsize=4096)
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
            // CGSIZE rounded to a fragment; kernel checks CGSIZE(fs) <= fs_cgsize.
            fs_cgsize: fs_cgsize as i32,
            fs_spare2: 0,
            fs_old_nsect: 0,
            fs_old_spc: 0,
            fs_old_ncyl: 0,
            fs_old_cpg: 0, // UFS2: no old cylinder groups
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
            fs_metackhash: CK_SUPERBLOCK | CK_CYLGRP,
            fs_flags: FS_METACKHASH,
            fs_contigsumsize: 0,
            fs_maxsymlinklen: 120,
            fs_old_inodefmt: 2,
            fs_maxfilesize: maxfilesize,
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
        let mut progress = WriteProgress::new(tree.entries.len());

        debug!("UFS write: processing {} entries...", tree.entries.len());
        for entry in &tree.entries {
            let cg = (entry.ino / layout.ipg) as usize;
            if cg >= layout.ncg as usize {
                return Err(UfsError::Other(format!(
                    "Inode {} out of bounds",
                    entry.ino
                )));
            }

            match &entry.kind {
                EntryKind::File => {
                    progress.starting_file(&entry.path);
                    trace!(
                        "  - Reading host file: {:?}",
                        entry.path.file_name().unwrap_or_default()
                    );
                    let data = fs::read(&entry.path)?;
                    let bytes = data.len() as u64;
                    let mut inode = self.new_inode(entry, &layout, &sb);
                    self.allocate_data(
                        &mut inode,
                        &data,
                        &mut allocator,
                        &layout,
                        &mut buffer,
                        &mut cg_summaries,
                    )?;
                    inodes[entry.ino as usize] = inode;
                    progress.file_written(&entry.path, bytes);
                }
                EntryKind::Dir => {
                    progress.starting_file(&entry.path);
                    trace!(
                        "  - Building directory: {:?}",
                        entry.path.file_name().unwrap_or_default()
                    );
                    let dir_data = self.build_dir_data(entry, &entry_by_ino)?;
                    let mut inode = self.new_inode(entry, &layout, &sb);
                    self.allocate_data(
                        &mut inode,
                        &dir_data,
                        &mut allocator,
                        &layout,
                        &mut buffer,
                        &mut cg_summaries,
                    )?;
                    inode.di_size = dir_data.len() as u64;
                    cg_summaries[cg].cs_ndir += 1;
                    inodes[entry.ino as usize] = inode;
                    progress.file_written(&entry.path, 0);
                }
                EntryKind::Symlink(target) => {
                    let target_bytes = target.to_string_lossy().as_bytes().to_vec();
                    let mut inode = self.new_inode(entry, &layout, &sb);
                    if target_bytes.len() < 120 {
                        let mut shortlink = [0u8; 120];
                        let len = target_bytes.len();
                        shortlink[..len].copy_from_slice(&target_bytes);
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
                            &target_bytes,
                            &mut allocator,
                            &layout,
                            &mut buffer,
                            &mut cg_summaries,
                        )?;
                    }
                    inodes[entry.ino as usize] = inode;
                    progress.file_written(&entry.path, 0);
                }
                EntryKind::CharDev(rdev) | EntryKind::BlockDev(rdev) => {
                    let mut inode = self.new_inode(entry, &layout, &sb);
                    inode.di_db[0] = *rdev as i64;
                    inode.di_size = 0;
                    inode.di_blocks = 0;
                    inodes[entry.ino as usize] = inode;
                    progress.file_written(&entry.path, 0);
                }
                EntryKind::Fifo | EntryKind::Socket => {
                    let mut inode = self.new_inode(entry, &layout, &sb);
                    inode.di_size = 0;
                    inode.di_blocks = 0;
                    inodes[entry.ino as usize] = inode;
                    progress.file_written(&entry.path, 0);
                }
            }

            if entry.ino != UFS_ROOTINO {
                cg_summaries[cg].cs_nifree -= 1;
            }
        }

        progress.finish();

        // 3. Finalize metadata and write to buffer
        debug!("UFS write: finalizing metadata...");
        let mut final_cg_summaries = cg_summaries.clone();
        for (i, summary) in final_cg_summaries.iter_mut().enumerate() {
            let mut cg_header = CylGroupHeader {
                cg_firstfield: 0,
                cg_magic: CG_MAGIC,
                cg_old_time: 0,
                cg_cgx: i as u32,
                cg_old_ncyl: 0,
                cg_old_niblk: 0,
                cg_ndblk: layout.fpg,
                cg_cs: *summary,
                cg_rotor: 0,
                cg_frotor: 0,
                cg_irotor: 0,
                cg_frsum: [0; MAXFRAG],
                cg_old_btotoff: 0,
                cg_old_boff: 0,
                cg_iusedoff: 168,
                cg_freeoff: 168 + howmany(layout.ipg as u64, 8) as u32,
                cg_nextfreeoff: 168
                    + howmany(layout.ipg as u64, 8) as u32
                    + howmany(layout.fpg as u64, 8) as u32,
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

            // Clear stray bits in last bitmap byte for non-8-aligned fpg.
            // fragtbl8 scans full bytes; phantom 1-bits from out-of-range frags
            // would make fragtbl8[byte] disagree with frsum, causing a kernel panic.
            if layout.fpg % 8 != 0 {
                let valid_bits = layout.fpg % 8;
                buffer[free_off + fpg_bytes - 1] &= (1u8 << valid_bits) - 1;
            }

            let cg_frag_count =
                (layout.fs_size as u64 - i as u64 * layout.fpg as u64).min(layout.fpg as u64);
            let (nbfree, nffree, frsum) = free_fragment_summary(
                &buffer[free_off..free_off + fpg_bytes],
                cg_frag_count as u32,
                layout.frag,
            );
            summary.cs_nbfree = nbfree;
            summary.cs_nffree = nffree;
            cg_header.cg_cs = *summary;
            cg_header.cg_frsum = frsum;
            buffer[cg_block_off..cg_block_off + 168].copy_from_slice(&cg_header.to_bytes());

            let cg_hash_end = cg_block_off + fs_cgsize as usize;
            cg_header.cg_ckhash = calc_ufs_crc32c(&buffer[cg_block_off..cg_hash_end]);
            buffer[cg_block_off..cg_block_off + 168].copy_from_slice(&cg_header.to_bytes());

            // Inode table
            let inode_base = (cg_base + (layout.iblkno as u64 * layout.fsize as u64)) as usize;
            for j in 0..layout.ipg {
                let ino = start_ino + j;
                if (ino as usize) < inodes.len() {
                    let off = inode_base + (j as usize * 256);
                    buffer[off..off + 256].copy_from_slice(&inodes[ino as usize].to_bytes());
                }
            }

            // Superblock backups are written after final summary/hash fields are set.
        }

        let mut total_summary = CsumTotal {
            cs_ndir: 0,
            cs_nbfree: 0,
            cs_nifree: 0,
            cs_nffree: 0,
            cs_numclusters: 0,
            cs_spare: [0; 3],
        };
        for summary in &final_cg_summaries {
            total_summary.cs_ndir += summary.cs_ndir as i64;
            total_summary.cs_nifree += summary.cs_nifree as i64;
            total_summary.cs_nbfree += summary.cs_nbfree as i64;
            total_summary.cs_nffree += summary.cs_nffree as i64;
        }

        // Write CG summary area
        let cs_off = (layout.csaddr * layout.fsize as i64) as usize;
        for (i, summary) in final_cg_summaries.iter().enumerate() {
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
        sb.fs_ckhash = superblock_hash(&sb);

        for i in 1..layout.ncg as usize {
            let cg_base = i as u64 * layout.fpg as u64 * layout.fsize as u64;
            let sb_off = (cg_base + (layout.sblkno as u64 * layout.fsize as u64)) as usize;
            buffer[sb_off..sb_off + 1376].copy_from_slice(&sb.to_bytes());
        }

        // Primary Superblock
        buffer[65536..65536 + 1376].copy_from_slice(&sb.to_bytes());

        let mut out = File::create(output)?;
        let chunk_size = 8 * 1024 * 1024; // 8MB chunks
        let mut written = 0;
        let total = buffer.len();
        let start = Instant::now();
        let mut last_log = Instant::now();

        debug!(
            "UFS write: starting disk write of {}...",
            format_bytes(total as u64)
        );

        while written < total {
            let end = (written + chunk_size).min(total);
            out.write_all(&buffer[written..end])?;
            written = end;

            if last_log.elapsed() >= Duration::from_secs(2) || written == total {
                debug!(
                    "UFS disk write: {}/{} ({:.1}%) in {:.1}s",
                    format_bytes(written as u64),
                    format_bytes(total as u64),
                    (written as f64 / total as f64) * 100.0,
                    start.elapsed().as_secs_f32()
                );
                last_log = Instant::now();
            }
        }

        Ok(())
    }

    fn new_inode(&self, entry: &FileEntry, layout: &FsLayout, sb: &Superblock) -> Ufs2Dinode {
        Ufs2Dinode {
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
        }
    }

    fn build_dir_data(
        &self,
        entry: &FileEntry,
        entry_by_ino: &HashMap<u32, &FileEntry>,
    ) -> Result<Vec<u8>, UfsError> {
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
            let child = entry_by_ino.get(&child_ino).copied().ok_or_else(|| {
                UfsError::Other(format!(
                    "directory entry {} references missing inode {}",
                    entry.path.display(),
                    child_ino
                ))
            })?;
            let d_type = match child.kind {
                EntryKind::Dir => 4,
                EntryKind::File => 8,
                EntryKind::Symlink(_) => 10,
                EntryKind::CharDev(_) => 2,
                EntryKind::BlockDev(_) => 6,
                EntryKind::Fifo => 1,
                EntryKind::Socket => 12,
            };
            let name = child
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    UfsError::Other(format!(
                        "non-UTF-8 directory entry name at {}",
                        child.path.display()
                    ))
                })?;
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
        Ok(data)
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
        let ninidir = (layout.bsize / 8) as usize;

        while remaining > 0 {
            let size = remaining.min(layout.bsize as usize);
            let frags = size.div_ceil(layout.fsize as usize) as u32;
            let (_cg, frag_addr) = allocator.alloc_frags(frags, layout, cg_summaries);

            let offset = (frag_addr * layout.fsize as u64) as usize;
            buffer[offset..offset + size]
                .copy_from_slice(&data[data.len() - remaining..data.len() - remaining + size]);

            if block_idx < 12 {
                inode.di_db[block_idx] = frag_addr as i64;
            } else if block_idx < 12 + ninidir {
                // Single indirect
                if inode.di_ib[0] == 0 {
                    let (_, ib_addr) = allocator.alloc_frags(layout.frag, layout, cg_summaries);
                    inode.di_ib[0] = ib_addr as i64;
                    inode.di_blocks += (layout.bsize / 512) as u64;
                }
                let ib_offset = (inode.di_ib[0] as u64 * layout.fsize as u64) as usize;
                let ib_idx = block_idx - 12;
                buffer[ib_offset + ib_idx * 8..ib_offset + ib_idx * 8 + 8]
                    .copy_from_slice(&(frag_addr as i64).to_le_bytes());
            } else {
                // Double indirect
                let dbl_idx = block_idx - 12 - ninidir;
                if dbl_idx >= ninidir * ninidir {
                    return Err(UfsError::Other("File too large for double indirect".into()));
                }

                if inode.di_ib[1] == 0 {
                    let (_, ib_addr) = allocator.alloc_frags(layout.frag, layout, cg_summaries);
                    inode.di_ib[1] = ib_addr as i64;
                    inode.di_blocks += (layout.bsize / 512) as u64;
                }

                let i1_idx = dbl_idx / ninidir;
                let i2_idx = dbl_idx % ninidir;

                let i1_offset = (inode.di_ib[1] as u64 * layout.fsize as u64) as usize;
                let mut i2_addr = i64::from_le_bytes(
                    buffer[i1_offset + i1_idx * 8..i1_offset + i1_idx * 8 + 8]
                        .try_into()
                        .unwrap(),
                );

                if i2_addr == 0 {
                    let (_, ib_addr) = allocator.alloc_frags(layout.frag, layout, cg_summaries);
                    i2_addr = ib_addr as i64;
                    buffer[i1_offset + i1_idx * 8..i1_offset + i1_idx * 8 + 8]
                        .copy_from_slice(&i2_addr.to_le_bytes());
                    inode.di_blocks += (layout.bsize / 512) as u64;
                }

                let i2_offset = (i2_addr as u64 * layout.fsize as u64) as usize;
                buffer[i2_offset + i2_idx * 8..i2_offset + i2_idx * 8 + 8]
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
        // csaddr = dblkno (CG 0's first data frag) — the CS area occupies the first
        // cssize_frags frags of CG 0's data area. Pre-mark them used so data
        // allocation doesn't collide with the CS write that happens last.
        let cssize_frags = layout.cssize as u64 / layout.fsize as u64;
        let mut used_frags_per_cg = vec![Vec::new(); layout.ncg as usize];
        for k in 0..cssize_frags {
            used_frags_per_cg[0].push(layout.dblkno as u64 + k);
        }
        Self {
            next_frag_per_cg: (0..layout.ncg as usize)
                .map(|i| {
                    let base = i as u64 * layout.fpg as u64 + layout.dblkno as u64;
                    if i == 0 {
                        base + cssize_frags
                    } else {
                        base
                    }
                })
                .collect(),
            used_frags_per_cg,
            current_cg: 0,
        }
    }

    fn alloc_frags(
        &mut self,
        frags: u32,
        layout: &FsLayout,
        _cg_summaries: &mut [CgSummary],
    ) -> (usize, u64) {
        let start_cg = self.current_cg;
        let mut attempts = 0;
        loop {
            let cg = self.current_cg;
            let base = cg as u64 * layout.fpg as u64;
            let end = (base + layout.fpg as u64).min(layout.fs_size as u64);
            if frags == layout.frag && !self.next_frag_per_cg[cg].is_multiple_of(layout.frag as u64)
            {
                self.next_frag_per_cg[cg] +=
                    layout.frag as u64 - (self.next_frag_per_cg[cg] % layout.frag as u64);
            }

            if self.next_frag_per_cg[cg] + frags as u64 <= end {
                let addr = self.next_frag_per_cg[cg];
                self.next_frag_per_cg[cg] += frags as u64;
                for i in 0..frags {
                    self.used_frags_per_cg[cg].push(addr + i as u64);
                }
                return (cg, addr);
            }

            attempts += 1;
            if attempts == layout.ncg {
                trace!(
                    "UFS: searched all {} CGs, no space for {} frags",
                    layout.ncg,
                    frags
                );
            }

            self.current_cg = (self.current_cg + 1) % layout.ncg as usize;
            if self.current_cg == start_cg {
                panic!(
                    "Out of space (requested {} frags, checked all {} CGs)",
                    frags, layout.ncg
                );
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

    #[test]
    fn test_free_fragment_summaries_match_bitmap() -> Result<(), UfsError> {
        let temp_source = tempdir().map_err(UfsError::Io)?;
        let source_path = temp_source.path();

        for i in 0..256 {
            fs::write(source_path.join(format!("small-{i:03}.txt")), [b'x'])
                .map_err(UfsError::Io)?;
        }

        let temp_out = tempdir().map_err(UfsError::Io)?;
        let output_img = temp_out.path().join("test.img");
        let image_size = 32 * 1024 * 1024;

        let writer = UfsWriter::new(image_size, "TESTVOL");
        writer.write(source_path, &output_img)?;

        let image = fs::read(&output_img).map_err(UfsError::Io)?;
        let layout = FsLayout::compute(image_size).map_err(UfsError::Layout)?;
        let cgsize_raw = 176 + howmany(layout.ipg as u64, 8) + 2 * howmany(layout.fpg as u64, 8);
        let fs_cgsize = howmany(cgsize_raw, layout.fsize as u64) * layout.fsize as u64;

        let mut total_nbfree = 0i64;
        let mut total_nffree = 0i64;
        for i in 0..layout.ncg as usize {
            let cg_base = i as u64 * layout.fpg as u64 * layout.fsize as u64;
            let cg_block_off = (cg_base + (layout.cblkno as u64 * layout.fsize as u64)) as usize;
            let cg_header = unsafe {
                std::ptr::read_unaligned(image[cg_block_off..].as_ptr() as *const CylGroupHeader)
            };
            let free_off = cg_block_off + cg_header.cg_freeoff as usize;
            let fpg_bytes = howmany(layout.fpg as u64, 8) as usize;
            let cg_frag_count =
                (layout.fs_size as u64 - i as u64 * layout.fpg as u64).min(layout.fpg as u64);
            let (nbfree, nffree, frsum) = free_fragment_summary(
                &image[free_off..free_off + fpg_bytes],
                cg_frag_count as u32,
                layout.frag,
            );

            assert_eq!(cg_header.cg_cs.cs_nbfree, nbfree);
            assert_eq!(cg_header.cg_cs.cs_nffree, nffree);
            assert_eq!(cg_header.cg_frsum, frsum);
            assert!(cg_header.cg_cs.cs_nffree <= cg_frag_count as i32);

            let cg_hash_end = cg_block_off + fs_cgsize as usize;
            let mut cg_bytes = image[cg_block_off..cg_hash_end].to_vec();
            let cg_hash_off =
                (&raw const cg_header.cg_ckhash as usize) - (&raw const cg_header as usize);
            cg_bytes[cg_hash_off..cg_hash_off + 4].fill(0);
            assert_eq!(cg_header.cg_ckhash, calc_ufs_crc32c(&cg_bytes));

            total_nbfree += nbfree as i64;
            total_nffree += nffree as i64;
        }

        let sb = unsafe {
            std::ptr::read_unaligned(image[SBLOCK_UFS2 as usize..].as_ptr() as *const Superblock)
        };
        assert_eq!(sb.fs_cstotal.cs_nbfree, total_nbfree);
        assert_eq!(sb.fs_cstotal.cs_nffree, total_nffree);

        Ok(())
    }

    #[test]
    fn test_full_block_allocations_are_fragment_aligned() -> Result<(), UfsError> {
        let layout = FsLayout::compute(32 * 1024 * 1024).map_err(UfsError::Layout)?;
        let mut summaries = vec![
            CgSummary {
                cs_ndir: 0,
                cs_nbfree: 0,
                cs_nifree: 0,
                cs_nffree: 0,
            };
            layout.ncg as usize
        ];
        let mut allocator = Allocator::new(&layout);

        let (_, partial_addr) = allocator.alloc_frags(1, &layout, &mut summaries);
        let (_, full_addr) = allocator.alloc_frags(layout.frag, &layout, &mut summaries);

        assert_ne!(partial_addr % layout.frag as u64, 0);
        assert_eq!(full_addr % layout.frag as u64, 0);

        Ok(())
    }

    // fragtbl8[byte]: bit k-1 set for each maximal contiguous free-frag run of length k.
    // This mirrors the kernel's fragtbl8 table used in ffs_mapsearch.
    fn fragtbl8_entry(byte: u8) -> u8 {
        let mut result = 0u8;
        let mut i = 0u8;
        while i < 8 {
            if (byte >> i) & 1 != 0 {
                let start = i;
                while i < 8 && (byte >> i) & 1 != 0 {
                    i += 1;
                }
                let run_len = i - start;
                if run_len < 8 {
                    result |= 1 << (run_len - 1);
                }
            } else {
                i += 1;
            }
        }
        result
    }

    // 576KB image produces fpg=9 (fpg%8=1). Before the stray-bit fix, the last
    // bitmap byte was 0xFF instead of 0x01, causing fragtbl8[0xFF]=0x80 to not
    // match allocsiz=1 mask 0x01 — the exact kernel panic we saw.
    #[test]
    fn test_bitmap_fragtbl_consistency_nonaligned_fpg() -> Result<(), UfsError> {
        let image_size = 589_824u64; // 576KB: fpg=9, fpg%8=1
        let temp_source = tempdir().map_err(UfsError::Io)?;
        fs::write(temp_source.path().join("test.txt"), b"hello").map_err(UfsError::Io)?;
        let temp_out = tempdir().map_err(UfsError::Io)?;
        let output_img = temp_out.path().join("test.img");
        let writer = UfsWriter::new(image_size, "TESTVOL");
        writer.write(temp_source.path(), &output_img)?;

        let image = fs::read(&output_img).map_err(UfsError::Io)?;
        let layout = FsLayout::compute(image_size).map_err(UfsError::Layout)?;
        assert_eq!(layout.fpg % 8, 1, "test requires non-8-aligned fpg");

        for i in 0..layout.ncg as usize {
            let cg_base = i as u64 * layout.fpg as u64 * layout.fsize as u64;
            let cg_block_off = (cg_base + layout.cblkno as u64 * layout.fsize as u64) as usize;
            let cg_header = unsafe {
                std::ptr::read_unaligned(image[cg_block_off..].as_ptr() as *const CylGroupHeader)
            };
            let free_off = cg_block_off + cg_header.cg_freeoff as usize;
            let fpg_bytes = howmany(layout.fpg as u64, 8) as usize;
            let bitmap = &image[free_off..free_off + fpg_bytes];

            // No stray bits in the last byte beyond fpg%8 valid frags.
            let valid_bits = layout.fpg % 8;
            let last_byte = bitmap[fpg_bytes - 1];
            assert_eq!(
                last_byte >> valid_bits,
                0,
                "CG{i}: last bitmap byte 0x{last_byte:02x} has stray bits (valid_bits={valid_bits})"
            );

            // fragtbl8 consistency: every frsum[k]>0 entry must have a matching
            // bitmap byte so ffs_mapsearch (mask=1<<(k-1)) can find it.
            for k in 1..8usize {
                if cg_header.cg_frsum[k] > 0 {
                    let mask = 1u8 << (k - 1);
                    let found = bitmap.iter().any(|&b| fragtbl8_entry(b) & mask != 0);
                    assert!(
                        found,
                        "CG{i}: frsum[{k}]={} but no bitmap byte has fragtbl8 bit {} set",
                        cg_header.cg_frsum[k],
                        k - 1
                    );
                }
            }
        }
        Ok(())
    }
}
