pub const FS_UFS2_MAGIC: u32 = 0x19540119;
pub const CG_MAGIC: u32 = 0x090255;
pub const SBLOCK_UFS2: u64 = 65536;
pub const SBLOCKSIZE: usize = 8192;
pub const BBSIZE: usize = 8192;
pub const UFS_ROOTINO: u32 = 2;
pub const UFS_NDADDR: usize = 12;
pub const UFS_NIADDR: usize = 3;
pub const MAXNAMLEN: usize = 255;
pub const DIRBLKSIZ: usize = 512;
pub const MAXMNTLEN: usize = 468;
pub const MAXVOLLEN: usize = 32;
pub const FSMAXSNAP: usize = 20;
pub const MAXFRAG: usize = 8;
pub const NOCSPTRS: usize = 15;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CgSummary {
    pub cs_ndir: i32,
    pub cs_nbfree: i32,
    pub cs_nifree: i32,
    pub cs_nffree: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CsumTotal {
    pub cs_ndir: i64,
    pub cs_nbfree: i64,
    pub cs_nifree: i64,
    pub cs_nffree: i64,
    pub cs_numclusters: i64,
    pub cs_spare: [i64; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Superblock {
    pub fs_firstfield: i32,
    pub fs_unused_1: i32,
    pub fs_sblkno: i32,
    pub fs_cblkno: i32,
    pub fs_iblkno: i32,
    pub fs_dblkno: i32,
    pub fs_old_cgoffset: i32,
    pub fs_old_cgmask: i32,
    pub fs_old_time: i32,
    pub fs_old_size: i32,
    pub fs_old_dsize: i32,
    pub fs_ncg: u32,
    pub fs_bsize: i32,
    pub fs_fsize: i32,
    pub fs_frag: i32,
    pub fs_minfree: i32,
    pub fs_old_rotdelay: i32,
    pub fs_old_rps: i32,
    pub fs_bmask: i32,
    pub fs_fmask: i32,
    pub fs_bshift: i32,
    pub fs_fshift: i32,
    pub fs_maxcontig: i32,
    pub fs_maxbpg: i32,
    pub fs_fragshift: i32,
    pub fs_fsbtodb: i32,
    pub fs_sbsize: i32,
    pub fs_spare1: [i32; 2],
    pub fs_nindir: i32,
    pub fs_inopb: u32,
    pub fs_old_nspf: i32,
    pub fs_optim: i32,
    pub fs_old_npsect: i32,
    pub fs_old_interleave: i32,
    pub fs_old_trackskew: i32,
    pub fs_id: [i32; 2],
    pub fs_old_csaddr: i32,
    pub fs_cssize: i32,
    pub fs_cgsize: i32,
    pub fs_spare2: i32,
    pub fs_old_nsect: i32,
    pub fs_old_spc: i32,
    pub fs_old_ncyl: i32,
    pub fs_old_cpg: i32,
    pub fs_ipg: u32,
    pub fs_fpg: i32,
    pub fs_old_cstotal: CgSummary,
    pub fs_fmod: i8,
    pub fs_clean: i8,
    pub fs_ronly: i8,
    pub fs_old_flags: i8,
    pub fs_fsmnt: [u8; MAXMNTLEN],
    pub fs_volname: [u8; MAXVOLLEN],
    pub fs_swuid: u64,
    pub fs_pad: i32,
    pub fs_cgrotor: i32,
    pub fs_ocsp: [u64; NOCSPTRS],
    pub fs_si: u64,
    pub fs_old_cpc: i32,
    pub fs_maxbsize: i32,
    pub fs_unrefs: i64,
    pub fs_providersize: i64,
    pub fs_metaspace: i64,
    pub fs_save_maxfilesize: u64,
    pub fs_sparecon64: [i64; 12],
    pub fs_sblockactualloc: i64,
    pub fs_sblockloc: i64,
    pub fs_cstotal: CsumTotal,
    pub fs_time: i64,
    pub fs_size: i64,
    pub fs_dsize: i64,
    pub fs_csaddr: i64,
    pub fs_pendingblocks: i64,
    pub fs_pendinginodes: u32,
    pub fs_snapinum: [u32; FSMAXSNAP],
    pub fs_avgfilesize: u32,
    pub fs_avgfpdir: u32,
    pub fs_available_spare: u32,
    pub fs_mtime: i64,
    pub fs_sujfree: i32,
    pub fs_sparecon32: [i32; 21],
    pub fs_ckhash: u32,
    pub fs_metackhash: u32,
    pub fs_flags: i32,
    pub fs_contigsumsize: i32,
    pub fs_maxsymlinklen: i32,
    pub fs_old_inodefmt: i32,
    pub fs_maxfilesize: u64,
    pub fs_qbmask: i64,
    pub fs_qfmask: i64,
    pub fs_state: i32,
    pub fs_old_postblformat: i32,
    pub fs_old_nrpos: i32,
    pub fs_spare5: [i32; 2],
    pub fs_magic: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CylGroupHeader {
    pub cg_firstfield: i32,
    pub cg_magic: u32,
    pub cg_old_time: i32,
    pub cg_cgx: u32,
    pub cg_old_ncyl: i16,
    pub cg_old_niblk: i16,
    pub cg_ndblk: u32,
    pub cg_cs: CgSummary,
    pub cg_rotor: u32,
    pub cg_frotor: u32,
    pub cg_irotor: u32,
    pub cg_frsum: [u32; MAXFRAG],
    pub cg_old_btotoff: i32,
    pub cg_old_boff: i32,
    pub cg_iusedoff: u32,
    pub cg_freeoff: u32,
    pub cg_nextfreeoff: u32,
    pub cg_clustersumoff: u32,
    pub cg_clusteroff: u32,
    pub cg_nclusterblks: u32,
    pub cg_niblk: u32,
    pub cg_initediblk: u32,
    pub cg_unrefs: u32,
    pub cg_sparecon32: [i32; 1],
    pub cg_ckhash: u32,
    pub cg_time: i64,
    pub cg_sparecon64: [i64; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ufs2Dinode {
    pub di_mode: u16,
    pub di_nlink: u16,
    pub di_uid: u32,
    pub di_gid: u32,
    pub di_blksize: u32,
    pub di_size: u64,
    pub di_blocks: u64,
    pub di_atime: i64,
    pub di_mtime: i64,
    pub di_ctime: i64,
    pub di_birthtime: i64,
    pub di_mtimensec: i32,
    pub di_atimensec: i32,
    pub di_ctimensec: i32,
    pub di_birthnsec: i32,
    pub di_gen: u32,
    pub di_kernflags: u32,
    pub di_flags: u32,
    pub di_extsize: u32,
    pub di_extb: [i64; 2],
    pub di_db: [i64; 12],
    pub di_ib: [i64; 3],
    pub di_modrev: u64,
    pub di_freelink: u32,
    pub di_ckhash: u32,
    pub di_spare: [u32; 2],
}

#[repr(C)]
pub struct Direct {
    pub d_ino: u32,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_namlen: u8,
    pub d_name: [u8; 0],
}

impl Superblock {
    pub fn to_bytes(&self) -> [u8; 1376] {
        let mut bytes = [0u8; 1376];
        let src = unsafe {
            std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        bytes[..src.len()].copy_from_slice(src);
        bytes
    }
}

impl CylGroupHeader {
    pub fn to_bytes(&self) -> [u8; 168] {
        let mut bytes = [0u8; 168];
        let src = unsafe {
            std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        bytes[..src.len()].copy_from_slice(src);
        bytes
    }
}

impl Ufs2Dinode {
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut bytes = [0u8; 256];
        let src = unsafe {
            std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        bytes[..src.len()].copy_from_slice(src);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn struct_sizes() {
        assert_eq!(mem::size_of::<CgSummary>(), 16);
        assert_eq!(mem::size_of::<CsumTotal>(), 64);
        assert_eq!(mem::size_of::<Superblock>(), 1376);
        assert_eq!(mem::size_of::<CylGroupHeader>(), 168);
        assert_eq!(mem::size_of::<Ufs2Dinode>(), 256);
    }
}
