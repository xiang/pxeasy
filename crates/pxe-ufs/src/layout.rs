use crate::format::{SBLOCKSIZE, SBLOCK_UFS2};

#[derive(Debug, Clone)]
pub struct FsLayout {
    pub ncg: u32,
    pub fpg: u32,      // frags per group
    pub ipg: u32,      // inodes per group
    pub fs_size: i64,  // total frags in filesystem
    pub fs_dsize: i64, // data frags
    pub csaddr: i64,   // block address of cg summary area
    pub cssize: i32,   // byte size of cg summary area
    pub sblkno: i32,   // frags from CG start to superblock backup
    pub cblkno: i32,   // frags from CG start to CG block
    pub iblkno: i32,   // frags from CG start to first inode block
    pub dblkno: i32,   // frags from CG start to first data block
    pub bsize: u32,
    pub fsize: u32,
    pub frag: u32,
    pub inopb: u32,
}

impl FsLayout {
    pub fn compute(total_bytes: u64) -> Result<Self, String> {
        let bsize: u32 = 32768;
        let fsize: u32 = 4096;
        let frag: u32 = bsize / fsize;
        let inopb: u32 = bsize / 256; // 128
        let density: u32 = 4096;

        let total_frags = (total_bytes / fsize as u64) as i64;

        let sblkno = roundup(
            howmany(SBLOCK_UFS2 + SBLOCKSIZE as u64, fsize as u64),
            frag as u64,
        ) as i32;
        let cblkno = sblkno + roundup(howmany(SBLOCKSIZE as u64, fsize as u64), frag as u64) as i32;
        let iblkno = cblkno + frag as i32; // One CG-block worth of frags

        let mut fpg = (total_frags / 16) as u32;
        if fpg < frag {
            fpg = frag;
        }

        // Follow mkfs.c:fsinit loop
        let (fpg, ipg) = loop {
            let fragsperinode = (density / fsize).max(1);
            let ipg = roundup(howmany(fpg as u64, fragsperinode as u64), inopb as u64) as u32;

            // CGSIZE macro from fs.h
            // sizeof(struct cg) + howmany(ipg, 8) + howmany(fpg, 8) + 4
            let cg_size = 168 + howmany(ipg as u64, 8) + howmany(fpg as u64, 8) + 4;
            if cg_size <= bsize as u64 - 8 {
                break (fpg, ipg);
            }
            if fpg <= frag {
                return Err("Image too small to hold filesystem metadata".into());
            }
            fpg -= frag;
        };

        let ncg = howmany(total_frags as u64, fpg as u64) as u32;
        let dblkno = iblkno + (ipg / (inopb / frag)) as i32;

        let cssize = roundup((ncg * 16) as u64, fsize as u64) as i32;
        let csaddr = dblkno as i64; // In the first CG's data area

        Ok(FsLayout {
            ncg,
            fpg,
            ipg,
            fs_size: total_frags,
            fs_dsize: total_frags - (ncg as i64 * dblkno as i64), // Rough estimate
            csaddr,
            cssize,
            sblkno,
            cblkno,
            iblkno,
            dblkno,
            bsize,
            fsize,
            frag,
            inopb,
        })
    }
}

fn howmany(x: u64, y: u64) -> u64 {
    x.div_ceil(y)
}

fn roundup(x: u64, y: u64) -> u64 {
    howmany(x, y) * y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_reference_check() {
        // From audit: roundup(howmany(65536 + 8192, 4096), 8) = 24
        assert_eq!(roundup(howmany(65536 + 8192, 4096), 8), 24);

        let layout = FsLayout::compute(64 * 1024 * 1024).unwrap();
        assert_eq!(layout.sblkno, 24);
        assert_eq!(layout.cblkno, 32);
        assert_eq!(layout.iblkno, 40);
    }
}
