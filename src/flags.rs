// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Flag constants and translation between the btrfs inode B-tree's
// BTRFS_INODE_* bits (kernel-internal, what TREE_SEARCH_V2 returns) and the
// FS_*_FL bits exposed via FS_IOC_GETFLAGS to userspace and printed by lsattr.
//
// The btrfs in-tree flag space is a strict subset of FS_*_FL: it doesn't carry
// encryption, project quotas, casefold, verity, dax, etc. Those slots therefore
// always read as `-` in our output even when the on-disk inode has the
// corresponding fs-level attribute set elsewhere. We document this in README.

// FS_*_FL bits, from <linux/fs.h>. lsattr only ever sees this namespace.
pub const FS_SECRM_FL: u32 = 0x0000_0001;
pub const FS_UNRM_FL: u32 = 0x0000_0002;
pub const FS_COMPR_FL: u32 = 0x0000_0004;
pub const FS_SYNC_FL: u32 = 0x0000_0008;
pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const FS_APPEND_FL: u32 = 0x0000_0020;
pub const FS_NODUMP_FL: u32 = 0x0000_0040;
pub const FS_NOATIME_FL: u32 = 0x0000_0080;
pub const FS_NOCOMP_FL: u32 = 0x0000_0400;
pub const FS_ENCRYPT_FL: u32 = 0x0000_0800;
pub const FS_INDEX_FL: u32 = 0x0000_1000;
pub const FS_JOURNAL_DATA_FL: u32 = 0x0000_4000;
pub const FS_NOTAIL_FL: u32 = 0x0000_8000;
pub const FS_DIRSYNC_FL: u32 = 0x0001_0000;
pub const FS_TOPDIR_FL: u32 = 0x0002_0000;
pub const FS_EXTENT_FL: u32 = 0x0008_0000;
pub const FS_VERITY_FL: u32 = 0x0010_0000;
pub const FS_NOCOW_FL: u32 = 0x0080_0000;
pub const FS_DAX_FL: u32 = 0x0200_0000;
pub const FS_INLINE_DATA_FL: u32 = 0x1000_0000;
pub const FS_PROJINHERIT_FL: u32 = 0x2000_0000;
pub const FS_CASEFOLD_FL: u32 = 0x4000_0000;

// BTRFS_INODE_* bits, from <linux/btrfs_tree.h>. The three constants marked
// dead_code (NODATASUM/READONLY/PREALLOC) document which bits btrfs_to_fs
// deliberately drops; they're only referenced from tests.
#[allow(dead_code)]
pub const BTRFS_INODE_NODATASUM: u64 = 1 << 0;
pub const BTRFS_INODE_NODATACOW: u64 = 1 << 1;
#[allow(dead_code)]
pub const BTRFS_INODE_READONLY: u64 = 1 << 2;
pub const BTRFS_INODE_NOCOMPRESS: u64 = 1 << 3;
#[allow(dead_code)]
pub const BTRFS_INODE_PREALLOC: u64 = 1 << 4;
pub const BTRFS_INODE_SYNC: u64 = 1 << 5;
pub const BTRFS_INODE_IMMUTABLE: u64 = 1 << 6;
pub const BTRFS_INODE_APPEND: u64 = 1 << 7;
pub const BTRFS_INODE_NODUMP: u64 = 1 << 8;
pub const BTRFS_INODE_NOATIME: u64 = 1 << 9;
pub const BTRFS_INODE_DIRSYNC: u64 = 1 << 10;
pub const BTRFS_INODE_COMPRESS: u64 = 1 << 11;

// First non-system objectid in any btrfs subvol; the subvol-root inode itself.
// INO_PATHS on this inum walks up into the parent tree (so the scan callback
// skips it), and it is what an opened fd's st_ino must equal to be a subvol
// root. From <linux/btrfs_tree.h> BTRFS_FIRST_FREE_OBJECTID.
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// FS_*_FL bits that are represented directly in btrfs INODE_ITEM flags and
/// can therefore be filtered by the tree-search fast path.
pub const BTRFS_SUPPORTED_FS_MASK: u32 = FS_SYNC_FL
    | FS_IMMUTABLE_FL
    | FS_APPEND_FL
    | FS_NODUMP_FL
    | FS_NOATIME_FL
    | FS_DIRSYNC_FL
    | FS_COMPR_FL
    | FS_NOCOMP_FL
    | FS_NOCOW_FL;

/// Translate the inode B-tree's BTRFS_INODE_* bits into the FS_*_FL bits that
/// `lsattr` knows about. NODATASUM/READONLY/PREALLOC are not part of the
/// FS_IOC_GETFLAGS namespace — drop them silently to mirror kernel behaviour
/// (see `fs/btrfs/ioctl.c btrfs_inode_flags_to_fsflags`).
pub fn btrfs_to_fs(b: u64) -> u32 {
    let mut f: u32 = 0;
    if b & BTRFS_INODE_SYNC != 0 {
        f |= FS_SYNC_FL;
    }
    if b & BTRFS_INODE_IMMUTABLE != 0 {
        f |= FS_IMMUTABLE_FL;
    }
    if b & BTRFS_INODE_APPEND != 0 {
        f |= FS_APPEND_FL;
    }
    if b & BTRFS_INODE_NODUMP != 0 {
        f |= FS_NODUMP_FL;
    }
    if b & BTRFS_INODE_NOATIME != 0 {
        f |= FS_NOATIME_FL;
    }
    if b & BTRFS_INODE_DIRSYNC != 0 {
        f |= FS_DIRSYNC_FL;
    }
    if b & BTRFS_INODE_NODATACOW != 0 {
        f |= FS_NOCOW_FL;
    }
    if b & BTRFS_INODE_NOCOMPRESS != 0 {
        f |= FS_NOCOMP_FL;
    }
    if b & BTRFS_INODE_COMPRESS != 0 {
        f |= FS_COMPR_FL;
    }
    f
}

pub struct LetterSpec {
    pub bit: u32,
    pub letter: char,
    pub long: &'static str,
}

// Canonical e2fsprogs `flags_array[]` order. Matches `lsattr` column layout
// exactly (22 slots).
#[rustfmt::skip]
pub const LETTERS: &[LetterSpec] = &[
    LetterSpec { bit: FS_SECRM_FL, letter: 's', long: "Secure_Deletion" },
    LetterSpec { bit: FS_UNRM_FL, letter: 'u', long: "Undelete" },
    LetterSpec { bit: FS_SYNC_FL, letter: 'S', long: "Synchronous_Updates" },
    LetterSpec { bit: FS_DIRSYNC_FL, letter: 'D', long: "Synchronous_Directory_Updates" },
    LetterSpec { bit: FS_IMMUTABLE_FL, letter: 'i', long: "Immutable" },
    LetterSpec { bit: FS_APPEND_FL, letter: 'a', long: "Append_Only" },
    LetterSpec { bit: FS_NODUMP_FL, letter: 'd', long: "No_Dump" },
    LetterSpec { bit: FS_NOATIME_FL, letter: 'A', long: "No_Atime" },
    LetterSpec { bit: FS_COMPR_FL, letter: 'c', long: "Compression_Requested" },
    LetterSpec { bit: FS_ENCRYPT_FL, letter: 'E', long: "Encrypted" },
    LetterSpec { bit: FS_JOURNAL_DATA_FL, letter: 'j', long: "Journaled_Data" },
    LetterSpec { bit: FS_INDEX_FL, letter: 'I', long: "Indexed_directory" },
    LetterSpec { bit: FS_NOTAIL_FL, letter: 't', long: "No_Tailmerging" },
    LetterSpec { bit: FS_TOPDIR_FL, letter: 'T', long: "Top_of_Directory_Hierarchies" },
    LetterSpec { bit: FS_EXTENT_FL, letter: 'e', long: "Extents" },
    LetterSpec { bit: FS_NOCOW_FL, letter: 'C', long: "No_COW" },
    LetterSpec { bit: FS_DAX_FL, letter: 'x', long: "DAX" },
    LetterSpec { bit: FS_CASEFOLD_FL, letter: 'F', long: "Casefold" },
    LetterSpec { bit: FS_INLINE_DATA_FL, letter: 'N', long: "Inline_Data" },
    LetterSpec { bit: FS_PROJINHERIT_FL, letter: 'P', long: "Project_Hierarchy" },
    LetterSpec { bit: FS_VERITY_FL, letter: 'V', long: "Verity" },
    LetterSpec { bit: FS_NOCOMP_FL, letter: 'm', long: "Dont_Compress" },
];

/// Parse an `--has` letter sequence into a fs-flag bitmask.
pub fn letters_to_mask(s: &str) -> Result<u32, char> {
    let mut mask: u32 = 0;
    for c in s.chars() {
        match LETTERS.iter().find(|l| l.letter == c) {
            Some(spec) => mask |= spec.bit,
            None => return Err(c),
        }
    }
    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodatacow_translates_to_nocow() {
        assert_eq!(btrfs_to_fs(BTRFS_INODE_NODATACOW), FS_NOCOW_FL);
    }

    #[test]
    fn immutable_and_nocow_combine() {
        let b = BTRFS_INODE_IMMUTABLE | BTRFS_INODE_NODATACOW;
        let f = btrfs_to_fs(b);
        assert!(f & FS_IMMUTABLE_FL != 0);
        assert!(f & FS_NOCOW_FL != 0);
    }

    #[test]
    fn unmapped_btrfs_bits_drop() {
        // NODATASUM/READONLY/PREALLOC are not exposed via FS_IOC_GETFLAGS.
        let b = BTRFS_INODE_NODATASUM | BTRFS_INODE_READONLY | BTRFS_INODE_PREALLOC;
        assert_eq!(btrfs_to_fs(b), 0);
    }

    #[test]
    fn letters_count_matches_lsattr() {
        assert_eq!(LETTERS.len(), 22);
    }

    #[test]
    fn letters_in_canonical_order() {
        let order: String = LETTERS.iter().map(|l| l.letter).collect();
        assert_eq!(order, "suSDiadAcEjItTeCxFNPVm");
    }

    #[test]
    fn letters_to_mask_simple() {
        assert_eq!(letters_to_mask("C").unwrap(), FS_NOCOW_FL);
        assert_eq!(
            letters_to_mask("Ci").unwrap(),
            FS_NOCOW_FL | FS_IMMUTABLE_FL
        );
    }

    #[test]
    fn letters_to_mask_unknown() {
        assert_eq!(letters_to_mask("Cz"), Err('z'));
    }

    #[test]
    fn btrfs_supported_mask_is_exact_fast_path_subset() {
        assert_eq!(
            BTRFS_SUPPORTED_FS_MASK,
            letters_to_mask("SiadADcmC").unwrap()
        );
    }
}
