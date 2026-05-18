// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Btrfs ioctl glue for the `--has` fast path: a streaming flags-only sweep
// (`scan_flags`) plus a per-match path resolver (`ino_paths`). Reading every
// inode's flags off the B-tree, then resolving paths only for the few that
// pass the filter, beats reading every INODE_REF/EXTREF page off cold disk.
// Both ioctls require CAP_SYS_ADMIN.

use std::fs::OpenOptions;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr;

use crate::flags::BTRFS_FIRST_FREE_OBJECTID;

const BTRFS_IOCTL_MAGIC: u32 = 0x94;
// Only INODE_ITEM is read; INODE_REF/EXTREF are skipped because INO_PATHS
// resolves matching inodes' paths separately.
const BTRFS_INODE_ITEM_KEY: u32 = 1;

// Offset of `flags` within btrfs_inode_item (packed). Derived:
//   generation+transid+size+nbytes+block_group = 5*8 = 40
//   + nlink+uid+gid+mode = 4*4 = 16
//   + rdev = 8 → 64. Reading just this u64 avoids a 152-byte struct copy
// per inode in the hot path.
const INODE_ITEM_FLAGS_OFF: usize = 64;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct BtrfsIoctlSearchKey {
    tree_id: u64,
    min_objectid: u64,
    max_objectid: u64,
    min_offset: u64,
    max_offset: u64,
    min_transid: u64,
    max_transid: u64,
    min_type: u32,
    max_type: u32,
    nr_items: u32,
    _unused32: u32,
    _unused64: [u64; 4],
}

#[repr(C)]
struct BtrfsIoctlSearchHeader {
    transid: u64,
    objectid: u64,
    offset: u64,
    typ: u32,
    len: u32,
}

#[repr(C)]
struct BtrfsIoctlInoPathArgs {
    inum: u64,
    size: u64,
    _reserved: [u64; 4],
    fspath: u64,
}

#[repr(C)]
struct BtrfsDataContainer {
    _bytes_left: u32,
    bytes_missing: u32,
    elem_cnt: u32,
    elem_missed: u32,
}

const fn ioc_rw(ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    // _IOC encoding: dir(2) << 30 | size(14) << 16 | type(8) << 8 | nr(8)
    ((3u32 << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
}

// _IOWR(0x94, 17, struct btrfs_ioctl_search_args_v2): {key (104B), buf_size (8B)}.
const BTRFS_IOC_TREE_SEARCH_V2: libc::c_ulong = ioc_rw(
    BTRFS_IOCTL_MAGIC,
    17,
    (mem::size_of::<BtrfsIoctlSearchKey>() + 8) as u32,
);
// _IOWR(0x94, 35, struct btrfs_ioctl_ino_path_args).
const BTRFS_IOC_INO_PATHS: libc::c_ulong = ioc_rw(
    BTRFS_IOCTL_MAGIC,
    35,
    mem::size_of::<BtrfsIoctlInoPathArgs>() as u32,
);

// 64KB holds ~340 inode_items+headers per ioctl, hard-capped by SEARCH_NR_ITEMS.
const SEARCH_BUF_BYTES: usize = 64 * 1024;
const SEARCH_NR_ITEMS: u32 = 4096;
// Per-inode path buffer: PATH_MAX=4096 plus headroom for hardlinked paths.
const FSPATH_BUF_BYTES: usize = 16 * 1024;
const MAX_FSPATH_BUF_BYTES: usize = 16 * 1024 * 1024;

const _: () = assert!(mem::size_of::<BtrfsIoctlSearchKey>() == 104);
const _: () = assert!(mem::size_of::<BtrfsIoctlSearchHeader>() == 32);
const _: () = assert!(mem::size_of::<BtrfsIoctlInoPathArgs>() == 56);
const _: () = assert!(mem::size_of::<BtrfsDataContainer>() == 16);

/// Open `path` as a directory and re-verify, on the resulting fd, that it is
/// still the subvol root the caller selected. `main.rs` picks the fast path by
/// `lstat`-ing the arg (`st_ino == 256 && st_dev == expect_dev`); an attacker
/// with write access to the parent could swap the path for a symlink in the
/// gap before this `open`. The privileged `TREE_SEARCH_V2`/`INO_PATHS` ioctls
/// are scoped to whatever subvol this fd lives in, so the post-open `fstat`
/// here re-binds the decision to the actually-opened object. A mismatch is
/// reported as `EINVAL` so `is_recoverable` routes the arg to the unprivileged
/// per-file walk instead of scanning a substituted subvol as root.
fn open_dir(path: &Path, expect_dev: u64) -> io::Result<OwnedFd> {
    let fd: OwnedFd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)?
        .into();
    let mut st: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.st_ino != BTRFS_FIRST_FREE_OBJECTID || st.st_dev as u64 != expect_dev {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(fd)
}

/// Resolve `inum` to one or more relative paths (relative to the subvol root
/// `fd` lives in). Returns empty when `INO_PATHS` reports no paths (subvol-root
/// inode 256, orphans). Returned slices borrow `scratch`.
pub fn ino_paths(fd: RawFd, inum: u64, scratch: &mut Vec<u8>) -> io::Result<Vec<&[u8]>> {
    let args_size = mem::size_of::<BtrfsIoctlInoPathArgs>();
    let mut fspath_size = FSPATH_BUF_BYTES;
    loop {
        // `resize` zero-fills any grown tail; the kernel overwrites the
        // container header and val[] on every call, so the prefix left over
        // from a prior retry iteration is irrelevant.
        scratch.resize(args_size + fspath_size, 0);
        unsafe {
            let args_ptr = scratch.as_mut_ptr() as *mut BtrfsIoctlInoPathArgs;
            let container_ptr = scratch.as_mut_ptr().add(args_size);
            ptr::write_unaligned(
                args_ptr,
                BtrfsIoctlInoPathArgs {
                    inum,
                    size: fspath_size as u64,
                    _reserved: [0; 4],
                    fspath: container_ptr as u64,
                },
            );
        }
        let r = unsafe { libc::ioctl(fd, BTRFS_IOC_INO_PATHS, scratch.as_mut_ptr()) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        let container = read_data_container(&scratch[args_size..])?;
        if container.bytes_missing == 0 && container.elem_missed == 0 {
            return parse_ino_path_buf(&container, &scratch[args_size..]);
        }
        fspath_size = grow_fspath_buffer(fspath_size, container.bytes_missing as usize)?;
    }
}

fn read_data_container(buf: &[u8]) -> io::Result<BtrfsDataContainer> {
    if buf.len() < mem::size_of::<BtrfsDataContainer>() {
        return Err(invalid_data("short INO_PATHS data container"));
    }
    Ok(unsafe { ptr::read_unaligned(buf.as_ptr() as *const BtrfsDataContainer) })
}

fn grow_fspath_buffer(current: usize, missing: usize) -> io::Result<usize> {
    if current >= MAX_FSPATH_BUF_BYTES {
        return Err(invalid_data("INO_PATHS result exceeds maximum path buffer"));
    }
    // Cover what the kernel said was missing plus a page of slack, but never
    // grow by less than 2x so a stream of small shortfalls can't degrade into
    // one ioctl per path. Clamp to the hard cap (current < cap guaranteed
    // above, so the result is always > current and the loop makes progress).
    let requested = current
        .checked_add(missing)
        .and_then(|v| v.checked_add(4096))
        .unwrap_or(MAX_FSPATH_BUF_BYTES);
    Ok(requested
        .max(current.saturating_mul(2))
        .min(MAX_FSPATH_BUF_BYTES))
}

fn parse_ino_path_buf<'a>(
    container: &BtrfsDataContainer,
    buf: &'a [u8],
) -> io::Result<Vec<&'a [u8]>> {
    use std::ffi::CStr;

    let container_size = mem::size_of::<BtrfsDataContainer>();
    let val_buf = &buf[container_size..];
    let offset_bytes = (container.elem_cnt as usize)
        .checked_mul(mem::size_of::<u64>())
        .ok_or_else(|| invalid_data("INO_PATHS element count overflow"))?;
    if offset_bytes > val_buf.len() {
        return Err(invalid_data("INO_PATHS element offsets exceed buffer"));
    }

    let mut out = Vec::with_capacity(container.elem_cnt as usize);
    for i in 0..container.elem_cnt as usize {
        let off64 = unsafe { ptr::read_unaligned((val_buf.as_ptr() as *const u64).add(i)) };
        if off64 >= val_buf.len() as u64 {
            return Err(invalid_data("INO_PATHS string offset exceeds buffer"));
        }
        let off = off64 as usize;
        if off < offset_bytes {
            return Err(invalid_data(
                "INO_PATHS string offset overlaps offset table",
            ));
        }
        let c = CStr::from_bytes_until_nul(&val_buf[off..])
            .map_err(|_| invalid_data("INO_PATHS string is not NUL terminated"))?;
        out.push(c.to_bytes());
    }
    Ok(out)
}

/// Stream every `INODE_ITEM` in the subvolume `root` lives in — the callback
/// gets `(fd, btrfs_flags, inum, scratch)`. INODE_ITEM keys have offset=0,
/// so the per-batch cursor advance is just `last_objectid + 1`. The caller
/// pairs this with [`ino_paths`] (reusing `scratch` as its path buffer) to
/// resolve only the inodes that pass the `--has` filter.
pub fn scan_flags<F>(root: &Path, expect_dev: u64, mut visit: F) -> io::Result<()>
where
    F: FnMut(RawFd, u64, u64, &mut Vec<u8>) -> io::Result<()>,
{
    let dirfd = open_dir(root, expect_dev)?;
    let raw_fd = dirfd.as_raw_fd();
    let mut buf = vec![0u8; mem::size_of::<BtrfsIoctlSearchKey>() + 8 + SEARCH_BUF_BYTES];
    let mut path_scratch: Vec<u8> = Vec::new();
    let mut key = BtrfsIoctlSearchKey {
        tree_id: 0,
        min_objectid: 0,
        max_objectid: u64::MAX,
        min_offset: 0,
        max_offset: u64::MAX,
        min_transid: 0,
        max_transid: u64::MAX,
        min_type: BTRFS_INODE_ITEM_KEY,
        max_type: BTRFS_INODE_ITEM_KEY,
        nr_items: SEARCH_NR_ITEMS,
        ..Default::default()
    };

    loop {
        key.nr_items = SEARCH_NR_ITEMS;
        unsafe {
            ptr::write_unaligned(buf.as_mut_ptr() as *mut BtrfsIoctlSearchKey, key);
            ptr::write_unaligned(
                buf.as_mut_ptr().add(mem::size_of::<BtrfsIoctlSearchKey>()) as *mut u64,
                SEARCH_BUF_BYTES as u64,
            );
        }
        let r = unsafe { libc::ioctl(raw_fd, BTRFS_IOC_TREE_SEARCH_V2, buf.as_mut_ptr()) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        // We asked for at most SEARCH_NR_ITEMS and sized `buf` for that, so a
        // larger `nr_items` would be a kernel bug. The per-item loop already
        // bounds-checks every read against `buf_end` (an inflated count can
        // only error, never overread); clamp so we iterate exactly the items
        // that fit instead of trusting the returned count.
        let returned = unsafe { ptr::read_unaligned(buf.as_ptr() as *const BtrfsIoctlSearchKey) }
            .nr_items
            .min(SEARCH_NR_ITEMS);
        if returned == 0 {
            break;
        }

        let data_off = mem::size_of::<BtrfsIoctlSearchKey>() + 8;
        let buf_end = data_off + SEARCH_BUF_BYTES;
        let mut p = data_off;
        let mut last_objectid: u64 = key.min_objectid;
        for _ in 0..returned {
            if p + mem::size_of::<BtrfsIoctlSearchHeader>() > buf_end {
                return Err(invalid_data("short TREE_SEARCH_V2 item header"));
            }
            let header = unsafe {
                ptr::read_unaligned(buf.as_ptr().add(p) as *const BtrfsIoctlSearchHeader)
            };
            let item_off = p + mem::size_of::<BtrfsIoctlSearchHeader>();
            let item_end = match item_off.checked_add(header.len as usize) {
                Some(v) if v <= buf_end => v,
                _ => return Err(invalid_data("TREE_SEARCH_V2 item exceeds buffer")),
            };
            if header.typ == BTRFS_INODE_ITEM_KEY
                && (header.len as usize) >= INODE_ITEM_FLAGS_OFF + 8
            {
                let flags = u64::from_le_bytes(
                    buf[item_off + INODE_ITEM_FLAGS_OFF..item_off + INODE_ITEM_FLAGS_OFF + 8]
                        .try_into()
                        .unwrap(),
                );
                visit(raw_fd, flags, header.objectid, &mut path_scratch)?;
            }
            last_objectid = header.objectid;
            p = item_end;
        }

        // Kernel returns fewer than SEARCH_NR_ITEMS when the response buffer
        // fills — NOT end-of-tree — so only stop when returned==0.
        match last_objectid.checked_add(1) {
            Some(v) => key.min_objectid = v,
            None => break,
        }
    }
    Ok(())
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    // _IOWR results per <linux/btrfs.h>.
    const TREE_SEARCH_V2_REF: libc::c_ulong = 0xC070_9411;
    const INO_PATHS_REF: libc::c_ulong = 0xC038_9423;

    #[test]
    fn ioc_rw_matches_kernel_macro() {
        assert_eq!(ioc_rw(0x94, 17, 112), TREE_SEARCH_V2_REF);
        assert_eq!(ioc_rw(0x94, 35, 56), INO_PATHS_REF);
    }

    #[test]
    fn ioctl_constants_match_kernel_header() {
        assert_eq!(BTRFS_IOC_TREE_SEARCH_V2, TREE_SEARCH_V2_REF);
        assert_eq!(BTRFS_IOC_INO_PATHS, INO_PATHS_REF);
    }

    #[test]
    fn flags_offset_within_inode_item() {
        assert_eq!(INODE_ITEM_FLAGS_OFF, 5 * 8 + 4 * 4 + 8);
    }

    fn ino_path_buf(offsets: &[u64], strings: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&(offsets.len() as u32).to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        for off in offsets {
            buf.extend_from_slice(&off.to_ne_bytes());
        }
        for s in strings {
            buf.extend_from_slice(s);
        }
        buf
    }

    fn parse(buf: &[u8]) -> io::Result<Vec<&[u8]>> {
        let container = read_data_container(buf)?;
        parse_ino_path_buf(&container, buf)
    }

    #[test]
    fn parses_ino_paths_buffer() {
        let buf = ino_path_buf(&[16, 22], &[b"first\0", b"second\0"]);
        let paths = parse(&buf).unwrap();
        assert_eq!(paths, vec![b"first".as_slice(), b"second".as_slice()]);
    }

    #[test]
    fn rejects_ino_paths_offset_outside_buffer() {
        let buf = ino_path_buf(&[99], &[b"first\0"]);
        let err = parse(&buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_ino_paths_offset_inside_offset_table() {
        let buf = ino_path_buf(&[0], &[b"first\0"]);
        let err = parse(&buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_ino_paths_without_nul_terminator() {
        let buf = ino_path_buf(&[8], &[b"first"]);
        let err = parse(&buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn grows_ino_paths_buffer_for_missing_bytes() {
        assert!(grow_fspath_buffer(4096, 8192).unwrap() > 4096);
    }
}
