// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Per-file lsattr-compat walker.
//
// Mirrors the upstream e2fsprogs `lsattr` semantics (misc/lsattr.c +
// lib/e2p/fgetflags.c, fgetversion.c, fgetproject.c) so output is byte-
// identical to system `lsattr` when given the same flags. Recursion order,
// dotfile filtering, dir headers, error messages, column widths and
// exit-code semantics all match. Used as the default scan path; the btrfs
// tree-search fast path is reserved for `--has` filters with CAP_SYS_ADMIN.
//
// Behavior summary:
//   * lstat each top-level arg; if directory and no `-d`, iterate; else
//     read attrs directly (mirrors `lsattr_args`).
//   * Per-entry in iterate: lstat, skip dotfiles unless `-a`, read attrs,
//     recurse into subdirs only when `-R` is set and entry is not "." or
//     ".." (mirrors `lsattr_dir_proc`).
//   * `-R` prints `\n<dir>:\n` before each recursed dir's contents and
//     `\n` after.
//   * `-v` prepends 10-char left-aligned generation; `-p` prepends 5-char
//     right-aligned project id; both = project then generation.
//   * Open with `O_RDONLY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW`. ELOOP/ENXIO →
//     EOPNOTSUPP. ENOTTY → EOPNOTSUPP. Reject non-regular/non-dir.
//   * Exit 1 only when a top-level arg failed (lstat, opendir on dir arg,
//     or per-file ioctl on a non-dir arg). Errors during recursion print
//     to stderr but do not raise the exit code — same as upstream lsattr.

use std::ffi::{CStr, CString};
use std::fmt;
use std::io::{self, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{c_char, c_int, c_long, c_ulong};

use crate::format;

pub struct Opts {
    pub recursive: bool,
    pub all: bool,
    pub dirs_opt: bool,
    pub long: bool,
    pub paths_only: bool,
    pub project: bool,
    pub generation: bool,
    /// 0 = no filter; otherwise emit only entries whose flags & mask == mask.
    pub has_mask: u32,
}

pub struct Walker<'a, W: Write> {
    pub opts: &'a Opts,
    pub w: &'a mut W,
    /// True iff a TOP-LEVEL arg failed. Mirrors lsattr's main(): per-entry
    /// failures during recursion are printed but do not flip the exit code.
    pub had_err: bool,
    /// Set after stdout closes. Callers use this to stop traversal without
    /// treating a normal pipeline close as a scan failure.
    pub pipe_broken: bool,
}

// _IOR(type, nr, size). lsattr's ioctls are all _IOR.
const fn ioc_r(ty: u32, nr: u32, size: u32) -> c_ulong {
    ((2u32 << 30) | (size << 16) | (ty << 8) | nr) as c_ulong
}

// Match e2fsprogs: `_IOR('f', 1, long)`, `_IOR('v', 1, long)`. `long` is
// arch-dependent; the kernel only writes the low 4 bytes, but the IOC
// number encodes the full size.
const FS_IOC_GETFLAGS: c_ulong = ioc_r(b'f' as u32, 1, mem::size_of::<c_long>() as u32);
const FS_IOC_GETVERSION: c_ulong = ioc_r(b'v' as u32, 1, mem::size_of::<c_long>() as u32);

#[repr(C)]
struct Fsxattr {
    fsx_xflags: u32,
    fsx_extsize: u32,
    fsx_nextents: u32,
    fsx_projid: u32,
    fsx_cowextsize: u32,
    fsx_pad: [u8; 8],
}
const _: () = assert!(mem::size_of::<Fsxattr>() == 28);
const FS_IOC_FSGETXATTR: c_ulong = ioc_r(b'X' as u32, 31, mem::size_of::<Fsxattr>() as u32);

const OPEN_FLAGS: c_int = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW;

impl<'a, W: Write> Walker<'a, W> {
    /// Top-level arg dispatcher. Mirrors `lsattr_args` in misc/lsattr.c.
    pub fn list_arg(&mut self, path: &[u8]) {
        if self.pipe_broken {
            return;
        }
        let cpath = match CString::new(path) {
            Ok(c) => c,
            Err(_) => {
                report(path, "while trying to stat", libc::EINVAL);
                self.had_err = true;
                return;
            }
        };
        let mut st: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::lstat(cpath.as_ptr(), &mut st) } != 0 {
            report(path, "while trying to stat", errno());
            self.had_err = true;
            return;
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        if is_dir && !self.opts.dirs_opt {
            // opendir failure at top level → exit 1 (lsattr_args returns -1).
            // Same opendir failure during recursion is silent: caller below
            // throws away iterate_dir's return value.
            if !self.iterate_dir(path) {
                self.had_err = true;
            }
        } else if !self.list_attributes(path) {
            self.had_err = true;
        }
    }

    /// Read flags (and optional generation/project) and emit one line.
    /// Thin wrapper over the shared [`list_one`] so the walk path and the
    /// btrfs fast path (nested subvol-root entries) emit byte-identically.
    /// Returns false on error (already printed). Note: lsattr propagates
    /// list_attributes errors to retval ONLY when called from lsattr_args
    /// (top-level non-dir / -d arg). When called from lsattr_dir_proc the
    /// caller throws away the return; iterate_dir replicates that by
    /// ignoring our return.
    fn list_attributes(&mut self, path: &[u8]) -> bool {
        if self.pipe_broken {
            return true;
        }
        match list_one(path, self.opts, self.w) {
            Ok(ok) => ok,
            // Closed output pipe: mirror the old behaviour (treat as "ok" so
            // the top level doesn't flip the exit code) but stop the walk.
            Err(_) => {
                self.pipe_broken = true;
                true
            }
        }
    }

    /// One level of dir iteration with optional recursion. Mirrors
    /// `iterate_on_dir` + `lsattr_dir_proc`. Returns false only on opendir
    /// failure; per-entry failures are printed but do not affect the
    /// return (matching lsattr's iterate_on_dir, which always returns 0
    /// after a successful opendir even when entries fail). Whether opendir
    /// failure is fatal is the caller's choice — top level honors it,
    /// recursive call sites ignore it.
    fn iterate_dir(&mut self, dir: &[u8]) -> bool {
        if self.pipe_broken {
            return true;
        }
        let cdir = match CString::new(dir) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let dirp = unsafe { libc::opendir(cdir.as_ptr()) };
        if dirp.is_null() {
            return false;
        }
        loop {
            if self.pipe_broken {
                break;
            }
            // readdir() returns NULL for both end-of-dir and error; the only
            // way to tell them apart is errno, which it leaves untouched on a
            // clean end. Clear it first, then a non-zero errno means the
            // listing was truncated by a real error — surface it instead of
            // silently presenting a short directory as complete.
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                let e = errno();
                if e != 0 {
                    // Per-entry style: printed, no exit-code impact (matches
                    // lsattr's iterate_on_dir, which also just stops here).
                    report(dir, "While reading directory", e);
                }
                break;
            }
            let name =
                unsafe { CStr::from_ptr((*entry).d_name.as_ptr() as *const c_char) }.to_bytes();

            let mut child: Vec<u8> = Vec::with_capacity(dir.len() + 1 + name.len());
            child.extend_from_slice(dir);
            // Match lsattr.c:157-160 — only insert '/' when not already present.
            if !dir.ends_with(b"/") {
                child.push(b'/');
            }
            child.extend_from_slice(name);

            let cchild = match CString::new(child.as_slice()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut st: libc::stat = unsafe { mem::zeroed() };
            if unsafe { libc::lstat(cchild.as_ptr(), &mut st) } != 0 {
                // lsattr uses perror(path) — `path: errno_text`. No retval impact.
                warn(format_args!("{}: {}", lossy(&child), Strerror(errno())));
                continue;
            }

            // Dotfile filter — applies to "." and ".." too. Without -a these
            // are skipped entirely (no list, no recurse).
            if name.first().copied() == Some(b'.') && !self.opts.all {
                continue;
            }

            // Per-entry list_attributes: lsattr_dir_proc throws away return.
            let _ = self.list_attributes(&child);

            if self.opts.recursive
                && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
                && name != b"."
                && name != b".."
            {
                // Skip the lsattr-style `\n<dir>:\n` section headers when
                // emitting raw paths or filtering with --has — both modes
                // are pipe targets where structured headers are noise.
                let headers = !self.opts.paths_only && self.opts.has_mask == 0;
                if headers && self.write_dir_header(&child).is_err() {
                    break;
                }
                let _ = self.iterate_dir(&child);
                if headers {
                    let _ = self.write_header_part(b"\n");
                }
            }
        }
        unsafe {
            libc::closedir(dirp);
        }
        true
    }

    /// Write the lsattr-style `\n<dir>:\n` section header. On a closed pipe,
    /// sets `pipe_broken` and returns Err so the caller stops the walk.
    fn write_dir_header(&mut self, dir: &[u8]) -> io::Result<()> {
        self.write_header_part(b"\n")?;
        self.write_header_part(dir)?;
        self.write_header_part(b":\n")
    }

    fn write_header_part(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self.w.write_all(bytes) {
            Ok(()) => Ok(()),
            Err(e) if is_broken_pipe(&e) => {
                self.pipe_broken = true;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }
}

/// Shared single-entry reader: open `path`, read `FS_IOC_GETFLAGS` (and
/// optional project/generation), apply `opts.has_mask`, emit one line.
/// Mirrors `fgetflags` + `fgetversion` + `fgetproject` exactly so the walk
/// path and the btrfs fast path's nested subvol-root entries are byte-
/// identical. `Ok(true)` = emitted or filtered out (no error); `Ok(false)` =
/// an error was reported to stderr (top-level callers raise the exit code);
/// `Err(BrokenPipe)` = the output pipe closed and the caller must stop.
pub(crate) fn list_one<W: Write>(path: &[u8], opts: &Opts, w: &mut W) -> io::Result<bool> {
    let cpath = match CString::new(path) {
        Ok(c) => c,
        Err(_) => {
            report_flags(path, libc::EINVAL);
            return Ok(false);
        }
    };
    let fd = unsafe { libc::open(cpath.as_ptr(), OPEN_FLAGS) };
    if fd < 0 {
        // fgetflags.c maps these to EOPNOTSUPP on open().
        let raw = errno();
        let mapped = if raw == libc::ELOOP || raw == libc::ENXIO {
            libc::EOPNOTSUPP
        } else {
            raw
        };
        report_flags(path, mapped);
        return Ok(false);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // fgetflags.c rejects non-regular/non-dir before the ioctl.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } == 0 {
        let m = st.st_mode & libc::S_IFMT;
        if m != libc::S_IFREG && m != libc::S_IFDIR {
            report_flags(path, libc::EOPNOTSUPP);
            return Ok(false);
        }
    }

    let mut raw_flags: c_long = 0;
    if unsafe { libc::ioctl(owned.as_raw_fd(), FS_IOC_GETFLAGS, &mut raw_flags) } != 0 {
        let raw = errno();
        let mapped = if raw == libc::ENOTTY {
            libc::EOPNOTSUPP
        } else {
            raw
        };
        report_flags(path, mapped);
        return Ok(false);
    }
    // Kernel writes 32 bits via put_user(int*); mask defensively.
    let flags = (raw_flags as u64 & 0xFFFF_FFFF) as u32;

    if opts.has_mask != 0 && (flags & opts.has_mask) != opts.has_mask {
        return Ok(true);
    }

    let project = if opts.project {
        let mut x: Fsxattr = unsafe { mem::zeroed() };
        if unsafe { libc::ioctl(owned.as_raw_fd(), FS_IOC_FSGETXATTR, &mut x) } != 0 {
            report(path, "While reading project on", errno());
            return Ok(false);
        }
        Some(x.fsx_projid)
    } else {
        None
    };

    let generation = if opts.generation {
        let mut g: c_long = 0;
        if unsafe { libc::ioctl(owned.as_raw_fd(), FS_IOC_GETVERSION, &mut g) } != 0 {
            report(path, "While reading version on", errno());
            return Ok(false);
        }
        Some(g as u64 & 0xFFFF_FFFF)
    } else {
        None
    };

    match format::write_line(
        w,
        flags,
        path,
        opts.long,
        opts.paths_only,
        project,
        generation,
    ) {
        Ok(()) => Ok(true),
        Err(e) if is_broken_pipe(&e) => Err(e),
        Err(e) => {
            warn(format_args!("btrfs-lsattr: write: {}", e));
            Ok(false)
        }
    }
}

/// True for a closed-pipe write error — a normal pipeline teardown, not a
/// scan failure. Single home shared by the walk and fast paths.
pub(crate) fn is_broken_pipe(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::BrokenPipe
}

/// Best-effort stderr write. Unlike `eprintln!` this never panics when stderr
/// itself is a closed pipe (e.g. `… 2>&1 | head`) — diagnostics are advisory,
/// losing one must not abort an in-progress scan.
pub(crate) fn warn(args: fmt::Arguments<'_>) {
    let mut err = io::stderr();
    let _ = err.write_fmt(args);
    let _ = err.write_all(b"\n");
}

pub(crate) fn report_flags(path: &[u8], errno_val: i32) {
    report(path, "While reading flags on", errno_val);
}

/// e2fsprogs `com_err(prog, errno, "fmt", args)` prints
/// `prog: errno_text fmt_with_args` — note the SPACE (not colon)
/// between errno text and format string. Match exactly.
pub(crate) fn report(path: &[u8], what: &str, errno_val: i32) {
    warn(format_args!(
        "btrfs-lsattr: {} {} {}",
        Strerror(errno_val),
        what,
        lossy(path)
    ));
}

pub(crate) fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn lossy(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

/// `strerror(errno)` formatter — `io::Error`'s Display appends "(os error N)"
/// which lsattr/com_err does not. Use this whenever output must match lsattr.
struct Strerror(i32);
impl fmt::Display for Strerror {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = unsafe { libc::strerror(self.0) };
        if p.is_null() {
            return write!(f, "Unknown error {}", self.0);
        }
        let cs = unsafe { CStr::from_ptr(p) };
        f.write_str(&cs.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn ioc_numbers_match_kernel_macros() {
        // _IOR('f', 1, long), _IOR('v', 1, long), _IOR('X', 31, fsxattr)
        // on 64-bit (sizeof(long)=8, sizeof(fsxattr)=28).
        assert_eq!(FS_IOC_GETFLAGS, 0x8008_6601);
        assert_eq!(FS_IOC_GETVERSION, 0x8008_7601);
        // _IOR('X', 31, fsxattr) — nr=31 dec = 0x1f.
        assert_eq!(FS_IOC_FSGETXATTR, 0x801c_581f);
    }

    fn base_opts() -> Opts {
        Opts {
            recursive: true,
            all: true,
            dirs_opt: false,
            long: false,
            paths_only: false,
            project: false,
            generation: false,
            has_mask: 0,
        }
    }

    fn temp_file() -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "btrfs-lsattr-test-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn list_one_smoke_real_fd() {
        // Smoke-tests the real open/fstat/ioctl/write_line glue. Asserts
        // only fs-independent invariants: the *value* of the attr field
        // depends on the filesystem temp_dir() lands on (ext4 sets the
        // extent bit on every new inode, btrfs/tmpfs do not), so the
        // exact-formatting contract is pinned hermetically in
        // format::tests::short_no_flags instead.
        let p = temp_file();
        let bytes = p.as_os_str().as_bytes();
        let mut out: Vec<u8> = Vec::new();
        let r = list_one(bytes, &base_opts(), &mut out);
        let _ = std::fs::remove_file(&p);
        assert!(matches!(r, Ok(true)));

        // Byte-layout contract: 22-char attr field + space + path + LF.
        assert_eq!(out.len(), 22 + 1 + bytes.len() + 1);
        let mut tail = vec![b' '];
        tail.extend_from_slice(bytes);
        tail.push(b'\n');
        assert_eq!(&out[22..], &tail[..]);

        // The attr field is well-formed: every slot is '-' or a letter
        // from the canonical 22-letter table.
        let allowed: Vec<u8> = crate::flags::LETTERS
            .iter()
            .map(|l| l.letter as u8)
            .collect();
        for &c in &out[..22] {
            assert!(
                c == b'-' || allowed.contains(&c),
                "unexpected attr char {c:#x}"
            );
        }
    }

    #[test]
    fn list_one_filter_miss_emits_nothing() {
        let p = temp_file();
        let mut opts = base_opts();
        opts.has_mask = crate::flags::FS_IMMUTABLE_FL;
        let mut out: Vec<u8> = Vec::new();
        let r = list_one(p.as_os_str().as_bytes(), &opts, &mut out);
        let _ = std::fs::remove_file(&p);
        // Filtered out: handled (Ok(true)) but produces no line.
        assert!(matches!(r, Ok(true)));
        assert!(out.is_empty());
    }

    #[test]
    fn list_one_reports_missing_path() {
        let mut out: Vec<u8> = Vec::new();
        // ENOENT is a real error, not a broken pipe: Ok(false), no output.
        let r = list_one(b"/nonexistent/btrfs-lsattr/xyz", &base_opts(), &mut out);
        assert!(matches!(r, Ok(false)));
        assert!(out.is_empty());
    }
}
