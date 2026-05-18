// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// btrfs-lsattr: drop-in replacement for e2fsprogs `lsattr` with btrfs-aware
// fast paths.
//
// Two execution paths:
//   * Per-file walk (default): mirrors `lsattr` exactly via FS_IOC_GETFLAGS
//     on each opened path. Works on any FS, no privileges needed. See
//     `walk.rs`. Honors `-R -a -d -l -v -p`.
//   * Btrfs tree-search fast path (`--has` filter, with CAP_SYS_ADMIN):
//     per subvol = one TREE_SEARCH_V2 sweep + per-match INO_PATHS, then a
//     directory walk to discover nested subvol roots (st_ino==256 with a
//     different st_dev) and recurse. Without nested-subvol recursion the
//     fast path would miss every file under a child subvol — visible as a
//     divergence between `--has` runs with and without sudo. Falls back to
//     the recursive walker on EPERM/ENOTTY/EINVAL.

mod btrfs;
mod flags;
mod format;
mod walk;

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::io::{self, BufWriter, Write};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use crate::flags::{
    btrfs_to_fs, letters_to_mask, BTRFS_FIRST_FREE_OBJECTID, BTRFS_SUPPORTED_FS_MASK,
};

#[derive(Parser, Debug)]
#[command(
    name = "btrfs-lsattr",
    about = "lsattr drop-in for btrfs (with optional tree-search fast path for --has)",
    long_about = None,
    disable_version_flag = true,
    override_usage = "btrfs-lsattr [-RVadlvp] [--has LETTERS] [--paths-only] [files...]",
)]
struct Cli {
    /// Recursively list attributes of directories and their contents.
    #[arg(short = 'R')]
    recursive: bool,

    /// Print program version to stderr and continue.
    #[arg(short = 'V')]
    print_version: bool,

    /// List all files in directories, including those starting with `.`.
    #[arg(short = 'a')]
    all: bool,

    /// List directories like other files, rather than listing their contents.
    #[arg(short = 'd')]
    dirs_opt: bool,

    /// Long names (Comma_Joined) instead of letter field.
    #[arg(short = 'l')]
    long: bool,

    /// List the file's version (generation) number.
    #[arg(short = 'v')]
    generation: bool,

    /// List the file's project number.
    #[arg(short = 'p')]
    project: bool,

    /// Filter to inodes that have all listed FS_*_FL letters set. Implies a
    /// recursive, dotfile-inclusive scan and ignores -d (the btrfs fast path
    /// sees every inode regardless, so the per-file fallback must match).
    #[arg(long = "has", value_name = "LETTERS")]
    has: Option<String>,

    /// Emit just absolute paths, one per line, no attr field.
    #[arg(long = "paths-only")]
    paths_only: bool,

    /// Files to inspect (default: current directory).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.print_version {
        eprintln!("btrfs-lsattr {}", env!("CARGO_PKG_VERSION"));
    }

    if cli.long && cli.paths_only {
        eprintln!("btrfs-lsattr: -l and --paths-only are mutually exclusive");
        return ExitCode::from(2);
    }
    let has_mask = match cli.has.as_deref() {
        None => 0,
        Some("") => {
            eprintln!("btrfs-lsattr: --has: empty filter");
            return ExitCode::from(2);
        }
        Some(s) => match letters_to_mask(s) {
            Ok(m) => m,
            Err(c) => {
                eprintln!("btrfs-lsattr: --has: unknown letter '{}'", c);
                return ExitCode::from(2);
            }
        },
    };

    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    let mut had_err = false;
    let mut pipe_broken = false;

    let default_path;
    let paths: Vec<&Path> = if cli.paths.is_empty() {
        default_path = PathBuf::from(".");
        vec![&default_path]
    } else {
        cli.paths.iter().map(|p| p.as_path()).collect()
    };

    if has_mask != 0 {
        let use_fast_path = can_use_fast_has_path(&cli, has_mask);
        // Try btrfs tree-search per arg; on EPERM (no CAP_SYS_ADMIN) or any
        // other ioctl-startup error, fall back to a recursive per-file walk.
        for path in &paths {
            if pipe_broken {
                break;
            }
            if !use_fast_path {
                pipe_broken |= walk_filtered(path, &cli, has_mask, &mut w, &mut had_err);
                continue;
            }
            // TREE_SEARCH_V2 is scoped to the whole subvol the fd lives in, and
            // INO_PATHS is subvol-root-relative — both only line up when the
            // arg IS a subvol root. For a plain subdir arg the fast path would
            // sweep the entire containing subvol (unbounded) and emit wrong
            // paths, so route those to the bounded per-file walk instead.
            // `subvol_root_dev` also hands back the arg's st_dev so the scan
            // doesn't have to lstat it a second time.
            match subvol_root_dev(path) {
                None => pipe_broken |= walk_filtered(path, &cli, has_mask, &mut w, &mut had_err),
                Some(dev) => {
                    let mut emitted = false;
                    let mut sub_pipe = false;
                    let res = scan_filtered(
                        path,
                        &cli,
                        has_mask,
                        &mut w,
                        dev,
                        &mut emitted,
                        &mut had_err,
                        &mut sub_pipe,
                    );
                    pipe_broken |= sub_pipe;
                    match res {
                        Ok(()) => {}
                        Err(e) if walk::is_broken_pipe(&e) => {
                            pipe_broken = true;
                        }
                        Err(e) if is_recoverable(&e) && !emitted => {
                            pipe_broken |=
                                walk_filtered(path, &cli, has_mask, &mut w, &mut had_err);
                        }
                        Err(e) => {
                            // Match the walk path's com_err-style error line so
                            // `--has`-only failures stay drop-in compatible.
                            match e.raw_os_error() {
                                Some(n) => walk::report(
                                    path.as_os_str().as_bytes(),
                                    "While reading flags on",
                                    n,
                                ),
                                None => walk::warn(format_args!(
                                    "btrfs-lsattr: {}: {}",
                                    path.display(),
                                    e
                                )),
                            }
                            had_err = true;
                        }
                    }
                }
            }
        }
    } else {
        let opts = walk::Opts {
            recursive: cli.recursive,
            all: cli.all,
            dirs_opt: cli.dirs_opt,
            long: cli.long,
            paths_only: cli.paths_only,
            project: cli.project,
            generation: cli.generation,
            has_mask: 0,
        };
        for path in &paths {
            if pipe_broken {
                break;
            }
            pipe_broken |= run_walk(path.as_os_str().as_bytes(), &opts, &mut w, &mut had_err);
        }
    }

    if !pipe_broken {
        if let Err(e) = w.flush() {
            if walk::is_broken_pipe(&e) {
                pipe_broken = true;
            } else {
                eprintln!("btrfs-lsattr: flush: {}", e);
                had_err = true;
            }
        }
    }

    if had_err && !pipe_broken {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// True when `--has` can use the btrfs tree-search fast path: the filter only
/// touches bits btrfs represents in INODE_ITEM, and no `-p`/`-v` column is
/// requested (the fast path can't produce project/generation). Only called
/// with `has_mask != 0`, so `cli.has` is necessarily `Some`.
fn can_use_fast_has_path(cli: &Cli, has_mask: u32) -> bool {
    !cli.project && !cli.generation && (has_mask & !BTRFS_SUPPORTED_FS_MASK) == 0
}

/// Errors that should trigger fallback from tree-search to per-file walk.
/// EPERM = no CAP_SYS_ADMIN. ENOTTY = not a btrfs FS. EINVAL = open fd
/// isn't a subvol root. Others (e.g. ENOENT) propagate as fatal arg errors.
fn is_recoverable(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EPERM) | Some(libc::ENOTTY) | Some(libc::EINVAL)
    )
}

/// Threaded through the fast-path recursion so per-call signatures stay flat.
/// `visited_subvols`/`visited_dirs`/`emitted`/`w` are reborrowed at each level;
/// `cli`/`has_mask` are the invariant scan parameters.
struct ScanCtx<'a, W: Write> {
    cli: &'a Cli,
    has_mask: u32,
    visited_subvols: &'a mut HashSet<u64>,
    visited_dirs: &'a mut HashSet<(libc::dev_t, libc::ino_t)>,
    emitted: &'a mut bool,
    /// Raised when a nested subvol's tree-search failed and its subtree was
    /// re-scanned via the per-file walk (or that walk hit a top-level error).
    /// Surfaces incompleteness through the process exit code.
    had_err: &'a mut bool,
    /// Set once the output pipe closes anywhere in the recursion so every
    /// level unwinds instead of grinding on with failing writes.
    pipe_broken: &'a mut bool,
    w: &'a mut W,
}

/// Btrfs fast path for `--has`: scan the arg's subvol via TREE_SEARCH_V2,
/// then walk its directories to find nested subvol roots and recurse.
#[allow(clippy::too_many_arguments)]
fn scan_filtered<W: Write>(
    root: &Path,
    cli: &Cli,
    has_mask: u32,
    w: &mut W,
    dev: u64,
    emitted: &mut bool,
    had_err: &mut bool,
    pipe_broken: &mut bool,
) -> io::Result<()> {
    let arg_bytes = root.as_os_str().as_bytes();
    let prefix_owned: Vec<u8> = trim_trailing_slashes(arg_bytes).to_vec();
    let mut visited_subvols: HashSet<u64> = HashSet::new();
    let mut visited_dirs: HashSet<(libc::dev_t, libc::ino_t)> = HashSet::new();
    let mut ctx = ScanCtx {
        cli,
        has_mask,
        visited_subvols: &mut visited_subvols,
        visited_dirs: &mut visited_dirs,
        emitted,
        had_err,
        pipe_broken,
        w,
    };
    scan_subvol(&mut ctx, root, &prefix_owned, dev)
}

/// Scan one subvol: tree-search its inode B-tree, then descend its dir tree
/// to discover and recurse into nested subvol mountpoints. `dev` is the
/// subvol's st_dev (already known by every caller — fed in to avoid a
/// redundant lstat); it guards against snapshot loops via `visited_subvols`.
fn scan_subvol<W: Write>(
    ctx: &mut ScanCtx<'_, W>,
    subvol_path: &Path,
    abs_prefix: &[u8],
    dev: u64,
) -> io::Result<()> {
    if !ctx.visited_subvols.insert(dev) {
        return Ok(());
    }
    sweep_subvol(ctx, subvol_path, abs_prefix, dev)?;

    let mut rel_buf: Vec<u8> = Vec::new();
    discover_subvols(ctx, subvol_path, abs_prefix, dev, &mut rel_buf, None);
    Ok(())
}

/// One TREE_SEARCH_V2 sweep over the subvol's INODE_ITEMs: translate flags,
/// apply `--has`, resolve surviving inodes to paths, emit. Split out of
/// `scan_subvol` so the borrow of the writer (via `ctx`) ends when this
/// returns, before `discover_subvols` reborrows the context.
fn sweep_subvol<W: Write>(
    ctx: &mut ScanCtx<'_, W>,
    subvol_path: &Path,
    abs_prefix: &[u8],
    dev: u64,
) -> io::Result<()> {
    let cli = ctx.cli;
    let has_mask = ctx.has_mask;
    let w = &mut *ctx.w;
    let emitted = &mut *ctx.emitted;
    let mut abs: Vec<u8> = Vec::new();
    btrfs::scan_flags(subvol_path, dev, |fd, btrfs_flags, inum, scratch| {
        let fs_flags = btrfs_to_fs(btrfs_flags);
        if (fs_flags & has_mask) != has_mask {
            return Ok(());
        }
        if inum == BTRFS_FIRST_FREE_OBJECTID {
            return Ok(());
        }
        let paths = match btrfs::ino_paths(fd, inum, scratch) {
            Ok(p) => p,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(e) => return Err(e),
        };
        let take = if cli.paths_only { 1 } else { paths.len() };
        for &rel in paths.iter().take(take) {
            if rel.is_empty() {
                continue;
            }
            abs.clear();
            abs.extend_from_slice(abs_prefix);
            abs.push(b'/');
            abs.extend_from_slice(rel);
            format::write_line(w, fs_flags, &abs, cli.long, cli.paths_only, None, None)?;
            *emitted = true;
        }
        Ok(())
    })
}

/// Walk dirs under `base` (currently at `base + rel_buf`) looking for nested
/// subvol roots. A subvol root is a directory with `st_ino == 256` AND a
/// different `st_dev` from the parent subvol. For each found, recurse via
/// `scan_subvol` with a fresh prefix; for plain dirs, recurse to keep
/// looking. A failure that prevents discovering nested subvols (bad path,
/// `opendir`/`readdir` error) raises `ctx.had_err` because it can hide files
/// under an unvisited child subvol — the scan would otherwise look complete.
fn discover_subvols<W: Write>(
    ctx: &mut ScanCtx<'_, W>,
    base: &Path,
    base_abs_prefix: &[u8],
    base_dev: u64,
    rel_buf: &mut Vec<u8>,
    // `(st_dev, st_ino)` of this dir when the caller already lstat'd it
    // (the recursive plain-dir descent); `None` only at the subvol root,
    // where it is lstat'd here.
    known_ids: Option<(libc::dev_t, libc::ino_t)>,
) {
    if *ctx.pipe_broken {
        return;
    }
    let dir_path = compose_path(base, rel_buf);
    let cdir = match CString::new(dir_path.as_slice()) {
        Ok(c) => c,
        Err(_) => {
            walk::warn(format_args!(
                "btrfs-lsattr: {}: invalid path",
                String::from_utf8_lossy(&dir_path)
            ));
            *ctx.had_err = true;
            return;
        }
    };
    let dirp = unsafe { libc::opendir(cdir.as_ptr()) };
    if dirp.is_null() {
        walk::report(&dir_path, "While opening directory", walk::errno());
        *ctx.had_err = true;
        return;
    }
    let ids = match known_ids {
        Some(ids) => Some(ids),
        None => lstat_path(&dir_path).ok().map(|st| (st.st_dev, st.st_ino)),
    };
    if let Some(ids) = ids {
        if !ctx.visited_dirs.insert(ids) {
            unsafe {
                libc::closedir(dirp);
            }
            return;
        }
    }
    let mut child_path: Vec<u8> = Vec::with_capacity(dir_path.len() + 64);
    loop {
        if *ctx.pipe_broken {
            break;
        }
        // NULL is end-of-dir OR error; disambiguate via errno (cleared first).
        // A real readdir error means an unvisited tail that could hide a
        // nested subvol, so flag incompleteness.
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            let er = walk::errno();
            if er != 0 {
                walk::report(&dir_path, "While reading directory", er);
                *ctx.had_err = true;
            }
            break;
        }
        let e = unsafe { &*entry };
        let name = unsafe { CStr::from_ptr(e.d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        // d_type can be DT_UNKNOWN on some FSes — fall through to lstat in
        // that case, which is the authoritative check anyway.
        if e.d_type != libc::DT_DIR && e.d_type != libc::DT_UNKNOWN {
            continue;
        }

        child_path.clear();
        child_path.extend_from_slice(&dir_path);
        if !child_path.ends_with(b"/") {
            child_path.push(b'/');
        }
        child_path.extend_from_slice(name);

        let st = match lstat_path(&child_path) {
            Ok(s) if (s.st_mode & libc::S_IFMT) == libc::S_IFDIR => s,
            _ => continue,
        };

        let saved = rel_buf.len();
        if !rel_buf.is_empty() {
            rel_buf.push(b'/');
        }
        rel_buf.extend_from_slice(name);

        if st.st_ino == BTRFS_FIRST_FREE_OBJECTID && (st.st_dev as u64) != base_dev {
            let mut child_abs_prefix: Vec<u8> =
                Vec::with_capacity(base_abs_prefix.len() + 1 + rel_buf.len());
            child_abs_prefix.extend_from_slice(base_abs_prefix);
            child_abs_prefix.push(b'/');
            child_abs_prefix.extend_from_slice(rel_buf);
            let child_subvol_path = Path::new(std::ffi::OsStr::from_bytes(&child_path));

            // F2: emit the nested subvol-root directory entry itself. The
            // per-file walk lists it as an ordinary dirent of the parent, but
            // `sweep_subvol` skips inode 256 in every subvol, so without this
            // `--has` output would differ with vs. without CAP_SYS_ADMIN.
            // `list_one` reuses the exact walk-path emit so it's byte-identical.
            let opts = filtered_walk_opts(ctx.cli, ctx.has_mask);
            match walk::list_one(&child_path, &opts, ctx.w) {
                Ok(_) => {}
                Err(_) => *ctx.pipe_broken = true,
            }

            if !*ctx.pipe_broken {
                match scan_subvol(ctx, child_subvol_path, &child_abs_prefix, st.st_dev as u64) {
                    Ok(()) => {}
                    Err(err) if walk::is_broken_pipe(&err) => *ctx.pipe_broken = true,
                    Err(err) => {
                        // Keep results complete: a child subvol we can't
                        // tree-search (EPERM mid-tree, ioctl/IO error) is
                        // re-scanned with the per-file walk instead of being
                        // silently dropped. `had_err` is raised by the walk
                        // on any top-level failure of that subtree.
                        walk::warn(format_args!(
                            "btrfs-lsattr: {}: tree-search failed ({}); \
                             falling back to per-file walk",
                            String::from_utf8_lossy(&child_path),
                            err
                        ));
                        if walk_filtered(
                            child_subvol_path,
                            ctx.cli,
                            ctx.has_mask,
                            ctx.w,
                            ctx.had_err,
                        ) {
                            *ctx.pipe_broken = true;
                        }
                    }
                }
            }
        } else {
            discover_subvols(
                ctx,
                base,
                base_abs_prefix,
                base_dev,
                rel_buf,
                Some((st.st_dev, st.st_ino)),
            );
        }
        rel_buf.truncate(saved);
        if *ctx.pipe_broken {
            break;
        }
    }
    unsafe {
        libc::closedir(dirp);
    }
}

/// `base + ('/' if needed) + rel`. Used wherever the walker composes a
/// filesystem path from a Path arg and a byte-slice tail.
fn compose_path(base: &Path, rel: &[u8]) -> Vec<u8> {
    let mut p = base.as_os_str().as_bytes().to_vec();
    if !rel.is_empty() {
        if !p.ends_with(b"/") {
            p.push(b'/');
        }
        p.extend_from_slice(rel);
    }
    p
}

/// `lstat(2)` a raw path into a fully-zeroed `stat`. The crate handles paths
/// as bytes, so this is the single place the CString round-trip + zeroed-stat
/// + errno scaffolding lives for the fast path.
fn lstat_path(path: &[u8]) -> io::Result<libc::stat> {
    let cpath = CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut st: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::lstat(cpath.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// `Some(st_dev)` iff `path` is a btrfs subvol root: a directory with
/// `st_ino == BTRFS_FIRST_FREE_OBJECTID` (256) — the same heuristic
/// `discover_subvols` uses. Only such args are safe for the tree-search fast
/// path. `None` on lstat failure or non-subvol-root; the per-file walk then
/// handles the arg (and surfaces any error consistently). The returned dev is
/// reused by the scan so it need not lstat the arg again.
fn subvol_root_dev(path: &Path) -> Option<u64> {
    let st = lstat_path(path.as_os_str().as_bytes()).ok()?;
    if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_ino == BTRFS_FIRST_FREE_OBJECTID {
        Some(st.st_dev as u64)
    } else {
        None
    }
}

/// Strip trailing `/`; bare `/` → `""` (caller always pastes a `/` before rel).
fn trim_trailing_slashes(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    &b[..end]
}

/// `walk::Opts` for the `--has` per-file path: forced recursive + dotfiles so
/// it sees the same all-inodes view as the tree-search fast path. Single home
/// so the fallback walk and the fast path's nested subvol-root emit (F2) stay
/// in lockstep.
fn filtered_walk_opts(cli: &Cli, has_mask: u32) -> walk::Opts {
    walk::Opts {
        recursive: true,
        all: true,
        dirs_opt: false,
        long: cli.long,
        paths_only: cli.paths_only,
        project: cli.project,
        generation: cli.generation,
        has_mask,
    }
}

/// Per-file `--has` walker: full recursive scan with filter applied.
/// Always recursive + dotfiles included so behavior matches the
/// tree-search fast path (which sees every inode regardless).
fn walk_filtered<W: Write>(
    path: &Path,
    cli: &Cli,
    has_mask: u32,
    w: &mut W,
    had_err: &mut bool,
) -> bool {
    let opts = filtered_walk_opts(cli, has_mask);
    run_walk(path.as_os_str().as_bytes(), &opts, w, had_err)
}

/// Run the per-file walker over one arg, OR-ing a top-level failure into
/// `had_err`. Single home for the `Walker` construction both walk paths share.
fn run_walk<W: Write>(path: &[u8], opts: &walk::Opts, w: &mut W, had_err: &mut bool) -> bool {
    let mut walker = walk::Walker {
        opts,
        w,
        had_err: false,
        pipe_broken: false,
    };
    walker.list_arg(path);
    *had_err |= walker.had_err;
    walker.pipe_broken
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_for_has(project: bool, generation: bool) -> Cli {
        Cli {
            recursive: false,
            print_version: false,
            all: false,
            dirs_opt: false,
            long: false,
            generation,
            project,
            has: Some("C".to_string()),
            paths_only: false,
            paths: Vec::new(),
        }
    }

    #[test]
    fn fast_has_accepts_btrfs_supported_mask_without_metadata_columns() {
        let cli = cli_for_has(false, false);
        assert!(can_use_fast_has_path(
            &cli,
            letters_to_mask("SiadADcmC").unwrap()
        ));
    }

    #[test]
    fn fast_has_rejects_unsupported_mask_bits() {
        let cli = cli_for_has(false, false);
        assert!(!can_use_fast_has_path(&cli, letters_to_mask("e").unwrap()));
    }

    #[test]
    fn fast_has_rejects_project_or_generation_columns() {
        assert!(!can_use_fast_has_path(
            &cli_for_has(true, false),
            letters_to_mask("C").unwrap()
        ));
        assert!(!can_use_fast_has_path(
            &cli_for_has(false, true),
            letters_to_mask("C").unwrap()
        ));
    }

    #[test]
    fn trim_trailing_slashes_cases() {
        assert_eq!(trim_trailing_slashes(b""), b"");
        assert_eq!(trim_trailing_slashes(b"/"), b"");
        assert_eq!(trim_trailing_slashes(b"////"), b"");
        assert_eq!(trim_trailing_slashes(b"a/"), b"a");
        assert_eq!(trim_trailing_slashes(b"a///b//"), b"a///b");
        assert_eq!(trim_trailing_slashes(b"/mnt/x"), b"/mnt/x");
    }

    #[test]
    fn compose_path_cases() {
        // Empty rel returns the base unchanged (no trailing slash added).
        assert_eq!(compose_path(Path::new("/mnt"), b""), b"/mnt");
        // Separator inserted only when the base lacks one.
        assert_eq!(compose_path(Path::new("/mnt"), b"a/b"), b"/mnt/a/b");
        assert_eq!(compose_path(Path::new("/mnt/"), b"a/b"), b"/mnt/a/b");
        // `.` base mirrors the walk path's `./name` composition.
        assert_eq!(compose_path(Path::new("."), b"a"), b"./a");
    }

    #[test]
    fn is_recoverable_matrix() {
        let mk = |e: i32| io::Error::from_raw_os_error(e);
        assert!(is_recoverable(&mk(libc::EPERM)));
        assert!(is_recoverable(&mk(libc::ENOTTY)));
        assert!(is_recoverable(&mk(libc::EINVAL)));
        // Real arg errors must stay fatal, not silently fall back.
        assert!(!is_recoverable(&mk(libc::ENOENT)));
        assert!(!is_recoverable(&mk(libc::EACCES)));
        // Parse-layer errors carry no errno → not recoverable.
        assert!(!is_recoverable(&io::Error::new(
            io::ErrorKind::InvalidData,
            "bad"
        )));
    }
}
