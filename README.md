# btrfs-lsattr

Drop-in `lsattr` replacement with a btrfs-aware fast path for `--has` filters.

Default mode is byte-identical to `e2fsprogs lsattr` — same flags, same output,
same exit codes — and works on any filesystem without privileges. When you ask
for a flag-filtered scan with `--has` and have `CAP_SYS_ADMIN`, it switches to
a single `BTRFS_IOC_TREE_SEARCH_V2` sweep over the subvolume's inode B-tree
instead of opening every file. On a cold cache that's roughly **60× faster**
than `lsattr -R | grep` on a multi-million-inode root.

## Install

User-local (`~/.cargo/bin`):

```sh
cargo install --git https://github.com/drizzt/btrfs-lsattr
```

System-wide (so `sudo` and root scripts find it):

```sh
sudo cargo install --git https://github.com/drizzt/btrfs-lsattr --root /usr/local
```

Requires Rust 1.74+.

## Usage

```
btrfs-lsattr [-RVadlvp] [--has LETTERS] [--paths-only] [files...]
```

With no `files`, lists the current directory. Default behavior matches `lsattr`:
a directory argument is expanded one level (its contents); use `-R` to recurse,
`-d` to print the directory itself instead.

Options (all short flags follow `lsattr` semantics):

| Flag             | Meaning                                                            |
|------------------|--------------------------------------------------------------------|
| `-R`             | Recursively list directories and their contents                    |
| `-a`             | Include entries starting with `.` (otherwise skipped)              |
| `-d`             | List directories themselves rather than their contents             |
| `-l`             | Long names (`Immutable, No_COW`) instead of letter field           |
| `-v`             | Prepend the file's version (generation) number                     |
| `-p`             | Prepend the file's project number                                  |
| `-V`             | Print program version to stderr and continue                       |
| `--has LETTERS`  | Emit only inodes that have **all** the listed letters set          |
| `--paths-only`   | Drop the attr field, emit one path per line                        |
| `-h`, `--help`   | Print help                                                         |

`--has` and `--paths-only` are extensions; everything else mirrors `lsattr`.
`--has` always scans recursively and includes dotfiles, regardless of `-R`,
`-a`, or `-d`.

### Examples

`lsattr`-style listing of the current directory:

```sh
btrfs-lsattr
```

Recursive listing of a subvolume:

```sh
btrfs-lsattr -R /mnt/btr_pool/root
```

Find every `+C` (NOCOW) file under a subvolume — uses the tree-search fast path
when run with `CAP_SYS_ADMIN`:

```sh
sudo btrfs-lsattr --has C --paths-only /mnt/btr_pool/root
```

Long form with version and project columns:

```sh
btrfs-lsattr -lvp /etc/fstab
    0 12345      /etc/fstab                   ---
```

## Permissions

Default mode uses `FS_IOC_GETFLAGS`, `FS_IOC_GETVERSION`, and `FS_IOC_FSGETXATTR`
on each opened file — works unprivileged exactly like `lsattr`.

The `--has` tree-search fast path uses `BTRFS_IOC_TREE_SEARCH_V2` and
`BTRFS_IOC_INO_PATHS`, which both require `CAP_SYS_ADMIN`. Without it,
`--has` falls back to a recursive per-file walk (slower, more `EOPNOTSUPP`
noise on symlinks, but functionally equivalent).

## Coverage

In default per-file mode, every `FS_*_FL` bit `lsattr` reports is reported here
(the kernel exposes the full set via `FS_IOC_GETFLAGS`).

In the `--has` tree-search fast path, only the bits stored in the btrfs inode
B-tree are visible:

| Letter | Long name        | btrfs inode bit              |
|--------|------------------|------------------------------|
| `S`    | Synchronous      | `BTRFS_INODE_SYNC`           |
| `i`    | Immutable        | `BTRFS_INODE_IMMUTABLE`      |
| `a`    | Append-only      | `BTRFS_INODE_APPEND`         |
| `d`    | No_Dump          | `BTRFS_INODE_NODUMP`         |
| `A`    | No_Atime         | `BTRFS_INODE_NOATIME`        |
| `D`    | DirSync          | `BTRFS_INODE_DIRSYNC`        |
| `c`    | Compression      | `BTRFS_INODE_COMPRESS`       |
| `m`    | No_Compression   | `BTRFS_INODE_NOCOMPRESS`     |
| `C`    | No_COW           | `BTRFS_INODE_NODATACOW`      |

Filtering on a letter outside this set with `--has` automatically uses the
per-file walker for full `FS_IOC_GETFLAGS` coverage. `-p` and `-v` with `--has`
also use the per-file walker so those columns are never silently dropped.

## Output format

Short (default) — 22-char attr field, one space, path, LF:

```
----i--------------C-- /abs/path
```

Long (`-l`) — path padded to 28 chars, one space, comma-joined long names
(`---` if no flags):

```
/abs/path                    Immutable, No_COW
```

`-v` prepends a 10-char left-aligned generation number; `-p` prepends a 5-char
right-aligned project id; combined order is `<projid> <gen> <flags|name>` —
matches `lsattr -lvp` byte for byte.

`--paths-only` emits one path per line; under `-R` it skips the `\n<dir>:\n`
section headers so the output is pipe-friendly.

In `--has` tree-search mode, hardlinked inodes emit one line per path returned
by `INO_PATHS` in default and `-l` modes; with `--paths-only`, only the first
path per inode is emitted.

## `--has` behavior

`--has` always performs a recursive, dotfile-inclusive scan and ignores `-d`:
the btrfs fast path sees every inode in the subvol regardless, so the
per-file fallback is forced to the same all-inodes view. This keeps `--has`
output identical with and without `CAP_SYS_ADMIN`, including the listing of
nested subvol-root directories.

Nested subvols are recursed automatically. If a child subvol cannot be
tree-searched (e.g. an ioctl error mid-tree), that subtree is transparently
re-scanned with the per-file walk so results stay complete; the failure is
reported on stderr and reflected in a non-zero exit code.

Known limitation: recursion is one stack frame per directory level (as in
upstream `lsattr`), so a pathologically deep tree can overflow the stack.

## Security

This is a read-only metadata lister: it never writes, execs, or opens network
connections, and the default path holds no privilege over the invoking user.
Two behaviors are inherited verbatim from upstream `e2fsprogs lsattr` and kept
deliberately for byte-for-byte compatibility:

- **Directory-recursion TOCTOU.** Like `lsattr`, recursion does `readdir` then
  `lstat`/`opendir` on the composed path. A writer of a traversed directory can
  swap an entry for a symlink in that gap, redirecting which path's *attributes*
  get listed. Impact is limited to reading metadata of the substituted path —
  no file content is read and nothing is written. The per-file `open()` already
  uses `O_NOFOLLOW`. Don't run a recursive scan over a tree another user can
  write while you treat the output as authoritative.

- **Raw filenames in output.** Paths are written as raw bytes, exactly as
  `lsattr` does, so a filename containing terminal escape sequences renders as
  such if you view the output directly. Pipe through a pager or `cat -v` when
  scanning untrusted trees.

The privileged `--has` fast path re-`fstat`s the opened fd and verifies it is
still the subvol root (`st_ino == 256`) on the device originally selected
before issuing the `CAP_SYS_ADMIN` ioctls; a mismatch falls back to the
unprivileged per-file walk rather than tree-searching a substituted subvol.

## License

Dual-licensed under either of:

- MIT license ([LICENSES/MIT.txt](LICENSES/MIT.txt))
- Apache License 2.0 ([LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt))

at your option.
