// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

// Output formatters. Match `e2fsprogs/misc/lsattr.c` output byte-for-byte so
// existing scripts keep working unchanged.

use std::io::{self, Write};

use crate::flags::LETTERS;

const PAD_BLANK: &[u8; 28] = b"                            ";

/// Short lsattr line: 22-char attr field, single space, path, LF.
pub fn write_short<W: Write>(w: &mut W, fs_flags: u32, path: &[u8]) -> io::Result<()> {
    let mut buf = [b'-'; 22];
    for (i, spec) in LETTERS.iter().enumerate() {
        if fs_flags & spec.bit != 0 {
            buf[i] = spec.letter as u8;
        }
    }
    w.write_all(&buf)?;
    w.write_all(b" ")?;
    w.write_all(path)?;
    w.write_all(b"\n")
}

/// Long lsattr line: path padded to 28 chars, single space, comma-joined long
/// names (or `---` when no flags are set).
pub fn write_long<W: Write>(w: &mut W, fs_flags: u32, path: &[u8]) -> io::Result<()> {
    w.write_all(path)?;
    if path.len() < 28 {
        w.write_all(&PAD_BLANK[..28 - path.len()])?;
    }
    w.write_all(b" ")?;
    let mut first = true;
    for spec in LETTERS.iter() {
        if fs_flags & spec.bit != 0 {
            if !first {
                w.write_all(b", ")?;
            }
            w.write_all(spec.long.as_bytes())?;
            first = false;
        }
    }
    if first {
        w.write_all(b"---")?;
    }
    w.write_all(b"\n")
}

/// One absolute path per line, LF-terminated.
pub fn write_paths_only<W: Write>(w: &mut W, path: &[u8]) -> io::Result<()> {
    w.write_all(path)?;
    w.write_all(b"\n")
}

/// Single emit point used by both scan paths. Picks the row format from
/// `paths_only`/`long` and prepends `-p`/`-v` columns when supplied.
/// Column order matches lsattr (`misc/lsattr.c:90-107`): project, generation,
/// then attrs.
pub fn write_line<W: Write>(
    w: &mut W,
    flags: u32,
    path: &[u8],
    long: bool,
    paths_only: bool,
    project: Option<u32>,
    generation: Option<u64>,
) -> io::Result<()> {
    if paths_only {
        return write_paths_only(w, path);
    }
    if let Some(p) = project {
        write!(w, "{:5} ", p)?;
    }
    if let Some(g) = generation {
        write!(w, "{:<10} ", g)?;
    }
    if long {
        write_long(w, flags, path)
    } else {
        write_short(w, flags, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{FS_IMMUTABLE_FL, FS_NOCOW_FL};

    fn s(buf: &[u8]) -> String {
        String::from_utf8(buf.to_vec()).unwrap()
    }

    #[test]
    fn short_no_flags() {
        let mut buf = Vec::new();
        write_short(&mut buf, 0, b"/x").unwrap();
        assert_eq!(s(&buf), "---------------------- /x\n");
    }

    #[test]
    fn short_immutable_and_nocow() {
        let mut buf = Vec::new();
        write_short(&mut buf, FS_IMMUTABLE_FL | FS_NOCOW_FL, b"/x").unwrap();
        // s u S D i a d A c E j I t T e C x F N P V m
        // Positions 4 (i) and 15 (C).
        assert_eq!(s(&buf), "----i----------C------ /x\n");
    }

    #[test]
    fn long_no_flags() {
        let mut buf = Vec::new();
        write_long(&mut buf, 0, b"/x").unwrap();
        assert_eq!(s(&buf), format!("{:<28} ---\n", "/x"));
    }

    #[test]
    fn long_immutable_and_nocow() {
        let mut buf = Vec::new();
        write_long(&mut buf, FS_IMMUTABLE_FL | FS_NOCOW_FL, b"/x").unwrap();
        assert_eq!(s(&buf), format!("{:<28} Immutable, No_COW\n", "/x"));
    }

    #[test]
    fn long_path_longer_than_pad() {
        let mut buf = Vec::new();
        let p = "/very/long/path/that/exceeds/twenty/eight/chars";
        write_long(&mut buf, FS_NOCOW_FL, p.as_bytes()).unwrap();
        assert_eq!(s(&buf), format!("{} No_COW\n", p));
    }

    #[test]
    fn paths_only() {
        let mut buf = Vec::new();
        write_paths_only(&mut buf, b"/x").unwrap();
        assert_eq!(s(&buf), "/x\n");
    }
}
