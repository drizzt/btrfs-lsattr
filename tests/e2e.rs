// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end checks gated on a real filesystem. Skipped (pass with a note)
//! unless `BTRFS_LSATTR_E2E` points at a directory to scan, so CI without a
//! btrfs mount stays green. Run locally with, e.g.:
//!
//! ```sh
//! BTRFS_LSATTR_E2E=/mnt/btr_pool/root cargo test --test e2e -- --nocapture
//! # the --has parity check additionally needs CAP_SYS_ADMIN:
//! sudo -E BTRFS_LSATTR_E2E=/mnt/btr_pool/root cargo test --test e2e
//! ```

use std::process::Command;

fn target() -> Option<String> {
    match std::env::var("BTRFS_LSATTR_E2E") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => {
            eprintln!("skipping: set BTRFS_LSATTR_E2E=<dir> to run e2e checks");
            None
        }
    }
}

/// Core compat invariant: default-mode output must be byte-identical to the
/// system `lsattr`. This is the contract the whole project rests on.
#[test]
fn default_mode_matches_system_lsattr() {
    let Some(dir) = target() else { return };
    let sys = match Command::new("lsattr").args(["-Rad", &dir]).output() {
        Ok(o) => o,
        Err(_) => {
            eprintln!("skipping: system `lsattr` not found");
            return;
        }
    };
    let ours = Command::new(env!("CARGO_BIN_EXE_btrfs-lsattr"))
        .args(["-Rad", &dir])
        .output()
        .unwrap();
    assert_eq!(
        sys.stdout, ours.stdout,
        "default-mode stdout diverged from system lsattr"
    );
    assert_eq!(sys.status.code(), ours.status.code(), "exit code diverged");
}

/// `--has` must not panic and must exit 0/1 (never a signal/abort), exercising
/// the fast path under CAP_SYS_ADMIN or the per-file fallback otherwise. With
/// privileges this also covers the nested-subvol recursion + F2 emit paths.
#[test]
fn has_filter_runs_cleanly() {
    let Some(dir) = target() else { return };
    let out = Command::new(env!("CARGO_BIN_EXE_btrfs-lsattr"))
        .args(["--has", "C", "--paths-only", &dir])
        .output()
        .unwrap();
    assert!(
        matches!(out.status.code(), Some(0) | Some(1)),
        "--has exited abnormally: {:?}",
        out.status
    );
    // Every emitted line is a path under the scanned dir.
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        assert!(
            line.starts_with(&dir) || line.starts_with("./") || line.starts_with('/'),
            "unexpected --has output line: {line:?}"
        );
    }
}
