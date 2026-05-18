// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy@fsfe.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::process::Command;

#[test]
fn empty_has_is_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_btrfs-lsattr"))
        .args(["--has", "", "."])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--has: empty filter"));
    assert!(out.stdout.is_empty());
}
