// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Black-box tests for `rust-dds convert --protocol DDS --format json`
//! (§11.2, §20.2/§20.3) — the driver `relay interop` shells out to. These
//! run the actual built binary end-to-end (stdin -> stdout), matching how
//! `relay interop` itself invokes it, rather than only exercising the
//! underlying `types::Sample`/`adapt::to_message` library functions
//! directly (already covered in `src/types.rs`/`src/relay.rs` unit tests).

use std::io::Write as _;
use std::process::{Command, Stdio};

/// Absolute path to the `rust-dds` binary Cargo built for this test binary
/// — see the `CARGO_BIN_EXE_<name>` docs
/// (https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates).
fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rust-dds")
}

fn run_convert(protocol: &str, stdin: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(cli_bin())
        .args(["convert", "--protocol", protocol, "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rust-dds convert");
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(stdin)
        .expect("write to stdin");
    let out = child.wait_with_output().expect("wait for rust-dds convert");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Matches RELAY's own `spec/vectors/dds-sample.json` golden vector
/// exactly, so this test doubles as a local reproduction of what
/// `relay interop --protocol DDS` checks in CI.
//fusa:test REQ-RELAY-004
#[test]
fn convert_dds_sample_matches_golden_vector() {
    let input = br#"{
        "topic": "rt/chatter",
        "payload": "aGVsbG8gZGRz",
        "timestamp": "0001-01-01T00:00:00Z",
        "seq": 7,
        "writer_guid": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
    }"#;
    let (code, stdout, stderr) = run_convert("DDS", input);
    assert_eq!(code, 0, "stderr: {stderr}");
    let got: serde_json::Value = serde_json::from_str(&stdout).expect("output must be JSON");
    let want = serde_json::json!({
        "protocol": 2,
        "version": {"major": 0, "minor": 0, "patch": 0},
        "id": "rt/chatter",
        "payload": "aGVsbG8gZGRz",
        "timestamp": "0001-01-01T00:00:00Z",
        "seq": 7,
        "meta": {"dds.writer_guid": "0102030405060708090a0b0c0d0e0f10"}
    });
    assert_eq!(got, want);
}

/// A binary that advertises `convert` MUST fail (not silently succeed) on
/// malformed input — this is exactly the behaviour `relay interop --strict`
/// depends on to distinguish a real conformance failure from a SKIP.
//fusa:test REQ-RELAY-004
#[test]
fn convert_invalid_input_exits_nonzero() {
    let (code, _stdout, stderr) = run_convert("DDS", b"{not valid json");
    assert_eq!(code, 1);
    assert!(
        stderr.contains("invalid canonical value"),
        "stderr: {stderr}"
    );
}

/// rust-dds only adapts DDS; a non-DDS protocol must be a clear, real
/// failure rather than a silently-accepted no-op.
//fusa:test REQ-RELAY-004
#[test]
fn convert_unsupported_protocol_exits_nonzero() {
    let (code, _stdout, stderr) = run_convert("CAN", b"{}");
    assert_eq!(code, 1);
    assert!(stderr.contains("not implemented"), "stderr: {stderr}");
}
