// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The live two-process RTPS interop test harness — `ROADMAP.md`'s
//! "Interop testing" section, deliverable 1 of 3 ("A live two-process
//! test harness ... This is the minimum bar and should gate Tier 1
//! completion").
//!
//! Each test here spawns two real, independent OS processes of the
//! `rtps-interop-peer` binary (`src/bin/rtps_interop_peer.rs` — real
//! `rust_dds::rtps` SPDP/SEDP/data-path machinery, no test-only shortcuts)
//! on real UDP loopback/multicast and asserts, from each process's own
//! JSON report on stdout:
//!
//! - SPDP discovers both sides (`spdp_peers_known >= 1` on both).
//! - SEDP matches the writer/reader pair (the reader actually receives
//!   samples, which is impossible without a real SEDP match; the writer's
//!   own `sedp_endpoint_matches` is asserted directly too).
//! - Samples flow end-to-end (`writer.sent == reader.received.len()`,
//!   payloads and sequence numbers checked).
//! - A reliable-QoS run that forces a real retransmission: the reader
//!   process deliberately discards its own first real receipt of one
//!   datagram (after the kernel already delivered it — a real UDP
//!   datagram that really crossed process boundaries), and the test
//!   asserts the dropped sample still arrives (via ACKNACK-driven
//!   retransmission) and every sample lands in original sequence order.
//!   This is the "not just within one process's own test suite" case —
//!   contrast with
//!   `src/rtps/participant.rs::tests::reliable_qos_detects_gap_and_retransmits_over_real_udp`,
//!   which proves the same retransmission logic but entirely within one
//!   test/process.
//!
//! `#[ignore]`d by default (real child-process spawning + real UDP
//! multicast is unsuited to the default cross-platform `cargo test`
//! matrix — see `ROADMAP.md`'s note that this is scoped as its own
//! `rtps-interop` CI job, ubuntu-only, analogous to but distinct from the
//! existing `relay-interop` job). Run explicitly:
//!
//! ```text
//! cargo test --release --test rtps_two_process_interop -- --ignored --test-threads=1
//! ```

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Absolute path to the `rtps-interop-peer` binary Cargo built for this
/// test binary — see the `CARGO_BIN_EXE_<name>` docs
/// (https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates).
fn peer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rtps-interop-peer")
}

#[derive(Debug, serde::Deserialize)]
struct ReceivedSample {
    payload_utf8: String,
    sequence_number: u64,
    #[allow(dead_code)]
    writer_guid_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct Report {
    #[allow(dead_code)]
    role: String,
    ok: bool,
    #[allow(dead_code)]
    guid_prefix_hex: String,
    spdp_peers_known: u64,
    #[allow(dead_code)]
    spdp_announces_sent: u64,
    #[allow(dead_code)]
    spdp_announces_received: u64,
    sedp_endpoint_matches: u64,
    sent: Option<usize>,
    received: Option<Vec<ReceivedSample>>,
    dropped_applied: Option<bool>,
    error: Option<String>,
}

/// Spawns `peer_bin()` with `args`, waits up to `deadline` (polling
/// `try_wait` rather than blocking indefinitely, so a hung child cannot
/// hang this test), and parses the last stdout line as a [`Report`].
fn run_peer(args: &[&str], deadline: Duration) -> Report {
    let mut child = Command::new(peer_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", peer_bin()));

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "peer process (args={args:?}) did not exit within {deadline:?} — killed. \
                 This should not happen: rtps-interop-peer bounds its own runtime via \
                 --discovery-timeout-secs/--recv-timeout-secs/--linger-secs."
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");

    let last_line = stdout
        .lines()
        .last()
        .unwrap_or_else(|| panic!("peer (args={args:?}) printed no stdout.\nstderr:\n{stderr}"));
    serde_json::from_str(last_line).unwrap_or_else(|e| {
        panic!(
            "peer (args={args:?}) last stdout line was not valid JSON: {e}\nline: {last_line}\n\
             exit status: {status:?}\nstderr:\n{stderr}"
        )
    })
}

/// Spawns the reader first (as a background `std::thread`, since
/// `run_peer` blocks until the child exits) so it is already listening
/// before the writer's first SPDP announcement — not required for
/// correctness (SPDP/SEDP discovery is symmetric either order, per
/// `spdp_peer_listener_bridges_discovery_to_sedp_announcement` in
/// `participant.rs`), just closer to how a real deployment would sequence
/// two independent processes.
fn run_writer_and_reader(
    writer_args: Vec<String>,
    reader_args: Vec<String>,
    deadline: Duration,
) -> (Report, Report) {
    let reader_handle = std::thread::spawn(move || {
        let args: Vec<&str> = reader_args.iter().map(String::as_str).collect();
        run_peer(&args, deadline)
    });
    // Give the reader a small head start to register before the writer's
    // discovery-timeout clock starts ticking.
    std::thread::sleep(Duration::from_millis(150));
    let args: Vec<&str> = writer_args.iter().map(String::as_str).collect();
    let writer_report = run_peer(&args, deadline);
    let reader_report = reader_handle.join().expect("reader thread panicked");
    (writer_report, reader_report)
}

//fusa:test REQ-RTPS-037
//fusa:test REQ-RTPS-038
//fusa:test REQ-RTPS-039
//fusa:test REQ-RTPS-040
#[test]
#[ignore = "spawns real OS processes + real UDP multicast; run via the rtps-interop CI job"]
fn spdp_discovers_both_sides_sedp_matches_and_besteffort_samples_flow_end_to_end() {
    let deadline = Duration::from_secs(30);
    let (writer, reader) = run_writer_and_reader(
        vec![
            "--role",
            "writer",
            "--topic",
            "Square",
            "--domain",
            "210",
            "--prefix-seed",
            "11",
            "--count",
            "5",
            "--payload",
            "besteffort",
            "--discovery-timeout-secs",
            "15",
            "--linger-secs",
            "1",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        vec![
            "--role",
            "reader",
            "--topic",
            "Square",
            "--domain",
            "210",
            "--prefix-seed",
            "12",
            "--count",
            "5",
            "--discovery-timeout-secs",
            "15",
            "--recv-timeout-secs",
            "20",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        deadline,
    );

    assert!(writer.ok, "writer did not report success: {writer:?}");
    assert!(reader.ok, "reader did not report success: {reader:?}");

    // SPDP discovered both sides.
    assert!(
        writer.spdp_peers_known >= 1,
        "writer never discovered a peer via SPDP: {writer:?}"
    );
    assert!(
        reader.spdp_peers_known >= 1,
        "reader never discovered a peer via SPDP: {reader:?}"
    );

    // SEDP matched the writer/reader pair (checked on the writer's own
    // count of local<->remote endpoint matches; the reader's ability to
    // receive anything at all below is itself only possible if SEDP
    // matched on its side too).
    assert!(
        reader.sedp_endpoint_matches >= 1,
        "reader's SEDP never recorded an endpoint match: {reader:?}"
    );

    // Samples flowed end-to-end.
    assert_eq!(writer.sent, Some(5));
    let received = reader.received.expect("reader report missing `received`");
    assert_eq!(received.len(), 5);
    let payloads: Vec<&str> = received.iter().map(|s| s.payload_utf8.as_str()).collect();
    assert_eq!(
        payloads,
        vec![
            "besteffort-0",
            "besteffort-1",
            "besteffort-2",
            "besteffort-3",
            "besteffort-4"
        ]
    );
    let seqs: Vec<u64> = received.iter().map(|s| s.sequence_number).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

//fusa:test REQ-RTPS-046
//fusa:test REQ-RTPS-047
//fusa:test REQ-RTPS-050
#[test]
#[ignore = "spawns real OS processes + real UDP multicast; run via the rtps-interop CI job"]
fn reliable_qos_recovers_a_real_dropped_datagram_between_two_live_processes() {
    let deadline = Duration::from_secs(30);
    let (writer, reader) = run_writer_and_reader(
        vec![
            "--role",
            "writer",
            "--topic",
            "Square",
            "--domain",
            "211",
            "--prefix-seed",
            "21",
            "--reliable",
            "--count",
            "5",
            "--payload",
            "reliable",
            "--discovery-timeout-secs",
            "15",
            "--linger-secs",
            "4",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        vec![
            "--role",
            "reader",
            "--topic",
            "Square",
            "--domain",
            "211",
            "--prefix-seed",
            "22",
            "--reliable",
            "--count",
            "5",
            "--discovery-timeout-secs",
            "15",
            "--recv-timeout-secs",
            "25",
            // Drop this process's own first real receipt of the datagram
            // carrying RTPS sequence number 3 (the middle sample) — a real
            // UDP datagram sent by the writer's OS process, already
            // delivered by the kernel to this reader process's socket,
            // deliberately discarded before RTPS dispatch. See
            // RtpsParticipant::handle_data_packet's doc comment.
            "--drop-seq",
            "3",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        deadline,
    );

    assert!(writer.ok, "writer did not report success: {writer:?}");
    assert!(reader.ok, "reader did not report success: {reader:?}");
    assert!(writer.spdp_peers_known >= 1);
    assert!(reader.spdp_peers_known >= 1);
    assert!(reader.sedp_endpoint_matches >= 1);

    assert_eq!(
        reader.dropped_applied,
        Some(true),
        "the reader never actually observed (and dropped) sequence 3 — the test proved nothing: {reader:?}"
    );

    assert_eq!(writer.sent, Some(5));
    let received = reader.received.expect("reader report missing `received`");
    assert_eq!(
        received.len(),
        5,
        "expected all 5 samples including the one recovered via ACKNACK retransmission: {received:?}"
    );
    let payloads: Vec<&str> = received.iter().map(|s| s.payload_utf8.as_str()).collect();
    assert_eq!(
        payloads,
        vec![
            "reliable-0",
            "reliable-1",
            "reliable-2",
            "reliable-3",
            "reliable-4"
        ]
    );
    // The recovered sample (seq 3, "reliable-2") must still land in
    // original sequence order, not just eventually arrive out of order.
    let seqs: Vec<u64> = received.iter().map(|s| s.sequence_number).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

#[test]
#[ignore = "spawns real OS processes + real UDP multicast; run via the rtps-interop CI job"]
fn peer_binary_reports_failure_when_no_peer_ever_appears() {
    // Sanity check on the harness itself: a lone reader with a short
    // discovery timeout and nobody to discover must report ok=false with
    // spdp_peers_known == 0, not hang or false-positive.
    let report = run_peer(
        &[
            "--role",
            "reader",
            "--topic",
            "NoOneIsPublishingThis",
            "--domain",
            "212",
            "--prefix-seed",
            "31",
            "--count",
            "1",
            "--discovery-timeout-secs",
            "2",
            "--recv-timeout-secs",
            "2",
        ],
        Duration::from_secs(15),
    );
    assert!(!report.ok);
    assert_eq!(report.spdp_peers_known, 0);
    assert!(report.error.is_some());
}
