// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The live two-process shmem transport interop test harness —
//! `ROADMAP.md`'s "Planned — v0.4 — Shared-Memory Transport" milestone,
//! the same "prove it works between two real OS processes, not just
//! in-process" bar `tests/rtps_two_process_interop.rs` established for
//! Tier 1's RTPS transport.
//!
//! Each test here spawns two real, independent OS processes of the
//! `shmem-interop-peer` binary (`src/bin/shmem_interop_peer.rs` — real
//! `rust_dds::shmem::ShmemParticipant` machinery: real rendezvous-file
//! writes on the writer side, real polling reads on the reader side; no
//! test-only shortcuts) and asserts, from the reader process's own JSON
//! report on stdout, that every payload/sequence-number pair the writer
//! process sent actually arrived — impossible unless the rendezvous file
//! this crate's `shmem::ipc` module writes and polls genuinely crossed a
//! process boundary, since the two processes share no other state (no
//! shared `Broker`, no shared memory the OS attaches to both processes'
//! address space, no socket — see `src/shmem/ipc.rs`'s module docs for
//! why this transport uses a plain file rather than an OS shared-memory
//! primitive).
//!
//! Two scenarios:
//!
//! - **Live delivery**: the reader process is spawned first and prints
//!   `READY` on stderr once it is actually subscribed (poller task
//!   spawned) *before* the writer process is spawned — this is a
//!   synchronization rendezvous the test harness waits on, not a race,
//!   so "how fast can two independently-scheduled OS processes start" is
//!   not a source of flakiness here the way it would be for
//!   `rtps_two_process_interop.rs`'s SPDP-discovery-timing case. Volatile
//!   QoS (the default), several samples, in order.
//! - **TransientLocal late joiner, cross-process**: the writer process
//!   publishes and exits *completely* first (with `--reliable`, i.e.
//!   `RELIABLE_QOS`/`DurabilityKind::TransientLocal`); only afterward is
//!   the reader process started, with no writer process alive at all by
//!   that point. The reader must still receive the writer's *last*
//!   published value, proving `src/shmem/ipc.rs::spawn_poller`'s
//!   cross-process TransientLocal fallback (reading the rendezvous file's
//!   *current* content on first poll) actually works across a real
//!   process boundary — this is a case go-DDS's own reference
//!   implementation does not handle at all cross-process (see
//!   `ipc.rs`'s module doc comment).
//!
//! `#[ignore]`d by default (real child-process spawning is unsuited to
//! the default cross-platform `cargo test` matrix — see `ROADMAP.md`'s
//! "Interop testing" section and this crate's existing `rtps-interop` CI
//! job for the established precedent). Run explicitly:
//!
//! ```text
//! cargo test --release --test shmem_two_process_interop -- --ignored --test-threads=1
//! ```

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn peer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_shmem-interop-peer")
}

/// A topic name unique to this test process invocation, so repeated CI
/// runs never collide on a stale rendezvous file left on disk by a
/// previous run (this crate's `shmem` transport does not clean up its
/// rendezvous directory on close — see `src/shmem/ipc.rs`).
fn unique_topic(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

#[derive(Debug, serde::Deserialize)]
struct ReceivedSample {
    payload_utf8: String,
    sequence_number: u64,
}

#[derive(Debug, serde::Deserialize)]
struct Report {
    #[allow(dead_code)]
    role: String,
    ok: bool,
    sent: Option<usize>,
    received: Option<Vec<ReceivedSample>>,
    error: Option<String>,
}

/// Runs `peer_bin()` with `args` to completion (no "READY" rendezvous —
/// used for the writer, which has no reason to synchronize with anything)
/// and parses its last stdout line as a [`Report`]. Polls `try_wait`
/// rather than blocking indefinitely, so a hung child cannot hang this
/// test.
fn run_to_completion(args: &[&str], deadline: Duration) -> Report {
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
            panic!("peer process (args={args:?}) did not exit within {deadline:?} — killed");
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
    let report: Report = serde_json::from_str(last_line).unwrap_or_else(|e| {
        panic!(
            "peer (args={args:?}) last stdout line was not valid JSON: {e}\nline: {last_line}\n\
             exit status: {status:?}\nstderr:\n{stderr}"
        )
    });
    assert!(
        status.success() == report.ok,
        "process exit code disagreed with its own report.ok"
    );
    report
}

/// Spawns the reader process and blocks until it prints `READY` on
/// stderr, proving it is actually subscribed (its `ipc::spawn_poller`
/// task is running) before returning — see this file's module doc
/// comment. Returns a `JoinHandle` that, once joined, waits for the
/// reader to exit and returns its parsed [`Report`].
fn spawn_reader_and_wait_ready(
    args: Vec<String>,
    ready_deadline: Duration,
    total_deadline: Duration,
) -> std::thread::JoinHandle<Report> {
    let mut child = Command::new(peer_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", peer_bin()));

    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");

    // Drain stdout on its own thread so the child can never block on a
    // full pipe while we are separately waiting on the stderr "READY"
    // line below.
    let (stdout_tx, stdout_rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout_pipe.read_to_string(&mut buf);
        let _ = stdout_tx.send(buf);
    });

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let stderr_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr_pipe);
        let mut collected = String::new();
        let mut sent_ready = false;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if !sent_ready && line.trim_end() == "READY" {
                        sent_ready = true;
                        let _ = ready_tx.send(());
                    }
                    collected.push_str(&line);
                }
                Err(_) => break,
            }
        }
        collected
    });

    if ready_rx.recv_timeout(ready_deadline).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "reader process (args={args:?}) did not print READY within {ready_deadline:?} — \
             it never reached a subscribed state"
        );
    }

    std::thread::spawn(move || {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break status;
            }
            if start.elapsed() > total_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "reader process (args={args:?}) did not exit within {total_deadline:?} — killed"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = stdout_rx.recv().unwrap_or_default();
        let stderr = stderr_handle.join().unwrap_or_default();
        let last_line = stdout.lines().last().unwrap_or_else(|| {
            panic!("reader (args={args:?}) printed no stdout.\nstderr:\n{stderr}")
        });
        let report: Report = serde_json::from_str(last_line).unwrap_or_else(|e| {
            panic!(
                "reader (args={args:?}) last stdout line was not valid JSON: {e}\nline: \
                 {last_line}\nexit status: {status:?}\nstderr:\n{stderr}"
            )
        });
        assert!(
            status.success() == report.ok,
            "reader process exit code disagreed with its own report.ok"
        );
        report
    })
}

//fusa:test REQ-SHMEM-003
#[test]
#[ignore = "spawns real OS processes; run via the shmem-interop CI job"]
fn two_live_processes_exchange_samples_over_a_real_rendezvous_file() {
    let topic = unique_topic("shmem-interop/live");
    let domain = "220";

    let reader_handle = spawn_reader_and_wait_ready(
        vec![
            "--role".into(),
            "reader".into(),
            "--topic".into(),
            topic.clone(),
            "--domain".into(),
            domain.into(),
            "--count".into(),
            "5".into(),
            "--recv-timeout-secs".into(),
            "15".into(),
        ],
        Duration::from_secs(10),
        Duration::from_secs(30),
    );

    let writer_report = run_to_completion(
        &[
            "--role",
            "writer",
            "--topic",
            &topic,
            "--domain",
            domain,
            "--count",
            "5",
            "--payload",
            "shmem-live",
            "--interval-ms",
            "30",
        ],
        Duration::from_secs(15),
    );
    assert!(
        writer_report.ok,
        "writer did not report ok: {:?}",
        writer_report.error
    );
    assert_eq!(writer_report.sent, Some(5));

    let reader_report = reader_handle.join().expect("reader thread panicked");
    assert!(
        reader_report.ok,
        "reader did not report ok: {:?}",
        reader_report.error
    );
    let received = reader_report
        .received
        .expect("reader must report received samples");
    assert_eq!(
        received.len(),
        5,
        "reader must receive all 5 samples the writer sent"
    );
    for (i, sample) in received.iter().enumerate() {
        assert_eq!(sample.payload_utf8, format!("shmem-live-{i}"));
    }
    // Sequence numbers must be strictly increasing — real per-writer
    // monotonic sequencing crossed the process boundary intact.
    for pair in received.windows(2) {
        assert!(
            pair[1].sequence_number > pair[0].sequence_number,
            "sequence numbers must increase: {:?}",
            received
        );
    }
}

//fusa:test REQ-SHMEM-004
#[test]
#[ignore = "spawns real OS processes; run via the shmem-interop CI job"]
fn late_joining_reader_gets_last_transient_local_value_cross_process() {
    let topic = unique_topic("shmem-interop/tl");
    let domain = "221";

    // The writer runs to completion — including its own process exit —
    // entirely before the reader process is even spawned. No writer
    // process is alive when the reader starts.
    let writer_report = run_to_completion(
        &[
            "--role",
            "writer",
            "--topic",
            &topic,
            "--domain",
            domain,
            "--count",
            "3",
            "--payload",
            "shmem-tl",
            "--interval-ms",
            "10",
            "--reliable",
        ],
        Duration::from_secs(15),
    );
    assert!(
        writer_report.ok,
        "writer did not report ok: {:?}",
        writer_report.error
    );

    let reader_report = run_to_completion(
        &[
            "--role",
            "reader",
            "--topic",
            &topic,
            "--domain",
            domain,
            "--count",
            "1",
            "--recv-timeout-secs",
            "10",
            "--reliable",
        ],
        Duration::from_secs(15),
    );
    assert!(
        reader_report.ok,
        "late-joining reader did not report ok: {:?}",
        reader_report.error
    );
    let received = reader_report
        .received
        .expect("reader must report received samples");
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].payload_utf8, "shmem-tl-2",
        "late joiner must receive the writer's LAST TransientLocal value, cross-process"
    );
}
