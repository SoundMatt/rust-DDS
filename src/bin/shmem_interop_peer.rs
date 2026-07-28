// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `shmem-interop-peer` — a standalone, single-topic
//! `rust_dds::shmem::ShmemParticipant` process, driven by the real,
//! production `rust_dds::shmem` machinery (real rendezvous-file writes and
//! polling reads — no test-only shortcuts).
//!
//! This is the shmem transport's live two-process interop test harness —
//! the analogue, for `ROADMAP.md`'s "Planned — v0.4 — Shared-Memory
//! Transport" milestone, of `src/bin/rtps_interop_peer.rs` for Tier 1's
//! "Interop testing" deliverable: `tests/shmem_two_process_interop.rs`
//! spawns two of these as separate OS processes (one `--role writer`, one
//! `--role reader`) sharing a domain and topic, and asserts the reader's
//! own JSON report shows the writer's exact payload/sequence-number pairs
//! arriving — proof that shared-memory IPC actually crosses a real
//! process boundary, not just an in-process broker.
//!
//! Not part of the crate's public library API (a `[[bin]]` target;
//! `rust_dds::shmem` remains internal/not re-exported from the crate
//! root) and not wired into `Participant`/`Publisher`/`Subscriber` —
//! purely a test/dev support tool, same category as
//! `rtps-interop-peer`.
//!
//! On completion, prints exactly one line of JSON to stdout (always the
//! *last* line) describing what happened, and exits `0` on success, `1`
//! otherwise. See [`Report`] for the exact shape.

use std::io::Write as _;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::Serialize;

use rust_dds::participant::Participant;
use rust_dds::relay::SubscriberOptions;
use rust_dds::shmem::ShmemParticipant;
use rust_dds::types::{Domain, QoS};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Role {
    Writer,
    Reader,
}

#[derive(Parser)]
#[command(
    name = "shmem-interop-peer",
    about = "Live shmem transport interop test peer process (test/dev tool, not a public API)"
)]
struct Cli {
    #[arg(long, value_enum)]
    role: Role,
    #[arg(long)]
    topic: String,
    #[arg(long, default_value_t = 0)]
    domain: i32,
    /// Writer: number of samples to publish. Reader: number of samples to
    /// wait for.
    #[arg(long, default_value_t = 5)]
    count: usize,
    /// Writer only: payload prefix; sample i's payload is `"<payload>-<i>"`.
    #[arg(long, default_value = "interop")]
    payload: String,
    #[arg(long, default_value_t = 20)]
    interval_ms: u64,
    #[arg(long, default_value_t = 10)]
    recv_timeout_secs: u64,
    #[arg(long, default_value_t = false)]
    reliable: bool,
}

#[derive(Serialize)]
struct ReceivedSample {
    payload_utf8: String,
    sequence_number: u64,
}

#[derive(Serialize)]
struct Report {
    role: &'static str,
    ok: bool,
    sent: Option<usize>,
    received: Option<Vec<ReceivedSample>>,
    error: Option<String>,
}

impl Report {
    fn print_and_exit(self) -> ! {
        let line = serde_json::to_string(&self).unwrap_or_else(|e| {
            format!(r#"{{"role":"unknown","ok":false,"error":"json encode failed: {e}"}}"#)
        });
        println!("{line}");
        let _ = std::io::stdout().flush();
        std::process::exit(if self.ok { 0 } else { 1 });
    }
}

fn qos(reliable: bool) -> QoS {
    if reliable {
        rust_dds::types::RELIABLE_QOS.clone()
    } else {
        QoS::default()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.role {
        Role::Writer => run_writer(cli).await,
        Role::Reader => run_reader(cli).await,
    }
}

async fn run_writer(cli: Cli) -> ! {
    let p = match ShmemParticipant::new(Domain(cli.domain)) {
        Ok(p) => p,
        Err(e) => Report {
            role: "writer",
            ok: false,
            sent: None,
            received: None,
            error: Some(format!("ShmemParticipant::new: {e}")),
        }
        .print_and_exit(),
    };
    let pub_ = match p.new_publisher(&cli.topic, qos(cli.reliable)).await {
        Ok(p) => p,
        Err(e) => Report {
            role: "writer",
            ok: false,
            sent: None,
            received: None,
            error: Some(format!("new_publisher: {e}")),
        }
        .print_and_exit(),
    };

    let mut sent = 0usize;
    for i in 0..cli.count {
        let payload = format!("{}-{}", cli.payload, i);
        if let Err(e) = pub_.write(payload.into_bytes()).await {
            Report {
                role: "writer",
                ok: false,
                sent: Some(sent),
                received: None,
                error: Some(format!("write #{i}: {e}")),
            }
            .print_and_exit();
        }
        sent += 1;
        tokio::time::sleep(Duration::from_millis(cli.interval_ms)).await;
    }

    Report {
        role: "writer",
        ok: sent == cli.count,
        sent: Some(sent),
        received: None,
        error: None,
    }
    .print_and_exit();
}

async fn run_reader(cli: Cli) -> ! {
    let p = match ShmemParticipant::new(Domain(cli.domain)) {
        Ok(p) => p,
        Err(e) => Report {
            role: "reader",
            ok: false,
            sent: None,
            received: None,
            error: Some(format!("ShmemParticipant::new: {e}")),
        }
        .print_and_exit(),
    };
    let (rx, _sub) = match p
        .new_subscriber(&cli.topic, qos(cli.reliable), SubscriberOptions::default())
        .await
    {
        Ok(v) => v,
        Err(e) => Report {
            role: "reader",
            ok: false,
            sent: None,
            received: None,
            error: Some(format!("new_subscriber: {e}")),
        }
        .print_and_exit(),
    };
    // Rendezvous signal for `tests/shmem_two_process_interop.rs`: once this
    // process is actually subscribed (poller task spawned), print READY on
    // stderr so the test harness knows it is safe to start the writer
    // process without racing "reader not listening yet" against "writer
    // already exited". See that test file's own doc comment.
    eprintln!("READY");
    let _ = std::io::stderr().flush();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.recv_timeout_secs);
    let mut received = Vec::new();
    while received.len() < cli.count {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(sample)) => received.push(ReceivedSample {
                payload_utf8: String::from_utf8_lossy(&sample.payload).into_owned(),
                sequence_number: sample.sequence_number,
            }),
            Ok(None) => break,
            Err(_) => break, // timed out waiting for the next sample
        }
    }

    let ok = received.len() == cli.count;
    Report {
        role: "reader",
        ok,
        sent: None,
        received: Some(received),
        error: if ok {
            None
        } else {
            Some("did not receive the expected number of samples before the timeout".to_string())
        },
    }
    .print_and_exit();
}
