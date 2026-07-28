// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `rtps-interop-peer` — a standalone, single-topic RTPS participant
//! process, driven entirely by the real, production `rust_dds::rtps`
//! machinery (real SPDP multicast announce/receive/evict, real SEDP
//! unicast announce/receive/match, real BestEffort/Reliable data path).
//!
//! This is the "live two-process test harness" deliverable of
//! `ROADMAP.md`'s "Interop testing" section — "the minimum bar" that
//! "should gate Tier 1 completion". It exists so
//! `tests/rtps_two_process_interop.rs` can spawn two of these as separate
//! OS processes and prove SPDP discovers both sides, SEDP matches the
//! writer/reader pair, and samples flow end-to-end over real UDP
//! loopback — including a reliable-QoS run that forces one real datagram
//! to be dropped and checks ACKNACK-driven recovery *between two live
//! processes*, not within one process's own test suite (that in-process
//! case is already covered by
//! `src/rtps/participant.rs::tests::reliable_qos_detects_gap_and_retransmits_over_real_udp`
//! — this binary is the thing that case explicitly does not prove) — and
//! (`--no-multicast`/`--peer`/`--meta-port`) the unicast half of SPDP
//! discovery from `ROADMAP.md`'s "Planned — v0.2" checklist, the same way,
//! between two live processes with no multicast socket on either side.
//!
//! Not part of the crate's public library API (this is a `[[bin]]`
//! target, `rust_dds::rtps` remains internal/not re-exported) and not
//! wired into `Participant`/`Publisher`/`Subscriber` — purely a test/dev
//! support tool, same category as go-DDS's own `tools/cmd/go-dds` pub/sub/
//! discover CLI, which this binary's `--role writer|reader` flags mirror.
//!
//! On completion, prints exactly one line of JSON to stdout (always the
//! *last* line — earlier lines, if any, are human-readable progress notes
//! useful when running this manually) describing what happened, and exits
//! `0` on success, `1` otherwise. See [`Report`] for the exact shape.

use std::io::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::Serialize;
use tokio::sync::mpsc;

use rust_dds::relay::SubscriberOptions;
use rust_dds::rtps::guid::GuidPrefix;
use rust_dds::rtps::message::{
    decode_data_submessage, Header, SubmessageIter, SUBMSG_DATA, VENDOR_ID_RUST_DDS,
};
use rust_dds::rtps::participant::RtpsParticipant;
use rust_dds::rtps::sedp::{SedpConfig, SedpService};
use rust_dds::rtps::spdp::{SpdpConfig, SpdpService};
use rust_dds::rtps::transport::{
    meta_multicast_port, RtpsDatagram, RtpsSocket, SPDP_MULTICAST_ADDR,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Role {
    Writer,
    Reader,
}

#[derive(Parser)]
#[command(
    name = "rtps-interop-peer",
    about = "Live RTPS interop test peer process (test/dev tool, not a public API)"
)]
struct Cli {
    #[arg(long, value_enum)]
    role: Role,
    #[arg(long)]
    topic: String,
    #[arg(long, default_value_t = 0)]
    domain: u32,
    /// Fills all 12 `GuidPrefix` bytes with this value. Must differ
    /// between the two peer processes in one test.
    #[arg(long, default_value_t = 1)]
    prefix_seed: u8,
    #[arg(long, default_value_t = false)]
    reliable: bool,
    /// Writer: number of samples to publish. Reader: number of samples to
    /// wait for.
    #[arg(long, default_value_t = 5)]
    count: usize,
    /// Writer only: payload prefix; sample i's payload is `"<payload>-<i>"`.
    #[arg(long, default_value = "interop")]
    payload: String,
    #[arg(long, default_value_t = 20)]
    interval_ms: u64,
    /// Writer only: how long to keep the process (and its data-socket
    /// receive loop, needed to process ACKNACK) alive after the last
    /// write, so a reliable writer has time to retransmit before exiting.
    #[arg(long, default_value_t = 3)]
    linger_secs: u64,
    #[arg(long, default_value_t = 15)]
    discovery_timeout_secs: u64,
    #[arg(long, default_value_t = 20)]
    recv_timeout_secs: u64,
    /// Writer only: extra delay after this process's own SEDP match
    /// condition is satisfied, before the first write. SEDP matching is
    /// not atomic across two independent processes: a writer's own
    /// `matched_reader_locators` becoming non-empty proves the writer has
    /// processed the reader's subscription announcement, but the
    /// reciprocal — the reader having processed the writer's publication
    /// announcement and added the writer's `Guid` to its own accepted-
    /// sources set (required before it will accept BestEffort DATA from
    /// that writer at all, see `ReaderState::sources`'s doc comment in
    /// `participant.rs`) — is a separate, independently-timed event on the
    /// other process. This settle delay is standard interop-test practice
    /// (not a workaround for a defect): real DDS deployments have the same
    /// discovery-vs-data race and real applications warm up briefly before
    /// publishing for the same reason.
    #[arg(long, default_value_t = 500)]
    settle_ms: u64,
    /// Reader + `--reliable` only: deliberately discard this process's own
    /// first real receipt of a DATA submessage carrying this RTPS sequence
    /// number (once), *after* the kernel has already delivered the real
    /// UDP datagram sent by the peer writer process — simulating one lost
    /// packet between two live processes without needing any privileged
    /// network-level packet filtering. See [`RtpsParticipant::handle_data_packet`]'s
    /// doc comment.
    #[arg(long)]
    drop_seq: Option<u64>,
    /// Binds the metatraffic unicast socket at this fixed port instead of
    /// an OS-assigned ephemeral one (default `0`). Needed for unicast-only
    /// discovery tests (`--no-multicast`/`--peer`): two independent
    /// processes must each know the other's metatraffic port *before*
    /// either one starts, which an ephemeral port cannot provide — the
    /// same "known in advance" property `ROADMAP.md`'s v0.2 SPDP-unicast
    /// item calls out for Docker/cloud/TSN deployments.
    #[arg(long, default_value_t = 0)]
    meta_port: u16,
    /// Disables SPDP multicast entirely (no bind/join of `239.255.0.1`, no
    /// multicast send) — see [`rust_dds::rtps::spdp::SpdpConfig::no_multicast`].
    /// Combine with `--peer` for unicast-only discovery.
    #[arg(long, default_value_t = false)]
    no_multicast: bool,
    /// Static peer unicast address (`host:port`) to send SPDP
    /// announcements directly to, in addition to (or, with
    /// `--no-multicast`, instead of) the multicast group. Repeatable — see
    /// [`rust_dds::rtps::spdp::SpdpConfig::peer_locators`].
    #[arg(long)]
    peer: Vec<SocketAddr>,
}

#[derive(Serialize)]
struct ReceivedSample {
    payload_utf8: String,
    sequence_number: u64,
    writer_guid_hex: String,
}

#[derive(Serialize)]
struct Report {
    role: &'static str,
    ok: bool,
    guid_prefix_hex: String,
    spdp_peers_known: u64,
    spdp_announces_sent: u64,
    spdp_announces_received: u64,
    sedp_endpoint_matches: u64,
    sent: Option<usize>,
    received: Option<Vec<ReceivedSample>>,
    dropped_applied: Option<bool>,
    error: Option<String>,
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}

fn guid_prefix(seed: u8) -> GuidPrefix {
    GuidPrefix([seed; 12])
}

/// Fans a single socket receive loop's output out to every sender in
/// `senders`, cloning each datagram — mirrors
/// `rust_dds::rtps::dds_participant`'s private helper of the same name
/// (not exported, so duplicated here rather than depended on; this binary
/// is deliberately built entirely on public/internal `rust_dds::rtps` API,
/// same as every other piece of this file). Needed because the
/// metatraffic unicast socket carries both SEDP traffic (always) and, once
/// a peer's unicast SPDP announcement arrives on it, SPDP traffic too —
/// and `mpsc::Receiver` is single-consumer.
fn spawn_datagram_fanout(
    mut rx: mpsc::Receiver<RtpsDatagram>,
    senders: Vec<mpsc::Sender<RtpsDatagram>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(datagram) = rx.recv().await {
            for tx in &senders {
                let _ = tx.send(datagram.clone()).await;
            }
        }
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit_code = run(cli).await;
    std::process::exit(exit_code);
}

async fn run(cli: Cli) -> i32 {
    let prefix = guid_prefix(cli.prefix_seed);
    let discovery_timeout = Duration::from_secs(cli.discovery_timeout_secs);

    let meta_socket = match RtpsSocket::bind_unicast_v4(cli.meta_port).await {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => return fail_report(cli.role, prefix, format!("bind meta socket: {e}")),
    };
    let data_socket = match RtpsSocket::bind_unicast_v4(0).await {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => return fail_report(cli.role, prefix, format!("bind data socket: {e}")),
    };
    // No multicast socket at all when --no-multicast — unicast-only
    // discovery relies entirely on --peer plus the metatraffic socket's
    // receive-loop fan-out to SPDP set up below.
    let mcast_socket = if cli.no_multicast {
        None
    } else {
        let Some(mcast_port) = meta_multicast_port(cli.domain) else {
            return fail_report(
                cli.role,
                prefix,
                format!("domain {} out of range", cli.domain),
            );
        };
        match RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, mcast_port).await {
            Ok(s) => Some(std::sync::Arc::new(s)),
            Err(e) => return fail_report(cli.role, prefix, format!("bind multicast socket: {e}")),
        }
    };

    log(format!(
        "rtps-interop-peer: role={:?} prefix_seed={} domain={} meta_port={} data_port={} mcast_port={:?} \
         no_multicast={} peers={:?}",
        cli.role,
        cli.prefix_seed,
        cli.domain,
        meta_socket.local_port(),
        data_socket.local_port(),
        mcast_socket.as_ref().map(|s| s.local_port()),
        cli.no_multicast,
        cli.peer,
    ));

    // Fast announce cadence — this is a test peer, not a production
    // participant, and the CI job driving this binary should not need to
    // wait out the real 2-second default just to observe discovery.
    let mut spdp_cfg = SpdpConfig::new(
        cli.domain,
        prefix,
        meta_socket.local_port(),
        data_socket.local_port(),
    )
    .with_announce_period(Duration::from_millis(200))
    .with_peer_locators(cli.peer.iter().copied());
    if cli.no_multicast {
        spdp_cfg = spdp_cfg.with_no_multicast();
    }
    let spdp = SpdpService::new(spdp_cfg, std::sync::Arc::clone(&meta_socket));
    let _announce_task = std::sync::Arc::clone(&spdp).spawn_announce_loop();
    let _evict_task = std::sync::Arc::clone(&spdp).spawn_evict_loop();
    // These two tasks' `JoinHandle`s are intentionally allowed to drop at
    // the end of this `if let` block: dropping a `JoinHandle` in tokio only
    // detaches the task (it keeps running), it does not abort it — same
    // convention as every other `let _x = ...spawn...()` binding in this
    // function, just scoped to this block instead of all of `run`.
    if let Some(mcast_socket) = &mcast_socket {
        let (mcast_rx, _mcast_recv_task) = mcast_socket.spawn_receive_loop(64);
        let _spdp_recv_task = std::sync::Arc::clone(&spdp).spawn_receive_loop(mcast_rx);
    }

    let sedp_cfg = SedpConfig::new(prefix, data_socket.local_port());
    let sedp = SedpService::new(
        sedp_cfg,
        std::sync::Arc::clone(&meta_socket),
        std::sync::Arc::clone(&spdp),
    );
    // A peer's unicast SPDP announcement (its own --peer pointing back at
    // this process) arrives on this process's metatraffic unicast socket —
    // the same socket SEDP unicast traffic already uses — so fan its
    // receive loop out to both SPDP and SEDP rather than SEDP alone,
    // matching `RtpsUdpParticipant::new_with_config`'s wiring
    // (`src/rtps/dds_participant.rs`).
    let (meta_rx, _meta_recv_task) = meta_socket.spawn_receive_loop(64);
    let (spdp_meta_tx, spdp_meta_rx) = mpsc::channel(64);
    let (sedp_meta_tx, sedp_meta_rx) = mpsc::channel(64);
    let _fanout_task = spawn_datagram_fanout(meta_rx, vec![spdp_meta_tx, sedp_meta_tx]);
    let _spdp_meta_recv_task = std::sync::Arc::clone(&spdp).spawn_receive_loop(spdp_meta_rx);
    let _sedp_recv_task = std::sync::Arc::clone(&sedp).spawn_receive_loop(sedp_meta_rx);

    let participant = RtpsParticipant::new(
        prefix,
        VENDOR_ID_RUST_DDS,
        std::sync::Arc::clone(&data_socket),
        std::sync::Arc::clone(&sedp),
    );
    let _match_listener_task = participant.clone().spawn_sedp_match_listener().await;
    let _spdp_bridge_task = participant
        .clone()
        .spawn_spdp_peer_listener(std::sync::Arc::clone(&spdp))
        .await;

    match cli.role {
        Role::Writer => {
            run_writer(
                cli,
                prefix,
                participant,
                spdp,
                sedp,
                data_socket,
                discovery_timeout,
            )
            .await
        }
        Role::Reader => {
            run_reader(
                cli,
                prefix,
                participant,
                spdp,
                sedp,
                data_socket,
                discovery_timeout,
            )
            .await
        }
    }
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::Writer => "writer",
        Role::Reader => "reader",
    }
}

fn base_report(role: Role, prefix: GuidPrefix, spdp: &SpdpService, sedp: &SedpService) -> Report {
    Report {
        role: role_str(role),
        ok: false,
        guid_prefix_hex: hex::encode(prefix.0),
        spdp_peers_known: 0, // filled by the caller once it has awaited known_peers()
        spdp_announces_sent: spdp.announces_sent(),
        spdp_announces_received: spdp.announces_received(),
        sedp_endpoint_matches: sedp.endpoint_matches(),
        sent: None,
        received: None,
        dropped_applied: None,
        error: None,
    }
}

fn print_report_and_exit_code(report: Report) -> i32 {
    let code = if report.ok { 0 } else { 1 };
    let json = serde_json::to_string(&report)
        .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"failed to serialise report: {e}"}}"#));
    println!("{json}");
    let _ = std::io::stdout().flush();
    code
}

fn fail_report(role: Role, prefix: GuidPrefix, error: impl Into<String>) -> i32 {
    let error = error.into();
    log(format!("rtps-interop-peer: FAIL: {error}"));
    let report = Report {
        role: role_str(role),
        ok: false,
        guid_prefix_hex: hex::encode(prefix.0),
        spdp_peers_known: 0,
        spdp_announces_sent: 0,
        spdp_announces_received: 0,
        sedp_endpoint_matches: 0,
        sent: None,
        received: None,
        dropped_applied: None,
        error: Some(error),
    };
    print_report_and_exit_code(report)
}

// ---------------------------------------------------------------------------
// Writer role
// ---------------------------------------------------------------------------

async fn run_writer(
    cli: Cli,
    prefix: GuidPrefix,
    participant: std::sync::Arc<RtpsParticipant>,
    spdp: std::sync::Arc<SpdpService>,
    sedp: std::sync::Arc<SedpService>,
    data_socket: std::sync::Arc<RtpsSocket>,
    discovery_timeout: Duration,
) -> i32 {
    // The writer always runs its data socket through the normal receive
    // path (not the manual drop-driving path — `--drop-seq` only applies
    // to the reader): a reliable writer needs to receive the reader's real
    // ACKNACK replies to retransmit at all.
    let (data_rx, _data_recv_task) = data_socket.spawn_receive_loop(64);
    let _data_dispatch_task = std::sync::Arc::clone(&participant).spawn_receive_loop(data_rx);

    // `_hb_task`'s binding (when reliable) keeps the heartbeat-sending
    // tokio task alive for the rest of this function — dropping a
    // `JoinHandle` in tokio detaches rather than aborts the task, but
    // holding the binding until the function returns keeps the intent
    // explicit and matches this file's other background-task bindings.
    let (writer_result, _hb_task) = if cli.reliable {
        let (w, hb) = participant.new_reliable_writer(cli.topic.clone()).await;
        (w, Some(hb))
    } else {
        (participant.new_writer(cli.topic.clone()).await, None)
    };

    log(format!(
        "rtps-interop-peer: writer registered for topic {:?}",
        cli.topic
    ));

    let topic = cli.topic.clone();
    let discovered = tokio::time::timeout(discovery_timeout, async {
        loop {
            if !sedp.matched_reader_locators(&topic).await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();

    if !discovered {
        let mut report = base_report(cli.role, prefix, &spdp, &sedp);
        report.spdp_peers_known = spdp.known_peers().await.len() as u64;
        report.error = Some(format!(
            "SEDP never matched a remote reader for topic {:?} within {:?}",
            cli.topic, discovery_timeout
        ));
        return print_report_and_exit_code(report);
    }

    log("rtps-interop-peer: writer discovered a matched reader; settling before writing samples");
    if cli.settle_ms > 0 {
        tokio::time::sleep(Duration::from_millis(cli.settle_ms)).await;
    }

    for i in 0..cli.count {
        let payload = format!("{}-{i}", cli.payload);
        if let Err(e) = writer_result.write(payload.as_bytes()).await {
            let mut report = base_report(cli.role, prefix, &spdp, &sedp);
            report.error = Some(format!("write {i} failed: {e}"));
            return print_report_and_exit_code(report);
        }
        if cli.interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cli.interval_ms)).await;
        }
    }

    // Keep the process (and its ACKNACK-processing receive loop) alive so
    // a reliable writer has time to actually retransmit before exiting.
    tokio::time::sleep(Duration::from_secs(cli.linger_secs)).await;

    let mut report = base_report(cli.role, prefix, &spdp, &sedp);
    report.spdp_peers_known = spdp.known_peers().await.len() as u64;
    report.sent = Some(cli.count);
    report.ok = true;
    print_report_and_exit_code(report)
}

// ---------------------------------------------------------------------------
// Reader role
// ---------------------------------------------------------------------------

async fn run_reader(
    cli: Cli,
    prefix: GuidPrefix,
    participant: std::sync::Arc<RtpsParticipant>,
    spdp: std::sync::Arc<SpdpService>,
    sedp: std::sync::Arc<SedpService>,
    data_socket: std::sync::Arc<RtpsSocket>,
    discovery_timeout: Duration,
) -> i32 {
    let dropped_applied = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let (mut data_rx, _data_recv_task) = data_socket.spawn_receive_loop(64);
    let data_dispatch_task = if let Some(drop_seq) = cli.drop_seq {
        let participant = std::sync::Arc::clone(&participant);
        let dropped_applied = std::sync::Arc::clone(&dropped_applied);
        tokio::spawn(async move {
            let mut dropped_once = false;
            while let Some(datagram) = data_rx.recv().await {
                let mut drop_this = false;
                if let Ok(_header) = Header::decode(&datagram.data) {
                    let body = &datagram.data[Header::LEN..];
                    for result in SubmessageIter::new(body) {
                        let Ok(raw) = result else { break };
                        if raw.id == SUBMSG_DATA {
                            if let Ok(ds) = decode_data_submessage(raw.flags, raw.body) {
                                if ds.seq_num.to_u64() == drop_seq && !dropped_once {
                                    drop_this = true;
                                }
                            }
                        }
                    }
                }
                if drop_this {
                    dropped_once = true;
                    dropped_applied.store(true, std::sync::atomic::Ordering::SeqCst);
                    log(format!(
                        "rtps-interop-peer: reader simulating loss of one real datagram carrying seq={drop_seq}"
                    ));
                    continue; // simulate loss: a real UDP datagram from the
                              // peer writer process, already delivered by
                              // the kernel to this socket, discarded here
                              // instead of dispatched.
                }
                participant
                    .handle_data_packet(&datagram.data, datagram.from)
                    .await;
            }
        })
    } else {
        std::sync::Arc::clone(&participant).spawn_receive_loop(data_rx)
    };
    let _data_dispatch_task = data_dispatch_task; // keep alive for this function's lifetime

    let (rx, _reader) = if cli.reliable {
        participant
            .new_reliable_reader(cli.topic.clone(), SubscriberOptions::default())
            .await
    } else {
        participant
            .new_reader(cli.topic.clone(), SubscriberOptions::default())
            .await
    };

    log(format!(
        "rtps-interop-peer: reader registered for topic {:?}",
        cli.topic
    ));

    let discovered = tokio::time::timeout(discovery_timeout, async {
        loop {
            if !spdp.known_peers().await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();

    if !discovered {
        let mut report = base_report(cli.role, prefix, &spdp, &sedp);
        report.error = Some(format!(
            "SPDP never discovered a peer within {discovery_timeout:?}"
        ));
        return print_report_and_exit_code(report);
    }

    log("rtps-interop-peer: reader discovered a peer; waiting for samples");

    let mut received = Vec::new();
    let collect = tokio::time::timeout(Duration::from_secs(cli.recv_timeout_secs), async {
        while received.len() < cli.count {
            match rx.recv().await {
                Some(sample) => received.push(ReceivedSample {
                    payload_utf8: String::from_utf8_lossy(&sample.payload).to_string(),
                    sequence_number: sample.sequence_number,
                    writer_guid_hex: hex::encode(sample.writer_guid),
                }),
                None => break,
            }
        }
    })
    .await;
    if collect.is_err() {
        log(format!(
            "rtps-interop-peer: recv timeout after {} sample(s) (wanted {})",
            received.len(),
            cli.count
        ));
    }

    let mut report = base_report(cli.role, prefix, &spdp, &sedp);
    report.spdp_peers_known = spdp.known_peers().await.len() as u64;
    report.sedp_endpoint_matches = sedp.endpoint_matches();
    report.dropped_applied = cli
        .drop_seq
        .map(|_| dropped_applied.load(std::sync::atomic::Ordering::SeqCst));
    report.ok = received.len() == cli.count;
    if !report.ok {
        report.error = Some(format!(
            "received {} of {} expected samples within {}s",
            received.len(),
            cli.count,
            cli.recv_timeout_secs
        ));
    }
    report.received = Some(received);
    print_report_and_exit_code(report)
}
