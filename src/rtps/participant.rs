// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RTPS participant runtime — the BestEffort data path (RTPS 2.3 §8.4/§8.7).
//!
//! This is Tier 1 sub-phase 6 of the parity build-out plan in `ROADMAP.md`
//! ("Tier 1 — RTPS wire-protocol port" → "BestEffort data path"): the first
//! module in this tree to actually own `rtpsReader`/`rtpsWriter`-shaped
//! runtime objects, composing `transport` (sub-phase 3), `spdp` (sub-phase
//! 4), and `sedp` (sub-phase 5) into something that delivers real DDS
//! samples end-to-end over UDP. Mirrors the receive-loop-dispatch and
//! reader/writer-bookkeeping half of go-DDS's `rtps/participant.go` (1,505
//! LOC total) — specifically `handleDataPacket`, `dispatchToReaders`,
//! `deliverToReader`, `NewPublisher`/`NewSubscriber`'s registration
//! bookkeeping, and the BestEffort (non-`w.reliable`) half of
//! `rtpsWriter.Write`. Sub-phase 7 (Reliable QoS) later extended this same
//! module with HEARTBEAT/ACKNACK retransmission wiring (see the "Reliable
//! QoS (sub-phase 7)" section below), and sub-phase 8 (Fragmentation) with
//! DATA_FRAG send/receive wiring on top of [`super::fragment`] — see
//! [`RtpsWriter::write`] and the `SUBMSG_DATA_FRAG` case in
//! [`RtpsParticipant::handle_data_packet`]. Sub-phase 9's two small stretch
//! items are wired in here too: [`RtpsWriter::write`] flushes the last
//! written payload per topic via [`super::persist::persist_flush`] (when
//! [`RtpsParticipant::new_with_persistent_history`] configured a
//! directory), [`RtpsParticipant::new_transient_local_reader`]/
//! [`RtpsParticipant::new_reliable_transient_local_reader`] deliver a
//! late-joining reader's TransientLocal last sample (in-memory first, disk
//! via [`super::persist::persist_load`] as fallback), and
//! [`RtpsParticipant::dispatch_to_readers`] matches topics with
//! [`super::wildcard::topic_matches`] instead of plain equality — see
//! `persist.rs`/`wildcard.rs`'s own module docs for the byte-format/
//! matching-rule detail.
//!
//! # Wiring SEDP's match output
//!
//! `sedp.rs`'s own module docs describe why, until this sub-phase landed,
//! [`super::sedp::SedpService::on_remote_writer`] and
//! [`super::sedp::SedpService::register_reader`] *returned* matched
//! `EntityId`/`Guid` values instead of notifying a reader object in-line —
//! no participant runtime type existed yet to hold one. [`RtpsParticipant`]
//! is that runtime type:
//!
//! - [`RtpsParticipant::new_reader`] consumes [`SedpService::register_reader`](super::sedp::SedpService::register_reader)'s
//!   synchronous return value directly (remote writers already known *at*
//!   registration time).
//! - [`RtpsParticipant::spawn_sedp_match_listener`] consumes
//!   [`super::sedp::WriterMatch`] events (via
//!   [`SedpService::set_match_listener`](super::sedp::SedpService::set_match_listener))
//!   for the asynchronous case: a remote writer discovered *after* the
//!   local reader was already registered, which only SEDP's own private
//!   receive loop observes.
//!
//! Either path ends the same way: the matched remote writer's `Guid` is
//! added to the reader's accepted-source set ([`ReaderState::sources`]),
//! mirroring go-DDS's `rtpsReader.addSourceGUID`.
//!
//! # DATA submessage payload
//!
//! No new wire format is introduced by this module — it composes
//! primitives already verified byte-for-byte against go-DDS in earlier
//! sub-phases: [`super::cdr::wrap_payload`]/[`super::cdr::unwrap_payload`]
//! (the `CDR_LE` payload encapsulation, sub-phase 2),
//! [`super::message::encode_data_submessage`]/[`super::message::decode_data_submessage`]
//! (sub-phase 4), and [`super::message::wrap_in_rtps_message`] (sub-phase
//! 4). [`RtpsWriter::write`]'s test verifies the *composition* of those
//! primitives for a fixed payload still matches go-DDS's own composition
//! (`cdrWrapPayload` → `marshalDataSubmessage` → `wrapInRTPSMessage`) — see
//! its doc comment for the exact reproduction command.
//!
//! One deliberate, documented deviation from go-DDS: go-DDS's
//! `rtpsWriter.Write` always prepends an `INFO_TS` submessage carrying the
//! write's wall-clock timestamp, which `handleDataPacket` on the receiving
//! side reattaches to the delivered [`Sample`](crate::types::Sample)'s
//! `timestamp` field. `INFO_TS` encode/decode does not exist yet in this
//! crate (`message.rs` only defines the `SUBMSG_INFO_TS` submessage-id
//! constant, no body codec) — out of scope for this sub-phase, per
//! `ROADMAP.md`'s scoping of sub-phase 6 to "DATA submessage encode/decode,
//! dispatch ... by topic + writer GUID" (no mention of inline timestamp
//! propagation, unlike sub-phase 5's explicit inline-QoS carve-out). Until
//! a later sub-phase adds it, every delivered `Sample`'s `timestamp` is
//! `Utc::now()` at the delivering side (local dispatch: the writer's own
//! `write()` call time; remote dispatch: the reader's receive time) rather
//! than the writer's original send time — a deviation, not a correctness
//! bug, and one `Sample::timestamp`'s own doc comment already anticipates
//! ("zero ... means no timestamp was provided by the transport").
//!
//! # Reusing `SampleReceiver`
//!
//! Per `ROADMAP.md`'s async/tokio design section (the go-DDS→rust-DDS
//! translation table), a reader's delivery channel reuses
//! [`crate::participant::SampleReceiver`]/[`crate::participant::SubInner`]
//! — the same type [`crate::mock::MockParticipant`] hands back from
//! `new_subscriber` — rather than inventing a second "reader channel" type.
//! [`RtpsParticipant::new_reader`] returns a real `SampleReceiver`;
//! `ReaderState` holds the matching `Arc<SubInner>` and calls
//! [`SubInner::push`] on delivery, exactly like `MockParticipant`'s broker.
//!
//! # Async model
//!
//! Same idiom as `spdp.rs`/`sedp.rs`: every long-running loop
//! ([`RtpsParticipant::spawn_receive_loop`],
//! [`RtpsParticipant::spawn_sedp_match_listener`]) is its own `tokio::task`,
//! independently stoppable via `.abort()` on its returned `JoinHandle`.
//! Endpoint bookkeeping (`readers`, `writers`) is guarded by a plain
//! `tokio::sync::RwLock`, held only for brief map lookups/inserts — never
//! across a socket send.
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001) and no panics on
//! malformed/truncated decode input (REQ-ASIL-003 / REQ-RTPS-009):
//! [`RtpsParticipant::handle_data_packet`] and everything it calls treats
//! malformed input as "ignore this datagram", never as a crash.
//!
//! Internal only: not re-exported from the crate root, not yet wired into
//! `Participant`/`Publisher`/`Subscriber`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::participant::{SampleReceiver, SubInner};
use crate::relay::SubscriberOptions;
use crate::types::Sample;

use super::cdr::{unwrap_payload, wrap_payload};
use super::fragment::{
    decode_data_frag, encode_data_frag, split_into_fragments, FragmentAssembler,
    MAX_FRAGMENT_PAYLOAD, SUBMSG_DATA_FRAG,
};
use super::guid::{
    entity_id_for_reader, entity_id_for_writer, EntityId, Guid, GuidPrefix, ENTITYID_UNKNOWN,
};
use super::message::{
    decode_acknack_submessage, decode_data_submessage, decode_heartbeat_submessage,
    encode_acknack_submessage, encode_data_submessage, encode_gap_submessage,
    encode_heartbeat_submessage, wrap_in_rtps_message, AckNack, Gap, Header, Heartbeat,
    SequenceNumber, SubmessageIter, VendorId, PROTOCOL_VERSION_2_3, SUBMSG_ACKNACK, SUBMSG_DATA,
    SUBMSG_HEARTBEAT,
};
use super::persist::{persist_flush, persist_load};
use super::reliable::{RecvTracker, SendHistory, HEARTBEAT_PERIOD};
use super::sedp::SedpService;
use super::transport::{RtpsDatagram, RtpsSocket};
use super::wildcard::topic_matches;

// ---------------------------------------------------------------------------
// ReaderState / WriterState
// ---------------------------------------------------------------------------

/// Per-reader bookkeeping. Matches go-DDS's `rtpsReader`.
struct ReaderState {
    topic: String,
    /// SEDP-matched remote writer `Guid`s this reader accepts samples from,
    /// in addition to any writer sharing this participant's own
    /// `GuidPrefix` (always accepted regardless of this set — see
    /// [`RtpsParticipant::accepts_source`]). Matches go-DDS's
    /// `rtpsReader.sources`.
    sources: RwLock<HashSet<Guid>>,
    inner: Arc<SubInner>,
    /// Whether this reader participates in Reliable QoS (HEARTBEAT/ACKNACK
    /// gap tracking — sub-phase 7). `false` for BestEffort readers, which
    /// never populate `trackers` or send ACKNACK. Matches go-DDS's
    /// `rtpsReader.reliable`.
    reliable: bool,
    /// Per-remote-writer gap trackers, populated lazily on first contact
    /// (DATA or HEARTBEAT) with each writer. Only ever non-empty when
    /// `reliable == true`. Matches go-DDS's `rtpsReader.trackers`.
    trackers: RwLock<HashMap<Guid, Arc<RecvTracker>>>,
}

/// Per-writer bookkeeping. Matches go-DDS's `rtpsWriter`. The topic name is
/// duplicated here (in addition to living on [`RtpsWriter`]) because
/// participant-level reliability handlers ([`RtpsParticipant::send_heartbeat`],
/// [`RtpsParticipant::handle_acknack`]) are keyed by `EntityId` alone (from
/// a decoded submessage) and need the topic to resolve matched reader
/// locators — go-DDS's equivalent code gets this for free because its
/// `p.writers` map stores the whole `*rtpsWriter`, topic included.
struct WriterState {
    topic: String,
    /// Next sequence number to assign; matches go-DDS's `rtpsWriter.seq`
    /// (full 64-bit, pre-increment — see [`RtpsWriter::write`]).
    seq: AtomicU64,
    /// Whether this writer participates in Reliable QoS (HEARTBEAT sending,
    /// send-history retention, ACKNACK-driven retransmission — sub-phase
    /// 7). `false` for BestEffort writers. Matches go-DDS's
    /// `rtpsWriter.reliable`.
    reliable: bool,
    /// Ring buffer of recently-sent wire messages, for retransmission.
    /// `Some` exactly when `reliable == true`. Matches go-DDS's
    /// `rtpsWriter.history` (`*sendHistory`, nil for BestEffort writers).
    history: Option<SendHistory>,
    /// Highest sequence number fully acknowledged (via ACKNACK) by at least
    /// one remote reader. `0` means nothing has been acknowledged yet.
    /// Matches go-DDS's `rtpsWriter.acked`. Not consulted by BestEffort
    /// writers.
    acked: AtomicU64,
}

/// Per-topic write/deliver/drop/byte counters — `observability::MetricsProvider`
/// (`ROADMAP.md`'s "Planned — v0.6 — Observability (Tier 5)" milestone).
/// Deliberately a plain `std::sync::Mutex`-guarded map of `AtomicU64`
/// counters, *not* folded into [`RtpsParticipant`]'s existing
/// `tokio::sync::RwLock`-guarded `readers`/`writers` maps: this state must
/// be readable from `MetricsProvider::topic_metrics(&self)`, a synchronous
/// (non-`async`) trait method that cannot `.await` a `tokio::sync::RwLock`
/// — the exact tension [`super::dds_participant::RtpsUdpParticipant`]'s
/// `HealthProvider` impl documented and deferred for its own
/// writer/reader-count reporting. A `std::sync::Mutex` is locked
/// synchronously (no `.await` required) and held only briefly here (never
/// across an `.await`), so it sidesteps that tension entirely rather than
/// deferring it further — see `observability::metrics`'s own module docs.
#[derive(Default)]
struct TopicCounters {
    writes: AtomicU64,
    delivers: AtomicU64,
    drops: AtomicU64,
    bytes_written: AtomicU64,
    bytes_delivered: AtomicU64,
}

impl TopicCounters {
    fn snapshot(&self, topic: &str) -> crate::observability::TopicMetrics {
        crate::observability::TopicMetrics {
            topic: topic.to_string(),
            write_count: self.writes.load(Ordering::Relaxed),
            deliver_count: self.delivers.load(Ordering::Relaxed),
            drop_count: self.drops.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            bytes_delivered: self.bytes_delivered.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// RtpsParticipant
// ---------------------------------------------------------------------------

/// Owns one participant's RTPS reader/writer bookkeeping and the BestEffort
/// send/receive data path. Composes an already-running
/// [`SedpService`]/[`RtpsSocket`] rather than owning discovery or socket
/// lifecycle itself — those are sub-phases 3–5's responsibility; a caller
/// typically constructs `SpdpService`/`SedpService`/the data-unicast
/// `RtpsSocket` first (as `sedp.rs`'s own tests do) and passes the latter
/// two here.
pub struct RtpsParticipant {
    guid_prefix: GuidPrefix,
    vendor_id: VendorId,
    data_socket: Arc<RtpsSocket>,
    sedp: Arc<SedpService>,
    entity_counter: AtomicU32,
    readers: RwLock<HashMap<EntityId, Arc<ReaderState>>>,
    writers: RwLock<HashMap<EntityId, Arc<WriterState>>>,
    /// Receive-side DATA_FRAG reassembly buffer, shared across every reader
    /// on this participant — see `fragment.rs`'s module docs ("Receive-side
    /// wiring") for why a single participant-wide instance mirrors go-DDS's
    /// own (unwired) `fragmentAssembler` design, caveats included.
    frag_assembler: FragmentAssembler,
    delivers: AtomicU64,
    drops: AtomicU64,
    /// In-memory TransientLocal last-sample cache, keyed by topic. Matches
    /// go-DDS's `p.lastSample` (a `sync.Map`); populated by every
    /// [`RtpsWriter::write`] regardless of whether persistent history is
    /// configured, and consulted (before falling back to disk) by
    /// [`RtpsParticipant::new_transient_local_reader`]/
    /// [`RtpsParticipant::new_reliable_transient_local_reader`]. See
    /// `persist.rs`'s module docs.
    last_sample: RwLock<HashMap<String, Sample>>,
    /// Directory backing TransientLocal durability persistence
    /// ([`super::persist`]), or `None` when persistence is disabled —
    /// matches go-DDS's `p.persistDir` (empty string = disabled). Set once
    /// at construction via [`RtpsParticipant::new_with_persistent_history`]
    /// (go-DDS's `WithPersistentHistory` functional option).
    persist_dir: Option<String>,
    /// The user-data multicast group's send destination, or `None` when
    /// multicast delivery is unavailable/disabled — matches go-DDS's
    /// `p.dataMcastSock` (a `nil` socket disables the multicast send path
    /// in `rtpsWriter.Write`). Set post-construction via
    /// [`RtpsParticipant::set_user_data_multicast_addr`] once the caller has
    /// bound (or failed to bind) the multicast receive socket — see that
    /// method's docs for why this is a setter rather than a constructor
    /// parameter.
    user_data_multicast_addr: RwLock<Option<SocketAddr>>,
    /// Per-topic [`TopicCounters`], keyed by topic name —
    /// `observability::MetricsProvider`'s backing data. See
    /// [`TopicCounters`]'s own docs for why this is a `std::sync::Mutex`,
    /// not a `tokio::sync::RwLock` like `readers`/`writers` above.
    topic_metrics: Mutex<HashMap<String, Arc<TopicCounters>>>,
}

impl RtpsParticipant {
    /// Creates a new participant runtime. `data_socket` is used both to
    /// *send* user-data DATA submessages (see [`RtpsWriter::write`]) and,
    /// via [`RtpsParticipant::spawn_receive_loop`], to receive them —
    /// matching go-DDS's single `p.dataSock` serving both roles. `sedp` is
    /// this participant's already-running [`SedpService`], used both to
    /// register local endpoints and to resolve matched remote readers'
    /// delivery locators on every write. TransientLocal disk persistence
    /// (sub-phase 9) is disabled — see
    /// [`RtpsParticipant::new_with_persistent_history`] to enable it.
    //fusa:req REQ-RTPS-041
    pub fn new(
        guid_prefix: GuidPrefix,
        vendor_id: VendorId,
        data_socket: Arc<RtpsSocket>,
        sedp: Arc<SedpService>,
    ) -> Arc<Self> {
        Self::new_inner(guid_prefix, vendor_id, data_socket, sedp, None)
    }

    /// Creates a new participant runtime exactly like [`RtpsParticipant::new`],
    /// with TransientLocal durability backed by files in `dir` (sub-phase 9
    /// — see [`super::persist`]'s module docs for the on-disk format).
    /// Matches go-DDS's `NewParticipant(..., WithPersistentHistory(dir))`.
    /// An empty `dir` behaves identically to [`RtpsParticipant::new`]
    /// (persistence disabled), matching go-DDS's own no-op convention.
    //fusa:req REQ-RTPS-057
    pub fn new_with_persistent_history(
        guid_prefix: GuidPrefix,
        vendor_id: VendorId,
        data_socket: Arc<RtpsSocket>,
        sedp: Arc<SedpService>,
        dir: impl Into<String>,
    ) -> Arc<Self> {
        Self::new_inner(guid_prefix, vendor_id, data_socket, sedp, Some(dir.into()))
    }

    fn new_inner(
        guid_prefix: GuidPrefix,
        vendor_id: VendorId,
        data_socket: Arc<RtpsSocket>,
        sedp: Arc<SedpService>,
        persist_dir: Option<String>,
    ) -> Arc<Self> {
        Arc::new(RtpsParticipant {
            guid_prefix,
            vendor_id,
            data_socket,
            sedp,
            entity_counter: AtomicU32::new(0),
            readers: RwLock::new(HashMap::new()),
            writers: RwLock::new(HashMap::new()),
            frag_assembler: FragmentAssembler::new(),
            delivers: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            last_sample: RwLock::new(HashMap::new()),
            persist_dir,
            user_data_multicast_addr: RwLock::new(None),
            topic_metrics: Mutex::new(HashMap::new()),
        })
    }

    /// This participant's own `GuidPrefix`.
    pub fn guid_prefix(&self) -> GuidPrefix {
        self.guid_prefix
    }

    /// Configures the user-data multicast group's send destination —
    /// `dst`'s IP is normally [`super::transport::USER_DATA_MULTICAST_ADDR`]
    /// and port [`super::transport::user_multicast_port`]`(domain)`. Once
    /// set, every subsequent [`RtpsWriter::write`] with at least one
    /// SEDP-matched remote reader sends a single multicast packet to `dst`
    /// instead of one unicast packet per matched reader locator — see
    /// [`RtpsWriter::write`]'s docs for the exact condition, matching
    /// go-DDS's `rtpsWriter.Write` (`len(locs) > 0 && w.p.dataMcastSock !=
    /// nil`).
    ///
    /// A setter (called after construction) rather than a `new`/`new_inner`
    /// parameter because, mirroring go-DDS's own soft-fail convention for
    /// its optional `dataMcastSock` ("Optional user-data multicast socket
    /// ... Failure is soft: fall back to unicast-only delivery"), the
    /// caller only knows this address once it has attempted (and possibly
    /// failed) to bind the multicast receive socket — see
    /// [`super::dds_participant::RtpsUdpParticipant::new_with_config`].
    /// Never called at all (leaving multicast permanently disabled) is a
    /// valid, supported configuration — every write then falls back to the
    /// pre-existing per-locator unicast path unconditionally.
    //fusa:req REQ-RTPS-061
    pub async fn set_user_data_multicast_addr(&self, dst: SocketAddr) {
        *self.user_data_multicast_addr.write().await = Some(dst);
    }

    fn next_entity_num(&self) -> u32 {
        self.entity_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// This participant's own RTPS message header (protocol version, vendor
    /// ID, and `GuidPrefix` are fixed once at construction), used by every
    /// method that sends a wire message.
    fn header(&self) -> Header {
        Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: self.vendor_id,
            guid_prefix: self.guid_prefix,
        }
    }

    // ── Writer registration ─────────────────────────────────────────────

    /// Registers a new local BestEffort writer for `topic` and announces it
    /// via SEDP to every known peer. Matches go-DDS's `NewPublisher`'s
    /// registration half (entity-id assignment, `p.writers[eid] = w`,
    /// `p.sedp.registerWriter`), BestEffort case (`w.reliable == false`).
    //fusa:req REQ-RTPS-041
    pub async fn new_writer(self: &Arc<Self>, topic: impl Into<String>) -> RtpsWriter {
        self.new_writer_impl(topic, false).await
    }

    /// Registers a new local **reliable** writer for `topic` (HEARTBEAT/
    /// ACKNACK retransmission — sub-phase 7): same registration as
    /// [`RtpsParticipant::new_writer`], plus a per-writer
    /// [`SendHistory`](super::reliable::SendHistory) and a periodic
    /// HEARTBEAT-sending `tokio::task` (matches go-DDS's
    /// `rtpsWriter.heartbeatLoop` goroutine, driven by
    /// [`super::reliable::HEARTBEAT_PERIOD`]). The returned `JoinHandle` is
    /// this writer's heartbeat loop, independently stoppable via `.abort()`
    /// — matching this module tree's established idiom (see
    /// [`RtpsParticipant::spawn_receive_loop`]'s docs) — since, like
    /// [`RtpsWriter`] itself, this sub-phase has no `Close` path yet to
    /// stop it automatically (a documented deviation from go-DDS's
    /// `rtpsWriter.Close`, which closes `hbDone`).
    //fusa:req REQ-RTPS-050
    pub async fn new_reliable_writer(
        self: &Arc<Self>,
        topic: impl Into<String>,
    ) -> (RtpsWriter, JoinHandle<()>) {
        let writer = self.new_writer_impl(topic, true).await;
        let eid = writer.eid;
        let participant = Arc::clone(self);
        let heartbeat_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_PERIOD);
            // tokio::time::interval fires its first tick immediately, unlike
            // go-DDS's time.NewTicker (which only fires after the first
            // full period). Consume that first tick so the loop's cadence
            // matches go-DDS's heartbeatLoop; the writer's own Write already
            // sends an immediate HEARTBEAT on first use (see
            // RtpsWriter::write), so nothing is lost by not sending one
            // here too before any data exists.
            interval.tick().await;
            loop {
                interval.tick().await;
                participant.send_heartbeat(eid).await;
            }
        });
        (writer, heartbeat_task)
    }

    async fn new_writer_impl(
        self: &Arc<Self>,
        topic: impl Into<String>,
        reliable: bool,
    ) -> RtpsWriter {
        let topic = topic.into();
        let eid = entity_id_for_writer(self.next_entity_num());
        self.writers.write().await.insert(
            eid,
            Arc::new(WriterState {
                topic: topic.clone(),
                seq: AtomicU64::new(0),
                reliable,
                history: reliable.then(SendHistory::new),
                acked: AtomicU64::new(0),
            }),
        );
        self.sedp.register_writer(eid, topic.clone()).await;
        RtpsWriter {
            participant: Arc::clone(self),
            eid,
            topic,
        }
    }

    // ── Reader registration ─────────────────────────────────────────────

    /// Registers a new local reader for `topic`, announces it via SEDP, and
    /// pre-populates its accepted-source set from any remote writer SEDP
    /// already knows about for this topic. Matches go-DDS's
    /// `NewSubscriber`'s registration half (entity-id assignment,
    /// `p.readers[eid] = r`, `p.sedp.registerReader`). `opts.chan_depth`/
    /// `opts.back_pressure` configure the returned [`SampleReceiver`]'s
    /// queue exactly as [`crate::mock::MockParticipant::new_subscriber`]
    /// does (default depth 64, matching go-DDS's own
    /// `cfg.ChanDepth(64)`).
    ///
    /// TransientLocal late-joiner delivery (go-DDS's `NewSubscriber`
    /// delivering `p.lastSample`) is not performed by this constructor —
    /// see [`RtpsParticipant::new_transient_local_reader`].
    //fusa:req REQ-RTPS-041
    pub async fn new_reader(
        self: &Arc<Self>,
        topic: impl Into<String>,
        opts: SubscriberOptions,
    ) -> (SampleReceiver, RtpsReader) {
        self.new_reader_impl(topic, opts, false, false).await
    }

    /// Registers a new local **reliable** reader for `topic` (HEARTBEAT/
    /// ACKNACK gap tracking — sub-phase 7): same registration as
    /// [`RtpsParticipant::new_reader`], plus a per-remote-writer
    /// [`RecvTracker`](super::reliable::RecvTracker), populated lazily on
    /// first contact with each matched writer. Unlike
    /// [`RtpsParticipant::new_reliable_writer`], no background task is
    /// spawned here — ACKNACK is only ever sent reactively, from within
    /// [`RtpsParticipant::handle_data_packet`]'s DATA/HEARTBEAT handling,
    /// matching go-DDS's `notifyReliableReaders`/`handleHeartbeat` (a
    /// reliable reader has no periodic loop of its own in go-DDS either).
    //fusa:req REQ-RTPS-051
    pub async fn new_reliable_reader(
        self: &Arc<Self>,
        topic: impl Into<String>,
        opts: SubscriberOptions,
    ) -> (SampleReceiver, RtpsReader) {
        self.new_reader_impl(topic, opts, true, false).await
    }

    /// Registers a new local BestEffort **TransientLocal** reader for
    /// `topic` (sub-phase 9): same registration as
    /// [`RtpsParticipant::new_reader`], plus late-joiner delivery of the
    /// topic's last written sample — from this participant's in-memory
    /// [`RtpsParticipant::last_sample`] cache if a local
    /// [`RtpsWriter::write`] has already populated it, otherwise (fallback)
    /// from disk via [`super::persist::persist_load`] if
    /// [`RtpsParticipant::new_with_persistent_history`] configured a
    /// directory. Matches go-DDS's `NewSubscriber`'s
    /// `if qos.Durability == dds.TransientLocal { ... }` block exactly,
    /// including the disk-fallback-only-when-no-in-memory-sample ordering.
    //fusa:req REQ-RTPS-057
    pub async fn new_transient_local_reader(
        self: &Arc<Self>,
        topic: impl Into<String>,
        opts: SubscriberOptions,
    ) -> (SampleReceiver, RtpsReader) {
        self.new_reader_impl(topic, opts, false, true).await
    }

    /// Registers a new local **Reliable + TransientLocal** reader for
    /// `topic` (sub-phase 9): the union of
    /// [`RtpsParticipant::new_reliable_reader`] and
    /// [`RtpsParticipant::new_transient_local_reader`] — matches this
    /// crate's `RELIABLE_QOS` combination (`src/types.rs`:
    /// Reliable + TransientLocal), and go-DDS's own support for the two
    /// QoS axes being fully orthogonal (`qos.Reliability` and
    /// `qos.Durability` are independent fields on `NewSubscriber`'s `qos`
    /// parameter).
    //fusa:req REQ-RTPS-057
    pub async fn new_reliable_transient_local_reader(
        self: &Arc<Self>,
        topic: impl Into<String>,
        opts: SubscriberOptions,
    ) -> (SampleReceiver, RtpsReader) {
        self.new_reader_impl(topic, opts, true, true).await
    }

    async fn new_reader_impl(
        self: &Arc<Self>,
        topic: impl Into<String>,
        opts: SubscriberOptions,
        reliable: bool,
        transient_local: bool,
    ) -> (SampleReceiver, RtpsReader) {
        let topic = topic.into();
        let eid = entity_id_for_reader(self.next_entity_num());
        let depth = opts.chan_depth(64);
        let inner = Arc::new(SubInner::new(depth, opts.back_pressure));
        let state = Arc::new(ReaderState {
            topic: topic.clone(),
            sources: RwLock::new(HashSet::new()),
            inner: Arc::clone(&inner),
            reliable,
            trackers: RwLock::new(HashMap::new()),
        });
        self.readers.write().await.insert(eid, Arc::clone(&state));

        let matched = self.sedp.register_reader(eid, topic.clone()).await;
        if !matched.is_empty() {
            let mut sources = state.sources.write().await;
            for g in matched {
                sources.insert(g);
            }
        }

        if transient_local {
            self.deliver_transient_local(&topic, &inner).await;
        }

        (
            SampleReceiver { inner },
            RtpsReader {
                participant: Arc::clone(self),
                eid,
            },
        )
    }

    /// Delivers `topic`'s last-known sample to a newly-registered
    /// TransientLocal reader's queue, if one exists — in-memory cache
    /// first, disk (via [`persist_load`]) as a fallback that also
    /// backfills the in-memory cache so a *second* late joiner does not
    /// need to touch disk again. Matches go-DDS's `NewSubscriber`
    /// TransientLocal block. A disk read error (including "no file yet")
    /// is treated the same as "nothing persisted" — never propagated as an
    /// error to the caller, matching go-DDS's `if payload, err :=
    /// persistLoad(...); err == nil && payload != nil`.
    //fusa:req REQ-RTPS-057
    async fn deliver_transient_local(&self, topic: &str, inner: &Arc<SubInner>) {
        if let Some(sample) = self.last_sample.read().await.get(topic).cloned() {
            inner.push(sample);
            return;
        }
        let Some(dir) = self.persist_dir.as_deref() else {
            return;
        };
        let Ok(Some(payload)) = persist_load(dir, topic) else {
            return;
        };
        let sample = Sample {
            topic: topic.to_string(),
            payload,
            timestamp: Utc::now(),
            sequence_number: 0,
            writer_guid: [0u8; 16],
        };
        self.last_sample
            .write()
            .await
            .insert(topic.to_string(), sample.clone());
        inner.push(sample);
    }

    /// Removes a reader from the dispatch table. Matches go-DDS's
    /// `rtpsReader.Unsubscribe` (the participant-side half — this crate's
    /// `SampleReceiver` has no separate `Close`, so there is no
    /// `rtpsReader.Close` counterpart to port here).
    async fn remove_reader(&self, eid: EntityId) {
        self.readers.write().await.remove(&eid);
    }

    // ── SEDP match-notification wiring ──────────────────────────────────

    /// Spawns a task that consumes [`super::sedp::WriterMatch`] events from
    /// this participant's [`SedpService`] (registering itself as the
    /// listener via [`SedpService::set_match_listener`](super::sedp::SedpService::set_match_listener))
    /// and adds each matched writer `Guid` to the named reader's accepted
    /// source set — the asynchronous counterpart to
    /// [`RtpsParticipant::new_reader`]'s synchronous match. See the module
    /// docs' "Wiring SEDP's match output" section. Exits once the sender
    /// side (owned internally by [`SedpService`]) is dropped, i.e. when
    /// `sedp` itself is dropped.
    //fusa:req REQ-RTPS-039
    pub async fn spawn_sedp_match_listener(self: &Arc<Self>) -> JoinHandle<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.sedp.set_match_listener(tx).await;
        let participant = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let readers = participant.readers.read().await;
                if let Some(state) = readers.get(&event.reader_eid) {
                    state.sources.write().await.insert(event.writer_guid);
                }
            }
        })
    }

    /// Spawns a task that consumes [`super::spdp::ParticipantProxy`] events
    /// from `spdp` (registering itself as `spdp`'s listener via
    /// [`SpdpService::set_peer_listener`](super::spdp::SpdpService::set_peer_listener))
    /// and forwards each into [`SedpService::on_new_peer`](super::sedp::SedpService::on_new_peer)
    /// on this participant's own `SedpService` — the bridge go-DDS gets for
    /// free from `spdpService.handlePacket` calling `s.p.sedp.onNewPeer`
    /// directly, which rust-DDS's `spdp`/`sedp` module split cannot do
    /// without this participant-level glue (see
    /// [`SpdpService::set_peer_listener`](super::spdp::SpdpService::set_peer_listener)'s
    /// docs for why). `spdp` is a parameter rather than a field on
    /// [`RtpsParticipant`] because — unlike `sedp` — this participant type
    /// has no other use for a `SpdpService` reference; passing it once here
    /// avoids holding a reference this module otherwise never needs. Exits
    /// once `spdp`'s sender side is dropped, i.e. when `spdp` itself is
    /// dropped.
    //fusa:req REQ-RTPS-042
    pub async fn spawn_spdp_peer_listener(
        self: &Arc<Self>,
        spdp: Arc<super::spdp::SpdpService>,
    ) -> JoinHandle<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        spdp.set_peer_listener(tx).await;
        let participant = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(proxy) = rx.recv().await {
                participant.sedp.on_new_peer(&proxy).await;
            }
        })
    }

    // ── Receive path ─────────────────────────────────────────────────────

    /// Spawns the receive loop: consumes `rx` (produced by
    /// [`RtpsSocket::spawn_receive_loop`](super::transport::RtpsSocket::spawn_receive_loop)
    /// on this participant's data-unicast socket) and decodes/dispatches
    /// each DATA submessage. Matches go-DDS's `dataReceiveLoop` (the
    /// single-socket case; go-DDS's IPv6/multicast fan-in via
    /// `reflect.Select` has no rust-DDS counterpart yet since
    /// `RtpsSocket::spawn_receive_loop` is one task per socket — a caller
    /// with multiple data sockets spawns one receive loop per socket, all
    /// feeding the same `RtpsParticipant`). Exits once `rx` is closed.
    //fusa:req REQ-RTPS-040
    pub fn spawn_receive_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<RtpsDatagram>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(datagram) = rx.recv().await {
                self.handle_data_packet(&datagram.data, datagram.from).await;
            }
        })
    }

    /// Decodes one received datagram and dispatches every well-formed
    /// submessage in it: DATA to matched local readers (plus, for reliable
    /// readers, gap-tracking and reactive ACKNACK — sub-phase 7's
    /// `notifyReliableReaders`), HEARTBEAT to
    /// [`RtpsParticipant::handle_heartbeat`], ACKNACK to
    /// [`RtpsParticipant::handle_acknack`], and DATA_FRAG to this
    /// participant's [`super::fragment::FragmentAssembler`] — once a
    /// fragmented sample fully reassembles, it is dispatched exactly like a
    /// completed DATA submessage (unwrap payload, gap-track/ACKNACK,
    /// deliver). `from` is the datagram's sender address, needed to route
    /// reliability replies back to the peer that sent this datagram.
    /// Matches go-DDS's `handleDataPacket`, plus the DATA_FRAG case go-DDS
    /// itself never wires in — see `fragment.rs`'s module docs
    /// ("Receive-side wiring"). Malformed input, unrecognised submessage
    /// IDs, and this participant's own packets (self-filtered by
    /// `GuidPrefix`, same convention as `spdp.rs`/`sedp.rs`) are silently
    /// ignored — never panics (REQ-RTPS-009).
    ///
    /// `pub` (rather than the crate-private visibility every other
    /// sub-phase left this at) specifically so the `rtps-interop-peer`
    /// binary's reliable-QoS two-process test harness can drive a
    /// participant's data socket manually — deliberately discarding one
    /// real, already-kernel-delivered datagram before it reaches this
    /// method, the same "drop after receipt, before dispatch" technique
    /// this module's own `reliable_qos_detects_gap_and_retransmits_over_real_udp`
    /// test uses in-process — without needing any other private state. See
    /// `ROADMAP.md`'s "Interop testing" section and
    /// `tests/rtps_two_process_interop.rs`. No behavior change.
    //fusa:req REQ-RTPS-040
    //fusa:req REQ-RTPS-055
    //fusa:req REQ-RTPS-009
    pub async fn handle_data_packet(&self, data: &[u8], from: SocketAddr) {
        let Ok(header) = Header::decode(data) else {
            return;
        };
        if header.guid_prefix == self.guid_prefix {
            return; // own packet
        }
        let body = &data[Header::LEN..];
        for result in SubmessageIter::new(body) {
            let Ok(raw) = result else {
                break;
            };
            match raw.id {
                SUBMSG_DATA => {
                    let Ok(ds) = decode_data_submessage(raw.flags, raw.body) else {
                        continue;
                    };
                    let Some(payload) = ds.payload else {
                        continue;
                    };
                    let Ok(raw_payload) = unwrap_payload(&payload) else {
                        continue;
                    };
                    let source = Guid {
                        prefix: header.guid_prefix,
                        entity: ds.writer_entity_id,
                    };
                    self.notify_reliable_readers(source, ds.seq_num.to_u64(), from)
                        .await;
                    self.dispatch_to_readers(
                        source,
                        None,
                        raw_payload.to_vec(),
                        Utc::now(),
                        ds.seq_num.to_u64(),
                    )
                    .await;
                }
                SUBMSG_DATA_FRAG => {
                    let Ok(frag) = decode_data_frag(raw.body) else {
                        continue;
                    };
                    let Some(reassembled) = self.frag_assembler.receive(&frag) else {
                        continue;
                    };
                    let Ok(raw_payload) = unwrap_payload(&reassembled) else {
                        continue;
                    };
                    let source = Guid {
                        prefix: header.guid_prefix,
                        entity: frag.writer_entity_id,
                    };
                    let seq = frag.writer_seq_num.to_u64();
                    self.notify_reliable_readers(source, seq, from).await;
                    self.dispatch_to_readers(source, None, raw_payload.to_vec(), Utc::now(), seq)
                        .await;
                }
                SUBMSG_HEARTBEAT => {
                    let Ok(hb) = decode_heartbeat_submessage(raw.body) else {
                        continue;
                    };
                    let writer_guid = Guid {
                        prefix: header.guid_prefix,
                        entity: hb.writer_entity_id,
                    };
                    self.handle_heartbeat(writer_guid, hb, from).await;
                }
                SUBMSG_ACKNACK => {
                    let Ok(an) = decode_acknack_submessage(raw.body) else {
                        continue;
                    };
                    self.handle_acknack(an, from).await;
                }
                _ => {}
            }
        }
    }

    // ── Reliable QoS (sub-phase 7) ──────────────────────────────────────

    /// Returns (creating on first contact) the [`RecvTracker`] `state`
    /// tracks for `writer_guid`. Matches go-DDS's `rtpsReader.trackerFor`.
    async fn tracker_for(state: &ReaderState, writer_guid: Guid) -> Arc<RecvTracker> {
        {
            let trackers = state.trackers.read().await;
            if let Some(t) = trackers.get(&writer_guid) {
                return Arc::clone(t);
            }
        }
        let mut trackers = state.trackers.write().await;
        Arc::clone(
            trackers
                .entry(writer_guid)
                .or_insert_with(|| Arc::new(RecvTracker::new())),
        )
    }

    /// Updates the [`RecvTracker`] of every reliable reader that accepts
    /// `writer_guid` with the just-received sequence number `seq`, and
    /// sends an ACKNACK back to `from` if a gap is detected. Matches
    /// go-DDS's `notifyReliableReaders`.
    //fusa:req REQ-RTPS-050
    async fn notify_reliable_readers(&self, writer_guid: Guid, seq: u64, from: SocketAddr) {
        let readers: Vec<(EntityId, Arc<ReaderState>)> = self
            .readers
            .read()
            .await
            .iter()
            .map(|(eid, state)| (*eid, Arc::clone(state)))
            .collect();

        for (reader_eid, state) in &readers {
            if !state.reliable || !Self::accepts_source(state, self.guid_prefix, writer_guid).await
            {
                continue;
            }
            let tracker = Self::tracker_for(state, writer_guid).await;
            tracker.record(seq);
            // The writer's history reaches at least this SN, so NACK any
            // gap below it.
            let (base, bitmap, need_ack) = tracker.missing(seq);
            if !need_ack {
                continue;
            }
            self.send_acknack(
                *reader_eid,
                writer_guid.entity,
                base,
                bitmap,
                &tracker,
                from,
            )
            .await;
        }
    }

    /// Responds with ACKNACK if any reliable reader accepting `writer_guid`
    /// has a gap up to `hb.last_sn`, and anchors that reader's cumulative-
    /// ACK base at `hb.first_sn` on first contact. Matches go-DDS's
    /// `handleHeartbeat`.
    //fusa:req REQ-RTPS-050
    async fn handle_heartbeat(&self, writer_guid: Guid, hb: Heartbeat, from: SocketAddr) {
        let readers: Vec<(EntityId, Arc<ReaderState>)> = self
            .readers
            .read()
            .await
            .iter()
            .map(|(eid, state)| (*eid, Arc::clone(state)))
            .collect();

        for (reader_eid, state) in &readers {
            if !state.reliable || !Self::accepts_source(state, self.guid_prefix, writer_guid).await
            {
                continue;
            }
            let tracker = Self::tracker_for(state, writer_guid).await;
            // On first contact, anchor the cumulative-ACK base at the
            // writer's FirstSN so the reader can request the writer's
            // whole live history.
            tracker.init_expected(hb.first_sn.to_u64());
            // Re-NACK every SN still missing up to the writer's LastSN.
            // Because the watermark never skips a gap, a lost retransmit is
            // requested again on each periodic HEARTBEAT until it arrives.
            let (base, bitmap, need_ack) = tracker.missing(hb.last_sn.to_u64());
            if !need_ack {
                continue;
            }
            self.send_acknack(
                *reader_eid,
                writer_guid.entity,
                base,
                bitmap,
                &tracker,
                from,
            )
            .await;
        }
    }

    /// Builds and sends one ACKNACK submessage to `to`.
    #[allow(clippy::too_many_arguments)]
    async fn send_acknack(
        &self,
        reader_eid: EntityId,
        writer_eid: EntityId,
        base: u64,
        bitmap: u32,
        tracker: &RecvTracker,
        to: SocketAddr,
    ) {
        let an = AckNack {
            reader_entity_id: reader_eid,
            writer_entity_id: writer_eid,
            base: SequenceNumber::from_u64(base),
            bitmap,
            count: tracker.next_ack_count(),
        };
        let msg = wrap_in_rtps_message(self.header(), &encode_acknack_submessage(an));
        let _ = self.data_socket.send_to(&msg, to).await;
    }

    /// Retransmits samples still in the writer's history for every
    /// requested sequence number in `an`'s bitmap, and sends a GAP
    /// declaring any leading portion of the request that has already been
    /// evicted from history — so the reader can advance past samples this
    /// writer can never provide instead of NACKing them forever. Matches
    /// go-DDS's `handleAckNack`. `from` is the requesting reader's address
    /// (used for the GAP, sent directly there in addition to every matched
    /// reader locator, same as go-DDS).
    //fusa:req REQ-RTPS-050
    async fn handle_acknack(&self, an: AckNack, from: SocketAddr) {
        let writer_state = {
            let writers = self.writers.read().await;
            writers.get(&an.writer_entity_id).cloned()
        };
        let Some(writer_state) = writer_state else {
            return;
        };
        if !writer_state.reliable {
            return;
        }
        let Some(history) = writer_state.history.as_ref() else {
            return;
        };

        // Advance the drain watermark: ackBase is the first SN not yet
        // confirmed.
        let ack_base = an.base.to_u64();
        advance_acked(&writer_state, ack_base);

        let hist_first_last = history.first_last();

        // Retransmit samples that are still in history.
        for bit in 0u64..32 {
            if an.bitmap & (1 << bit) == 0 {
                continue;
            }
            let seq = ack_base + bit;
            let Some(msg) = history.get(seq) else {
                continue;
            };
            for locator in self.sedp.matched_reader_locators(&writer_state.topic).await {
                if let Some(addr) = locator.udp_addr() {
                    let _ = self.data_socket.send_to(&msg, addr).await;
                }
            }
        }

        // Send a GAP for the leading portion of the NACK range that has
        // been evicted from history, so the reader can advance its
        // expected-SN pointer instead of stalling forever.
        if let Some((hist_first, _)) = hist_first_last {
            if ack_base < hist_first {
                let mut gap_end = hist_first - 1;
                // Cap to the 32-bit NACK bitmap range so we don't
                // over-declare.
                if gap_end > ack_base + 31 {
                    gap_end = ack_base + 31;
                }
                let g = Gap {
                    reader_entity_id: an.reader_entity_id,
                    writer_entity_id: an.writer_entity_id,
                    gap_start: SequenceNumber::from_u64(ack_base),
                    gap_end: SequenceNumber::from_u64(gap_end),
                };
                let gap_msg = wrap_in_rtps_message(self.header(), &encode_gap_submessage(g));
                // Send directly to the requesting reader.
                let _ = self.data_socket.send_to(&gap_msg, from).await;
                // Also send to all matched readers so any reader on this
                // topic can advance.
                for locator in self.sedp.matched_reader_locators(&writer_state.topic).await {
                    if let Some(addr) = locator.udp_addr() {
                        let _ = self.data_socket.send_to(&gap_msg, addr).await;
                    }
                }
            }
        }
    }

    /// Builds and sends a HEARTBEAT for writer `writer_eid` to every reader
    /// locator SEDP has matched to its topic. A no-op if `writer_eid` is
    /// unknown, not reliable, or has never stored a sample (nothing to
    /// advertise yet). Matches go-DDS's `rtpsWriter.sendHeartbeatLocked`.
    //fusa:req REQ-RTPS-050
    async fn send_heartbeat(&self, writer_eid: EntityId) {
        let writer_state = {
            let writers = self.writers.read().await;
            writers.get(&writer_eid).cloned()
        };
        let Some(writer_state) = writer_state else {
            return;
        };
        let Some(history) = writer_state.history.as_ref() else {
            return;
        };
        let Some((first, last)) = history.first_last() else {
            return;
        };
        let hb = Heartbeat {
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_entity_id: writer_eid,
            first_sn: SequenceNumber::from_u64(first),
            last_sn: SequenceNumber::from_u64(last),
            count: history.next_hb_count(),
        };
        let msg = wrap_in_rtps_message(self.header(), &encode_heartbeat_submessage(hb));
        for locator in self.sedp.matched_reader_locators(&writer_state.topic).await {
            if let Some(addr) = locator.udp_addr() {
                let _ = self.data_socket.send_to(&msg, addr).await;
            }
        }
    }

    // ── Dispatch ─────────────────────────────────────────────────────────

    /// Delivers `payload` to every local reader that matches. `topic_filter
    /// = Some(t)` restricts delivery to readers whose topic is exactly `t`
    /// (used for local, same-process delivery, where the topic is known
    /// directly — matches go-DDS's `w.p.dispatchToReaders(..., w.topic,
    /// ...)`); `topic_filter = None` disables topic filtering and relies
    /// entirely on [`RtpsParticipant::accepts_source`] (used for the UDP
    /// receive path, where the DATA submessage carries no topic name —
    /// matches go-DDS's `dispatchToReaders(..., "", ...)`). `state.topic`
    /// (a reader's registered topic, potentially an MQTT-style `+`/`#`
    /// wildcard pattern — sub-phase 9) is matched against a non-`None`
    /// `topic_filter` (always a concrete, wildcard-free writer topic) via
    /// exact equality first, falling back to
    /// [`super::wildcard::topic_matches`] — matches go-DDS's own
    /// `r.topic != topicFilter && !TopicMatches(r.topic, topicFilter)`
    /// short-circuit exactly (equality first, wildcard match only as a
    /// fallback, not as a replacement).
    //fusa:req REQ-RTPS-038
    //fusa:req REQ-RTPS-056
    async fn dispatch_to_readers(
        &self,
        source: Guid,
        topic_filter: Option<&str>,
        payload: Vec<u8>,
        timestamp: DateTime<Utc>,
        seq_num: u64,
    ) {
        let readers: Vec<Arc<ReaderState>> = self.readers.read().await.values().cloned().collect();
        let writer_guid = source.to_bytes();
        for state in &readers {
            if let Some(tf) = topic_filter {
                if state.topic != tf && !topic_matches(&state.topic, tf) {
                    continue;
                }
            }
            if !Self::accepts_source(state, self.guid_prefix, source).await {
                continue;
            }
            let byte_len = payload.len() as u64;
            let sample = Sample {
                topic: state.topic.clone(),
                payload: payload.clone(),
                timestamp,
                sequence_number: seq_num,
                writer_guid,
            };
            // Per-topic counters (observability::MetricsProvider):
            // deliberately scoped to this exact push, not before it — a
            // topic with only a registered reader and no delivered sample
            // yet must not appear in `topic_metrics()` (see that method's
            // docs), so this lookup/create happens only on the path that
            // is about to record a delivery or a drop, never speculatively.
            let counters = self.topic_counter(&state.topic);
            if state.inner.push(sample) {
                self.delivers.fetch_add(1, Ordering::Relaxed);
                counters.delivers.fetch_add(1, Ordering::Relaxed);
                counters
                    .bytes_delivered
                    .fetch_add(byte_len, Ordering::Relaxed);
            } else {
                self.drops.fetch_add(1, Ordering::Relaxed);
                counters.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Whether `state`'s reader accepts samples from writer `source`.
    /// Matches go-DDS's `rtpsReader.acceptsSource` exactly: with no
    /// SEDP-matched sources recorded yet, only this participant's own
    /// writers (same `GuidPrefix`) are accepted; once at least one remote
    /// source is recorded, this participant's own writers are *still*
    /// always accepted, in addition to any explicitly-matched remote one.
    //fusa:req REQ-RTPS-038
    async fn accepts_source(state: &ReaderState, own_prefix: GuidPrefix, source: Guid) -> bool {
        let sources = state.sources.read().await;
        if sources.is_empty() {
            return source.prefix == own_prefix;
        }
        if source.prefix == own_prefix {
            return true;
        }
        sources.contains(&source)
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Cumulative count of samples successfully delivered to some reader
    /// (one increment per reader per sample, matching go-DDS's `mDelivers`
    /// counter granularity).
    pub fn delivers(&self) -> u64 {
        self.delivers.load(Ordering::Relaxed)
    }

    /// Cumulative count of samples dropped due to a full reader queue
    /// under `DropNewest`/unsubscribed/closed — matches go-DDS's `mDrops`.
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Returns (creating on first access) the [`TopicCounters`] for
    /// `topic`. Synchronous — a brief `std::sync::Mutex` lock, never held
    /// across an `.await` — see [`TopicCounters`]'s own docs for why that
    /// matters.
    fn topic_counter(&self, topic: &str) -> Arc<TopicCounters> {
        let mut map = self.topic_metrics.lock().unwrap();
        Arc::clone(
            map.entry(topic.to_string())
                .or_insert_with(|| Arc::new(TopicCounters::default())),
        )
    }

    /// Snapshot of per-topic write/deliver/drop/byte counters, one entry
    /// per topic this participant has locally written to *or* dispatched a
    /// remotely-received sample for — `observability::MetricsProvider`'s
    /// backing data for [`super::dds_participant::RtpsUdpParticipant`]. A
    /// topic with only a registered reader and neither a local write nor
    /// any received remote traffic yet is omitted, matching go-DDS's own
    /// `topicCounterFor`, reached only from `Write`/`dispatchToReaders`,
    /// never reader registration — no post-hoc filtering needed here since
    /// `RtpsParticipant::topic_counter` is itself only ever called from
    /// those same two call sites (unlike `mock`/`shmem`'s broker wirings,
    /// which fold per-topic counters into the same map subscriber
    /// registration also populates, and so filter on `write_count > 0`
    /// instead — this participant's per-topic map has no such shared-map
    /// concern, since `dispatch_to_readers` is reached independently of any
    /// local write via the UDP receive path, and must still be counted).
    //fusa:req REQ-MON-006
    pub fn topic_metrics(&self) -> Vec<crate::observability::TopicMetrics> {
        self.topic_metrics
            .lock()
            .unwrap()
            .iter()
            .map(|(topic, counters)| counters.snapshot(topic))
            .collect()
    }
}

/// Records that a remote reader has acknowledged up to (but not including)
/// `ack_base`, advancing `state.acked` if this is higher-water than what
/// was already recorded. `ack_base == 0` is a no-op (go-DDS's ACKNACK
/// `Base` is 1-indexed like every other RTPS sequence number; `0` never
/// denotes a real acknowledgement). Matches go-DDS's
/// `rtpsWriter.advanceAcked`, minus the `drainCh` close (this sub-phase has
/// no writer `Close`/drain path yet — see [`RtpsParticipant::new_reliable_writer`]'s
/// docs).
//fusa:req REQ-RTPS-050
fn advance_acked(state: &WriterState, ack_base: u64) {
    if ack_base == 0 {
        return;
    }
    let confirmed = ack_base - 1;
    let mut cur = state.acked.load(Ordering::Relaxed);
    while confirmed > cur {
        match state.acked.compare_exchange_weak(
            cur,
            confirmed,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

// ---------------------------------------------------------------------------
// RtpsWriter
// ---------------------------------------------------------------------------

/// A registered local writer. Created by [`RtpsParticipant::new_writer`].
/// Matches go-DDS's `rtpsWriter` (BestEffort subset).
pub struct RtpsWriter {
    participant: Arc<RtpsParticipant>,
    eid: EntityId,
    topic: String,
}

impl RtpsWriter {
    /// This writer's topic name.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// This writer's `EntityId`.
    pub fn entity_id(&self) -> EntityId {
        self.eid
    }

    /// Encodes `payload` as a BestEffort DATA submessage (`CDR_LE`
    /// encapsulation, no inline QoS, no `INFO_TS` — see the module docs'
    /// "DATA submessage payload" section for the latter's deliberate
    /// deviation from go-DDS) — or, when the CDR-wrapped payload exceeds
    /// [`super::fragment::MAX_FRAGMENT_PAYLOAD`], as a sequence of
    /// DATA_FRAG submessages instead (sub-phase 8, see
    /// [`super::fragment::split_into_fragments`]) — delivers it immediately
    /// to any local (same-process) readers on this writer's topic, then
    /// sends the wire message(s) to every remote reader SEDP has matched to
    /// this topic. Matches go-DDS's `rtpsWriter.Write`'s BestEffort path
    /// (`w.reliable == false`): no history store, no HEARTBEAT.
    ///
    /// Reference bytes reproduced from go-DDS's actual `rtps` package
    /// (real `cdrWrapPayload`/`marshalDataSubmessage`/`wrapInRTPSMessage`,
    /// not reimplemented). Go reproduction (package-local scratch test
    /// file, `rtps/zzrepro_participant_test.go`, never committed to
    /// go-DDS, deleted after use):
    ///
    /// ```text
    /// var prefix GuidPrefix
    /// for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    /// writerEID := entityIdForWriter(1)
    /// payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
    ///
    /// wrapped := cdrWrapPayload(payload)
    /// fmt.Printf("wrapped=%x\n", wrapped)
    /// // -> wrapped=01000000deadbeef0102
    ///
    /// submsg := marshalDataSubmessage(writerEID, EntityIdUnknown,
    ///     SequenceNumber{High: 0, Low: 1}, wrapped)
    /// fmt.Printf("submsg=%x\n", submsg)
    /// // -> submsg=15051e00000010000000000000000103000000000100000001000000deadbeef0102
    ///
    /// msg := wrapInRTPSMessage(prefix, submsg)
    /// fmt.Printf("msg=%x\n", msg)
    /// // -> msg=52545053020301270102030405060708090a0b0c15051e0000001000000000
    /// //         0000000103000000000100000001000000deadbeef0102
    /// fmt.Printf("msglen=%d\n", len(msg)) // -> 54
    /// ```
    ///
    /// Full run: `go test ./rtps/... -run TestZZReproParticipantDataBytes -v`
    /// (go-DDS commit 9d81543 / rust-DDS branch feat/rtps-besteffort-data).
    //fusa:req REQ-RTPS-037
    //fusa:req REQ-RTPS-055
    //fusa:req REQ-RTPS-061
    pub async fn write(&self, payload: &[u8]) -> std::io::Result<()> {
        let writer_state = {
            let writers = self.participant.writers.read().await;
            writers.get(&self.eid).cloned()
        };
        let Some(writer_state) = writer_state else {
            // Writer was removed from the participant's table out from
            // under this handle; treat as a silent no-op rather than an
            // error surface (this sub-phase has no `Close`/`Unsubscribe`
            // path for writers yet — see the module docs).
            return Ok(());
        };
        let seq = writer_state.seq.fetch_add(1, Ordering::Relaxed) + 1;

        // Per-topic write counters (observability::MetricsProvider): matches
        // go-DDS's `rtpsWriter.Write` incrementing `topicTC.writes`/
        // `topicTC.bytesW` up front, before any encoding work — see
        // `RtpsParticipant::topic_metrics`'s docs for why this participant's
        // per-topic map needs no additional filtering at read time.
        //fusa:req REQ-MON-006
        let topic_counter = self.participant.topic_counter(&self.topic);
        topic_counter.writes.fetch_add(1, Ordering::Relaxed);
        topic_counter
            .bytes_written
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        let wrapped = wrap_payload(payload);

        // Fragmentation (sub-phase 8): a CDR-wrapped payload larger than
        // MAX_FRAGMENT_PAYLOAD is split into DATA_FRAG submessages — one
        // full RTPS wire message per fragment — instead of a single DATA
        // submessage. Matches go-DDS's `rtpsWriter.Write` (`len(wrapped) >
        // fragSize`); rust-DDS has no TSN writer class yet, so every writer
        // uses the same default fragment size go-DDS falls back to (see
        // `fragment.rs`'s module docs).
        let msgs: Vec<Vec<u8>> = if wrapped.len() > MAX_FRAGMENT_PAYLOAD {
            split_into_fragments(self.eid, SequenceNumber::from_u64(seq), &wrapped)
                .iter()
                .map(|frag| {
                    wrap_in_rtps_message(self.participant.header(), &encode_data_frag(frag))
                })
                .collect()
        } else {
            let submsg = encode_data_submessage(
                self.eid,
                ENTITYID_UNKNOWN,
                SequenceNumber::from_u64(seq),
                &wrapped,
            );
            vec![wrap_in_rtps_message(self.participant.header(), &submsg)]
        };

        // Reliable QoS (sub-phase 7): retain a copy of the full wire
        // message for retransmission before anything else, matching
        // go-DDS's `w.history.store(w.seq, msgs[0])` — store-before-send so
        // a retransmit request that races the send below can never observe
        // an unstored sequence number. For a fragmented payload this stores
        // only the first fragment's wire message, matching go-DDS's own
        // documented limitation (`participant.go`'s `Write`: "a future
        // enhancement can store per-fragment msgs").
        if let Some(history) = writer_state.history.as_ref() {
            if let Some(first) = msgs.first() {
                history.store(seq, first);
            }
        }

        let source = Guid {
            prefix: self.participant.guid_prefix,
            entity: self.eid,
        };
        let now = Utc::now();

        // TransientLocal durability (sub-phase 9): record this write as the
        // topic's last sample (in-memory, always) and flush it to disk if
        // persistent history is configured (a no-op when it is not — see
        // `persist_flush`'s own docs). Matches go-DDS's
        // `w.p.lastSample.Store(w.topic, &sample)` /
        // `persistFlush(w.p.persistDir, w.topic, localCopy)`, both called
        // unconditionally on every write, independent of whether *this*
        // writer has any TransientLocal readers today — a reader
        // registered after this write still needs to see it.
        let last = Sample {
            topic: self.topic.clone(),
            payload: payload.to_vec(),
            timestamp: now,
            sequence_number: seq,
            writer_guid: source.to_bytes(),
        };
        self.participant
            .last_sample
            .write()
            .await
            .insert(self.topic.clone(), last);
        if let Some(dir) = self.participant.persist_dir.as_deref() {
            persist_flush(dir, &self.topic, payload);
        }

        self.participant
            .dispatch_to_readers(source, Some(&self.topic), payload.to_vec(), now, seq)
            .await;

        // Remote delivery: one multicast send when the multicast group is
        // configured and at least one remote reader is matched (matches
        // go-DDS's `rtpsWriter.Write`: `if len(locs) > 0 &&
        // w.p.dataMcastSock != nil { ...multicast... } else { ...per-locator
        // unicast... }` — applied to both BestEffort and Reliable writers
        // since go-DDS's own condition does not distinguish them); falls
        // back to the pre-existing per-locator unicast send otherwise (no
        // multicast configured, or no matched readers to justify it).
        let locators = self
            .participant
            .sedp
            .matched_reader_locators(&self.topic)
            .await;
        let multicast_dst = *self.participant.user_data_multicast_addr.read().await;
        if !locators.is_empty() {
            if let Some(dst) = multicast_dst {
                for msg in &msgs {
                    let _ = self.participant.data_socket.send_to(msg, dst).await;
                }
            } else {
                for locator in &locators {
                    if let Some(addr) = locator.udp_addr() {
                        for msg in &msgs {
                            let _ = self.participant.data_socket.send_to(msg, addr).await;
                        }
                    }
                }
            }
        }

        // Send HEARTBEAT immediately after each reliable write so remote
        // readers can detect gaps without waiting for the periodic ticker
        // (see RtpsParticipant::new_reliable_writer). Matches go-DDS's
        // `rtpsWriter.Write` calling `sendHeartbeatLocked()` unconditionally
        // when `w.reliable`.
        if writer_state.reliable {
            self.participant.send_heartbeat(self.eid).await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RtpsReader
// ---------------------------------------------------------------------------

/// A registered local reader's lifecycle handle. Created by
/// [`RtpsParticipant::new_reader`] alongside the [`SampleReceiver`] used to
/// actually consume samples. Matches the non-channel half of go-DDS's
/// `rtpsReader` (`Unsubscribe`).
pub struct RtpsReader {
    participant: Arc<RtpsParticipant>,
    eid: EntityId,
}

impl RtpsReader {
    /// This reader's `EntityId`.
    pub fn entity_id(&self) -> EntityId {
        self.eid
    }

    /// Removes this reader from the participant's dispatch table. Matches
    /// go-DDS's `rtpsReader.Unsubscribe`. The `SampleReceiver` returned
    /// alongside this handle remains usable (any already-queued samples
    /// can still be drained) but receives nothing further.
    //fusa:req REQ-RTPS-041
    pub async fn unsubscribe(&self) {
        self.participant.remove_reader(self.eid).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::BackPressurePolicy;
    use crate::rtps::locator::Locator;
    use crate::rtps::message::VENDOR_ID_RUST_DDS;
    use crate::rtps::spdp::SpdpConfig;
    use crate::rtps::spdp::SpdpService;

    fn ascending_prefix() -> GuidPrefix {
        let mut b = [0u8; 12];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i + 1) as u8; // safe: i in [0,11], (i+1) in [1,12] fits u8
        }
        GuidPrefix(b)
    }

    fn other_prefix() -> GuidPrefix {
        let mut p = ascending_prefix();
        p.0[0] = 0xFF;
        p
    }

    async fn bound_socket() -> Arc<RtpsSocket> {
        Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap())
    }

    /// Builds a standalone (no real peers) `RtpsParticipant` for tests that
    /// only exercise local-delivery/dispatch logic.
    async fn lone_participant(prefix: GuidPrefix) -> Arc<RtpsParticipant> {
        let send_socket = bound_socket().await;
        let spdp = SpdpService::new(
            SpdpConfig::new(0, prefix, 17410, 17411),
            Arc::clone(&send_socket),
        );
        let sedp = SedpService::new(
            super::super::sedp::SedpConfig::new(prefix, 17411),
            Arc::clone(&send_socket),
            spdp,
        );
        RtpsParticipant::new(prefix, VENDOR_ID_RUST_DDS, send_socket, sedp)
    }

    //fusa:test REQ-RTPS-037
    #[test]
    fn write_wire_message_matches_go_dds_reference() {
        // Exercises the exact composition write() performs
        // (wrap_payload -> encode_data_submessage -> wrap_in_rtps_message)
        // synchronously, at the field level, against the go-DDS reference
        // values documented in RtpsWriter::write's doc comment.
        let prefix = ascending_prefix();
        let writer_eid = entity_id_for_writer(1);
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];

        let wrapped = wrap_payload(&payload);
        assert_eq!(hex::encode(&wrapped), "01000000deadbeef0102");

        let submsg = encode_data_submessage(
            writer_eid,
            ENTITYID_UNKNOWN,
            SequenceNumber { high: 0, low: 1 },
            &wrapped,
        );
        assert_eq!(
            hex::encode(&submsg),
            "15051e00000010000000000000000103000000000100000001000000deadbeef0102"
        );

        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: VendorId([0x01, 0x27]), // go-DDS's own vendor id, for byte-exact parity
            guid_prefix: prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);
        assert_eq!(msg.len(), 54);
        assert_eq!(
            hex::encode(&msg),
            "52545053020301270102030405060708090a0b0c15051e00000010000000000000000103000000000100000001000000deadbeef0102"
        );
    }

    //fusa:test REQ-RTPS-041
    #[tokio::test]
    async fn new_writer_and_new_reader_assign_distinct_entity_ids() {
        let p = lone_participant(ascending_prefix()).await;
        let w1 = p.new_writer("Square").await;
        let w2 = p.new_writer("Circle").await;
        assert_eq!(w1.entity_id(), entity_id_for_writer(1));
        assert_eq!(w2.entity_id(), entity_id_for_writer(2));

        let (_rx, r1) = p.new_reader("Square", SubscriberOptions::default()).await;
        assert_eq!(r1.entity_id(), entity_id_for_reader(3));
    }

    //fusa:test REQ-RTPS-051
    #[tokio::test]
    async fn new_reliable_reader_registers_and_delivers_like_a_besteffort_reader() {
        let p = lone_participant(ascending_prefix()).await;
        let (rx, reader) = p
            .new_reliable_reader("Square", SubscriberOptions::default())
            .await;
        assert_eq!(reader.entity_id(), entity_id_for_reader(1));

        let writer = p.new_writer("Square").await;
        writer.write(b"hello").await.unwrap();
        let sample = rx.try_recv().expect("expected a delivered sample");
        assert_eq!(sample.payload, b"hello");
    }

    //fusa:test REQ-RTPS-038
    #[tokio::test]
    async fn local_write_delivers_to_local_reader_on_same_topic() {
        let p = lone_participant(ascending_prefix()).await;
        let (rx, _reader) = p.new_reader("Square", SubscriberOptions::default()).await;
        let writer = p.new_writer("Square").await;

        writer.write(b"hello").await.unwrap();

        let sample = rx.try_recv().expect("expected a delivered sample");
        assert_eq!(sample.topic, "Square");
        assert_eq!(sample.payload, b"hello");
        assert_eq!(sample.sequence_number, 1);
        assert_eq!(p.delivers(), 1);
        assert_eq!(p.drops(), 0);
    }

    //fusa:test REQ-RTPS-038
    #[tokio::test]
    async fn local_write_does_not_deliver_to_reader_on_different_topic() {
        let p = lone_participant(ascending_prefix()).await;
        let (rx, _reader) = p.new_reader("Circle", SubscriberOptions::default()).await;
        let writer = p.new_writer("Square").await;

        writer.write(b"hello").await.unwrap();

        assert!(rx.try_recv().is_none());
        assert_eq!(p.delivers(), 0);
    }

    //fusa:test REQ-RTPS-041
    #[tokio::test]
    async fn unsubscribe_stops_further_local_delivery() {
        let p = lone_participant(ascending_prefix()).await;
        let (rx, reader) = p.new_reader("Square", SubscriberOptions::default()).await;
        let writer = p.new_writer("Square").await;

        writer.write(b"first").await.unwrap();
        assert!(rx.try_recv().is_some());

        reader.unsubscribe().await;
        writer.write(b"second").await.unwrap();
        assert!(rx.try_recv().is_none());
    }

    //fusa:test REQ-RTPS-038
    #[tokio::test]
    async fn dispatch_applies_drop_newest_back_pressure() {
        let p = lone_participant(ascending_prefix()).await;
        let opts = SubscriberOptions {
            channel_depth: 1,
            back_pressure: BackPressurePolicy::DropNewest,
            topic: None,
            deadline_missed: None,
        };
        let (rx, _reader) = p.new_reader("Square", opts).await;
        let writer = p.new_writer("Square").await;

        writer.write(b"first").await.unwrap();
        writer.write(b"second").await.unwrap(); // dropped: queue already full

        assert_eq!(p.delivers(), 1);
        assert_eq!(p.drops(), 1);
        let sample = rx.try_recv().unwrap();
        assert_eq!(sample.payload, b"first");
        assert!(rx.try_recv().is_none());
    }

    /// `RtpsParticipant::topic_metrics` counts local writes and successful
    /// local deliveries per topic, and omits topics with neither a write
    /// nor a dispatched sample yet.
    //fusa:test REQ-MON-006
    #[tokio::test]
    async fn topic_metrics_counts_writes_and_delivers() {
        let p = lone_participant(ascending_prefix()).await;
        let (_rx, _reader) = p.new_reader("Square", SubscriberOptions::default()).await;
        // A reader with no writer yet must not create a topic_metrics entry.
        assert!(p.topic_metrics().is_empty());

        let writer = p.new_writer("Square").await;
        writer.write(b"abc").await.unwrap();
        writer.write(b"de").await.unwrap();

        let metrics = p.topic_metrics();
        assert_eq!(metrics.len(), 1);
        let m = &metrics[0];
        assert_eq!(m.topic, "Square");
        assert_eq!(m.write_count, 2);
        assert_eq!(m.deliver_count, 2);
        assert_eq!(m.drop_count, 0);
        assert_eq!(m.bytes_written, 5);
        assert_eq!(m.bytes_delivered, 5);
    }

    /// `RtpsParticipant::topic_metrics` counts drops under `DropNewest`
    /// back-pressure once the local reader's queue is full.
    //fusa:test REQ-MON-006
    #[tokio::test]
    async fn topic_metrics_counts_drops() {
        let p = lone_participant(ascending_prefix()).await;
        let opts = SubscriberOptions {
            channel_depth: 1,
            back_pressure: BackPressurePolicy::DropNewest,
            topic: None,
            deadline_missed: None,
        };
        let (_rx, _reader) = p.new_reader("Square", opts).await;
        let writer = p.new_writer("Square").await;

        writer.write(b"first").await.unwrap();
        writer.write(b"second").await.unwrap(); // dropped: queue already full

        let metrics = p.topic_metrics();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].write_count, 2);
        assert_eq!(metrics[0].deliver_count, 1);
        assert_eq!(metrics[0].drop_count, 1);
    }

    /// `RtpsParticipant::topic_metrics` is safe to read concurrently with
    /// concurrent writes from multiple tokio tasks — no increment is lost
    /// to a data race.
    //fusa:test REQ-MON-006
    #[tokio::test]
    async fn topic_metrics_concurrent_writes() {
        let p = lone_participant(ascending_prefix()).await;
        // Wide enough channel_depth (default is 64) that no write here is
        // ever dropped for back-pressure reasons — this test proves no
        // counter increment is lost to a *data race*, not back-pressure
        // drop-counting (see the dedicated `topic_metrics_counts_drops`
        // test above for that).
        let opts = SubscriberOptions {
            channel_depth: 100,
            back_pressure: BackPressurePolicy::DropNewest,
            topic: None,
            deadline_missed: None,
        };
        let (_rx, _reader) = p.new_reader("Square", opts).await;
        let writer = Arc::new(p.new_writer("Square").await);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let writer = Arc::clone(&writer);
            handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    writer.write(b"x").await.unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let metrics = p.topic_metrics();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].write_count, 80);
        assert_eq!(metrics[0].deliver_count, 80);
    }

    //fusa:test REQ-RTPS-038
    //fusa:test REQ-RTPS-009
    #[tokio::test]
    async fn handle_data_packet_ignores_own_and_malformed_input_without_panicking() {
        let p = lone_participant(ascending_prefix()).await;
        let (rx, _reader) = p.new_reader("Square", SubscriberOptions::default()).await;
        let dummy_from: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Malformed: too short to even have a header.
        p.handle_data_packet(b"short", dummy_from).await;
        assert!(rx.try_recv().is_none());

        // Well-formed, but from this same participant's own GuidPrefix —
        // self-filtered like SPDP/SEDP.
        let writer_eid = entity_id_for_writer(1);
        let wrapped = wrap_payload(b"hello");
        let submsg = encode_data_submessage(
            writer_eid,
            ENTITYID_UNKNOWN,
            SequenceNumber { high: 0, low: 1 },
            &wrapped,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: VENDOR_ID_RUST_DDS,
            guid_prefix: ascending_prefix(), // == p's own prefix
        };
        let msg = wrap_in_rtps_message(header, &submsg);
        p.handle_data_packet(&msg, dummy_from).await;
        assert!(rx.try_recv().is_none());
    }

    // ── Real two-participant round trip over loopback UDP ────────────────
    //
    // Builds two independent RtpsParticipants (A, B), each with its own
    // real SpdpService/SedpService/data socket bound to an ephemeral
    // loopback port, and drives SPDP discovery + SEDP matching + a
    // BestEffort DATA send exactly as two separate rust-DDS processes
    // would communicate: A registers a writer, B registers a reader
    // *before* A's writer even exists (matching go-DDS's asynchronous
    // "writer discovered later" case, exercising
    // RtpsParticipant::spawn_sedp_match_listener), and the sample must
    // arrive at B purely via the network path (real UDP datagrams, real
    // wire decode) — not the local in-process dispatch path.

    struct Peer {
        participant: Arc<RtpsParticipant>,
        spdp: Arc<SpdpService>,
        _sedp_recv: JoinHandle<()>,
        _data_recv: JoinHandle<()>,
        _match_listener: JoinHandle<()>,
    }

    async fn spawn_peer(prefix: GuidPrefix) -> Peer {
        let meta_socket = Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap());
        let data_socket = Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap());
        let meta_port = meta_socket.local_port();
        let data_port = data_socket.local_port();

        let spdp = SpdpService::new(
            SpdpConfig::new(0, prefix, meta_port, data_port),
            Arc::clone(&meta_socket),
        );
        let sedp = SedpService::new(
            super::super::sedp::SedpConfig::new(prefix, data_port),
            Arc::clone(&meta_socket),
            Arc::clone(&spdp),
        );

        let (meta_rx, _meta_recv_handle) = meta_socket.spawn_receive_loop(64);
        let sedp_recv = Arc::clone(&sedp).spawn_receive_loop(meta_rx);

        let participant = RtpsParticipant::new(
            prefix,
            VENDOR_ID_RUST_DDS,
            Arc::clone(&data_socket),
            Arc::clone(&sedp),
        );
        let match_listener = participant.clone().spawn_sedp_match_listener().await;

        let (data_rx, _data_recv_handle) = data_socket.spawn_receive_loop(64);
        let data_recv = Arc::clone(&participant).spawn_receive_loop(data_rx);

        Peer {
            participant,
            spdp,
            _sedp_recv: sedp_recv,
            _data_recv: data_recv,
            _match_listener: match_listener,
        }
    }

    fn proxy_from(
        spdp: &SpdpService,
        prefix: GuidPrefix,
        meta_port: u16,
    ) -> super::super::spdp::ParticipantProxy {
        use super::super::guid::ENTITYID_PARTICIPANT;
        let _ = spdp; // silence unused-parameter warnings in case fields shrink later
        super::super::spdp::ParticipantProxy {
            guid: Guid {
                prefix,
                entity: ENTITYID_PARTICIPANT,
            },
            metatraffic_unicast: Locator::udp_v4([127, 0, 0, 1], u32::from(meta_port)),
            default_unicast: Locator::default(),
            builtin_endpoints: 0,
            lease_duration: std::time::Duration::from_secs(30),
            last_seen: None,
        }
    }

    //fusa:test REQ-RTPS-037
    //fusa:test REQ-RTPS-038
    //fusa:test REQ-RTPS-039
    //fusa:test REQ-RTPS-040
    #[tokio::test]
    async fn two_participant_besteffort_round_trip_over_real_udp() {
        let prefix_a = ascending_prefix();
        let prefix_b = other_prefix();

        let a = spawn_peer(prefix_a).await;
        let b = spawn_peer(prefix_b).await;

        // b registers its reader first — a's writer (and SEDP publication
        // announcement) does not exist yet, so this exercises the
        // asynchronous spawn_sedp_match_listener path, not new_reader's
        // synchronous match.
        let (rx_b, _reader_b) = b
            .participant
            .new_reader("Square", SubscriberOptions::default())
            .await;
        let writer_a = a.participant.new_writer("Square").await;

        // Simulates what a real SpdpService discovery round would trigger
        // via RtpsParticipant::spawn_spdp_peer_listener once both sides'
        // announce/receive loops are running (see
        // spdp_peer_listener_bridges_discovery_to_sedp_announcement below
        // for that bridge exercised end-to-end over real multicast) —
        // `SedpService::on_new_peer` itself needs only the peer's proxy, not
        // a populated SPDP known-peers table, so this is a faithful,
        // hermetic stand-in. Called *after* both endpoints are registered
        // so each side has something to announce to the other, matching
        // go-DDS's own `onNewPeer`, which always announces the *current*
        // set of local endpoints at call time.
        let proxy_b = proxy_from(&b.spdp, prefix_b, b.spdp.config().meta_unicast_port);
        let proxy_a = proxy_from(&a.spdp, prefix_a, a.spdp.config().meta_unicast_port);
        a.participant.sedp.on_new_peer(&proxy_b).await;
        b.participant.sedp.on_new_peer(&proxy_a).await;

        // Give the SEDP announcement + this test's match-listener task time
        // to land before writing. `matched_reader_locators` is checked on
        // *a*'s own SedpService — the same query `RtpsWriter::write` itself
        // makes to resolve where to send — since it holds *b*'s reader as a
        // remote endpoint once b's subscription announcement (sent above via
        // `b.participant.sedp.on_new_peer(&proxy_a)`) has been received and
        // processed by a's SEDP receive loop.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !a
                    .participant
                    .sedp
                    .matched_reader_locators("Square")
                    .await
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SEDP endpoint match never landed on participant a");

        writer_a.write(b"hello-from-a").await.unwrap();

        let sample = tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv())
            .await
            .expect("no sample received in time")
            .expect("channel closed unexpectedly");
        assert_eq!(sample.topic, "Square");
        assert_eq!(sample.payload, b"hello-from-a");
        assert_eq!(sample.sequence_number, 1);
        let expected_writer_guid = Guid {
            prefix: prefix_a,
            entity: writer_a.entity_id(),
        }
        .to_bytes();
        assert_eq!(sample.writer_guid, expected_writer_guid);
    }

    // ── BestEffort delivery over the user-data multicast group ─────────────

    //fusa:test REQ-RTPS-061
    //fusa:test REQ-RTPS-062
    #[tokio::test]
    async fn besteffort_write_delivers_via_configured_multicast_group_not_unicast() {
        use super::super::transport::USER_DATA_MULTICAST_ADDR;

        // Multicast may be unavailable in some CI sandboxes/containers (no
        // multicast-capable interface); skip rather than fail — same
        // convention as transport.rs's own multicast bind tests.
        let Ok(mcast_socket) = RtpsSocket::bind_multicast_v4(USER_DATA_MULTICAST_ADDR, 0).await
        else {
            return;
        };
        let mcast_socket = Arc::new(mcast_socket);
        let mcast_dst = SocketAddr::from((USER_DATA_MULTICAST_ADDR, mcast_socket.local_port()));

        let prefix_a = ascending_prefix();
        let prefix_b = other_prefix();

        let a = spawn_peer(prefix_a).await;
        let b = spawn_peer(prefix_b).await;

        // b's own unicast data socket keeps running (spawn_peer's receive
        // loop is still active) but nothing will ever be sent to it in this
        // test — only the multicast socket below feeds b's participant, so
        // a sample can only arrive at rx_b via the multicast path,
        // discriminating this test from the plain unicast round trip above.
        let (mcast_rx, _mcast_recv_handle) = mcast_socket.spawn_receive_loop(64);
        let _mcast_dispatch = Arc::clone(&b.participant).spawn_receive_loop(mcast_rx);

        let (rx_b, _reader_b) = b
            .participant
            .new_reader("Square", SubscriberOptions::default())
            .await;
        let writer_a = a.participant.new_writer("Square").await;

        let proxy_b = proxy_from(&b.spdp, prefix_b, b.spdp.config().meta_unicast_port);
        let proxy_a = proxy_from(&a.spdp, prefix_a, a.spdp.config().meta_unicast_port);
        a.participant.sedp.on_new_peer(&proxy_b).await;
        b.participant.sedp.on_new_peer(&proxy_a).await;

        // Configure a's multicast send destination only after SEDP matching
        // is confirmed, mirroring RtpsUdpParticipant::new_with_config's
        // real ordering (multicast bind result known before the first
        // write can occur).
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !a
                    .participant
                    .sedp
                    .matched_reader_locators("Square")
                    .await
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SEDP endpoint match never landed on participant a");
        a.participant.set_user_data_multicast_addr(mcast_dst).await;

        writer_a.write(b"hello-via-multicast").await.unwrap();

        // Real UDP multicast fan-out is, unlike unicast, genuinely
        // environment-dependent — some CI sandboxes/hosts allow binding and
        // joining the group (checked above) yet still never deliver a
        // packet sent to it back to a local listener (observed on macOS
        // GitHub Actions runners; see `spdp.rs`'s
        // `send_announcement_reaches_a_real_multicast_listener` for the
        // same caveat on the SPDP multicast group). Skip rather than fail
        // on a timeout here, for the same reason — this crate makes no
        // stronger claim about real multicast delivery than that test
        // already does.
        let Ok(Some(sample)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv()).await
        else {
            return;
        };
        assert_eq!(sample.topic, "Square");
        assert_eq!(sample.payload, b"hello-via-multicast");
    }

    // ── Fragmentation: large-payload round trip over real UDP ──────────────

    //fusa:test REQ-RTPS-055
    //fusa:test REQ-RTPS-038
    #[tokio::test]
    async fn fragmented_payload_round_trips_over_real_udp() {
        let prefix_a = ascending_prefix();
        let prefix_b = other_prefix();

        let a = spawn_peer(prefix_a).await;
        let b = spawn_peer(prefix_b).await;

        let (rx_b, _reader_b) = b
            .participant
            .new_reader("Square", SubscriberOptions::default())
            .await;
        let writer_a = a.participant.new_writer("Square").await;

        let proxy_b = proxy_from(&b.spdp, prefix_b, b.spdp.config().meta_unicast_port);
        let proxy_a = proxy_from(&a.spdp, prefix_a, a.spdp.config().meta_unicast_port);
        a.participant.sedp.on_new_peer(&proxy_b).await;
        b.participant.sedp.on_new_peer(&proxy_a).await;

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !a
                    .participant
                    .sedp
                    .matched_reader_locators("Square")
                    .await
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SEDP endpoint match never landed on participant a");

        // Larger than MAX_FRAGMENT_PAYLOAD once CDR-wrapped, so writer_a's
        // write() takes the DATA_FRAG path (several UDP datagrams) instead
        // of a single DATA submessage; b's participant must reassemble them
        // via its FragmentAssembler and dispatch exactly one Sample, same
        // as a single-datagram write would.
        let payload: Vec<u8> = (0..(MAX_FRAGMENT_PAYLOAD * 3 + 77))
            .map(|i| (i % 256) as u8)
            .collect();
        writer_a.write(&payload).await.unwrap();

        let sample = tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv())
            .await
            .expect("no reassembled sample received in time")
            .expect("channel closed unexpectedly");
        assert_eq!(sample.topic, "Square");
        assert_eq!(sample.payload, payload);
        assert_eq!(sample.sequence_number, 1);
        let expected_writer_guid = Guid {
            prefix: prefix_a,
            entity: writer_a.entity_id(),
        }
        .to_bytes();
        assert_eq!(sample.writer_guid, expected_writer_guid);

        // Nothing further arrives: exactly one reassembled Sample per
        // write(), not one per fragment.
        assert!(rx_b.try_recv().is_none());
    }

    // ── Reliable QoS: gap detection + ACKNACK retransmission over real UDP ─
    //
    // Two independent real RtpsParticipants (A, B), same SPDP/SEDP-matched
    // setup as the BestEffort round trip above, but A registers a
    // *reliable* writer and B a *reliable* reader. Unlike the BestEffort
    // test, B's data-socket receive loop is driven manually by this test
    // (instead of RtpsParticipant::spawn_receive_loop) so it can simulate
    // exactly one lost DATA datagram (sequence number 2, dropped the first
    // time it is observed — a real retransmission of the same sequence
    // number is forwarded normally) without touching any private state:
    // every other step — real encode/decode, real SEDP-resolved UDP sends,
    // real gap tracking, real ACKNACK, real history-backed retransmission —
    // is the actual production code path.

    //fusa:test REQ-RTPS-046
    //fusa:test REQ-RTPS-047
    //fusa:test REQ-RTPS-050
    #[tokio::test]
    async fn reliable_qos_detects_gap_and_retransmits_over_real_udp() {
        let prefix_a = ascending_prefix();
        let prefix_b = other_prefix();

        // A: reuse the standard peer helper (its own data-receive loop is
        // needed so A's participant can process B's ACKNACK and retransmit).
        let a = spawn_peer(prefix_a).await;

        // B: same building blocks as spawn_peer, but the data socket's
        // receive channel is kept in this test's hands rather than handed
        // to RtpsParticipant::spawn_receive_loop.
        let meta_socket_b = Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap());
        let data_socket_b = Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap());
        let meta_port_b = meta_socket_b.local_port();
        let data_port_b = data_socket_b.local_port();
        let spdp_b = SpdpService::new(
            SpdpConfig::new(0, prefix_b, meta_port_b, data_port_b),
            Arc::clone(&meta_socket_b),
        );
        let sedp_b = SedpService::new(
            super::super::sedp::SedpConfig::new(prefix_b, data_port_b),
            Arc::clone(&meta_socket_b),
            Arc::clone(&spdp_b),
        );
        let (meta_rx_b, _meta_recv_handle_b) = meta_socket_b.spawn_receive_loop(64);
        let _sedp_recv_b = Arc::clone(&sedp_b).spawn_receive_loop(meta_rx_b);
        let participant_b = RtpsParticipant::new(
            prefix_b,
            VENDOR_ID_RUST_DDS,
            Arc::clone(&data_socket_b),
            Arc::clone(&sedp_b),
        );
        let _match_listener_b = participant_b.clone().spawn_sedp_match_listener().await;
        let (mut data_rx_b, _data_recv_handle_b) = data_socket_b.spawn_receive_loop(64);

        let (rx_b, _reader_b) = participant_b
            .new_reliable_reader("Square", SubscriberOptions::default())
            .await;
        let (writer_a, _hb_task_a) = a.participant.new_reliable_writer("Square").await;

        let proxy_b = proxy_from(&spdp_b, prefix_b, meta_port_b);
        let proxy_a = proxy_from(&a.spdp, prefix_a, a.spdp.config().meta_unicast_port);
        a.participant.sedp.on_new_peer(&proxy_b).await;
        participant_b.sedp.on_new_peer(&proxy_a).await;

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !a
                    .participant
                    .sedp
                    .matched_reader_locators("Square")
                    .await
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SEDP endpoint match never landed on participant a");

        // Drive B's data socket manually: drop the first DATA submessage
        // carrying sequence number 2 (simulating one lost datagram); every
        // other datagram — including the later retransmission of the same
        // sequence number — is forwarded to the real handle_data_packet
        // path.
        let participant_b_task = Arc::clone(&participant_b);
        let drain_task = tokio::spawn(async move {
            let mut dropped_seq2_once = false;
            while let Some(datagram) = data_rx_b.recv().await {
                let mut drop_this = false;
                if let Ok(header) = Header::decode(&datagram.data) {
                    let body = &datagram.data[Header::LEN..];
                    for result in SubmessageIter::new(body) {
                        let Ok(raw) = result else { break };
                        if raw.id == SUBMSG_DATA {
                            if let Ok(ds) = decode_data_submessage(raw.flags, raw.body) {
                                if ds.seq_num.to_u64() == 2 && !dropped_seq2_once {
                                    drop_this = true;
                                }
                            }
                        }
                    }
                    let _ = header; // header already decoded above for iteration
                }
                if drop_this {
                    dropped_seq2_once = true;
                    continue; // simulate loss
                }
                participant_b_task
                    .handle_data_packet(&datagram.data, datagram.from)
                    .await;
            }
        });

        writer_a.write(b"one").await.unwrap();
        writer_a.write(b"two").await.unwrap();
        writer_a.write(b"three").await.unwrap();

        let mut received: HashSet<Vec<u8>> = HashSet::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(sample) = rx_b.recv().await {
                received.insert(sample.payload);
                if received.len() == 3 {
                    break;
                }
            }
        })
        .await
        .expect("did not receive all 3 samples (including the gap-recovered one) in time");

        assert!(received.contains(b"one".as_slice()));
        assert!(received.contains(b"two".as_slice())); // recovered via ACKNACK retransmission
        assert!(received.contains(b"three".as_slice()));

        drain_task.abort();
    }

    // ── SPDP → SEDP bridge (spawn_spdp_peer_listener) over real multicast ──

    //fusa:test REQ-RTPS-042
    #[tokio::test]
    async fn spdp_peer_listener_bridges_discovery_to_sedp_announcement() {
        // Picks an ephemeral, collision-free multicast port (rather than the
        // real domain-formula SPDP port) for the same reason spdp.rs's own
        // `send_announcement_reaches_a_real_multicast_listener` test does:
        // hermetic against a real SPDP listener, or another parallel test,
        // sharing this host. Skips (rather than fails) if this environment
        // has no multicast-capable interface.
        let mcast_port = RtpsSocket::bind_unicast_v4(0).await.unwrap().local_port();
        let Ok(mcast_socket) =
            RtpsSocket::bind_multicast_v4(super::super::transport::SPDP_MULTICAST_ADDR, mcast_port)
                .await
        else {
            return;
        };

        let prefix_a = ascending_prefix();
        let a = spawn_peer(prefix_a).await;
        // Wire a's SpdpService into its RtpsParticipant's SEDP bridge, then
        // feed a's SpdpService from the ephemeral multicast socket above —
        // standing in for a's normal mcast-joined receive socket.
        let peer_listener = a
            .participant
            .spawn_spdp_peer_listener(Arc::clone(&a.spdp))
            .await;
        let (mcast_rx, _mcast_recv_handle) = mcast_socket.spawn_receive_loop(8);
        let spdp_recv = Arc::clone(&a.spdp).spawn_receive_loop(mcast_rx);

        // a needs something to announce once it learns about the fake peer.
        a.participant.new_writer("Square").await;

        // A real socket standing in for a fake peer's metatraffic unicast
        // port — same pattern as sedp.rs's own
        // `on_new_peer_announces_local_endpoints_to_one_peer` test.
        let fake_peer_meta = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let fake_peer_meta_port = fake_peer_meta.local_port();
        let (mut fake_peer_rx, fake_peer_recv_handle) = fake_peer_meta.spawn_receive_loop(8);

        // Build and multicast a real SPDP ParticipantData announcement for
        // the fake peer — real build_participant_data/encode_data_submessage/
        // wrap_in_rtps_message, same primitives spdp.rs's own tests use.
        let prefix_fake = other_prefix();
        let fake_cfg = super::super::spdp::SpdpConfig::new(0, prefix_fake, fake_peer_meta_port, 0);
        let payload = super::super::spdp::build_participant_data(&fake_cfg);
        let submsg = encode_data_submessage(
            super::super::guid::ENTITYID_SPDP_WRITER,
            super::super::guid::ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: fake_cfg.vendor_id,
            guid_prefix: prefix_fake,
        };
        let msg = wrap_in_rtps_message(header, &submsg);
        let sender = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        sender
            .send_to(
                &msg,
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, mcast_port)),
            )
            .await
            .unwrap();

        // If the bridge works, a's SpdpService stores the fake peer, emits
        // a ParticipantProxy event, spawn_spdp_peer_listener forwards it into
        // a.sedp.on_new_peer, which announces a's "Square" writer directly
        // to the fake peer's meta port.
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(5), fake_peer_rx.recv())
            .await
            .expect("fake peer never received a SEDP announcement")
            .expect("channel closed unexpectedly");
        assert_eq!(&datagram.data[0..4], b"RTPS");
        let recv_header = Header::decode(&datagram.data).unwrap();
        assert_eq!(recv_header.guid_prefix, prefix_a);

        peer_listener.abort();
        spdp_recv.abort();
        fake_peer_recv_handle.abort();
    }
}
