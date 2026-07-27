// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Public, UDP-backed `Participant`/`Publisher`/`Subscriber` implementation
//! — the wiring deliverable of `ROADMAP.md`'s "Planned — v0.2 — RTPS
//! Transport (Tier 1)" milestone, "Pure-Rust RTPS/UDP transport
//! (`rtps::RtpsParticipant`)".
//!
//! Every Tier 1 sub-phase (1 through 9, `rust-DDS#22`–`#30`) landed the real
//! RTPS engine — wire types, CDR, UDP transport, SPDP, SEDP, the BestEffort/
//! Reliable data path, fragmentation, TransientLocal persistence — as
//! `super::participant::RtpsParticipant` and its `RtpsWriter`/`RtpsReader`
//! handles, but every one of those sub-phases' own module docs says the same
//! thing: "internal only — not yet wired into `Participant`/`Publisher`/
//! `Subscriber`". [`RtpsUdpParticipant`] is that wiring: it owns the same
//! bootstrap sequence `src/bin/rtps_interop_peer.rs` already exercises as a
//! standalone test/dev binary (bind meta/data unicast sockets + the SPDP
//! multicast socket at the RTPS 2.3 §9.6.1 formula ports, start SPDP
//! announce/evict/receive, start SEDP receive, bridge SPDP→SEDP and
//! SEDP→[`RtpsParticipant`] match notifications, start the data-socket
//! receive/dispatch loop) behind [`RtpsUdpParticipant::new`], and implements
//! [`Participant`]/[`Publisher`]/[`Subscriber`] on top of it — so
//! application code that already programs against those traits (as it does
//! for [`crate::mock::MockParticipant`] today) can swap in a real,
//! network-capable, interop-tested participant at the call site with no
//! other code change, exactly per `ROADMAP.md`'s "Async vs. sync — the
//! concrete call for this crate" section (tokio tasks per socket/reliable
//! writer, `std::sync::Mutex` for short bookkeeping, `SampleReceiver`/
//! `SubInner` reused unmodified for delivery — no new concurrency model).
//!
//! # What this does *not* do
//!
//! This module adds no new wire behaviour and changes no byte layout —
//! every submessage/CDR/discovery byte this type puts on the wire was
//! already verified byte-for-byte against real go-DDS output by the
//! sub-phase that implemented it (see each `rtps` submodule's own tests).
//! It also does not touch `relay::Node`/`adapt()`: those already work with
//! *any* `Arc<dyn Participant>`, so wrapping an [`RtpsUdpParticipant`] with
//! [`crate::adapt`] works for free, no separate integration needed.
//!
//! # Constructing one
//!
//! ```rust,no_run
//! use rust_dds::rtps::dds_participant::RtpsUdpParticipant;
//! use rust_dds::participant::Participant;
//! use rust_dds::relay::SubscriberOptions;
//! use rust_dds::types::{Domain, QoS};
//!
//! # #[tokio::main]
//! # async fn main() {
//! let p = RtpsUdpParticipant::new(Domain(0)).await.unwrap();
//! let pub_ = p.new_publisher("vehicle/speed", QoS::default()).await.unwrap();
//! let (rx, _sub) = p
//!     .new_subscriber("vehicle/speed", QoS::default(), SubscriberOptions::default())
//!     .await
//!     .unwrap();
//! pub_.write(b"80".to_vec()).await.unwrap();
//! let sample = rx.recv().await.unwrap();
//! assert_eq!(sample.payload, b"80");
//! # }
//! ```
//!
//! Two `RtpsUdpParticipant`s in different OS processes on the same domain
//! discover each other via SPDP multicast and exchange samples over real
//! UDP — see `src/bin/rtps_interop_peer.rs` and
//! `tests/rtps_two_process_interop.rs` for the live two-process proof this
//! wiring reuses unmodified.
//!
//! # QoS → RTPS engine mapping
//!
//! `QoS::reliability == Reliable` selects
//! [`RtpsParticipant::new_reliable_writer`]/[`RtpsParticipant::new_reliable_reader`]
//! (HEARTBEAT/ACKNACK) over the BestEffort constructors;
//! `QoS::durability == TransientLocal` selects
//! [`RtpsParticipant::new_transient_local_reader`]/
//! [`RtpsParticipant::new_reliable_transient_local_reader`] (late-joiner
//! delivery) — the four combinations map 1:1 onto the four reader
//! constructors sub-phase 9 already built. TransientLocal *disk*
//! persistence (`RtpsParticipant::new_with_persistent_history`) has no QoS
//! field to select it from and is out of scope for this wiring (every
//! `RtpsUdpParticipant` uses the in-memory-only constructor,
//! [`RtpsParticipant::new`]).
//!
//! # Lifecycle
//!
//! [`RtpsUdpParticipant::close`] is idempotent: it closes every
//! still-registered subscriber's channel (so `SampleReceiver::recv` drains
//! and returns `None`, matching `MockParticipant::close`'s contract) and
//! aborts every background `tokio::task` this participant spawned
//! (announce/evict/receive loops), releasing the bound sockets once their
//! last `Arc<RtpsSocket>` reference is dropped. Matches
//! `MockParticipant::close`'s scope: publishers/subscribers created
//! *before* `close()` are not retroactively forced to error on their next
//! call — only `new_publisher`/`new_subscriber` after `close()` do (both
//! return `Error::Closed`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::task::JoinHandle;

use crate::error::Error;
use crate::participant::{Participant, Publisher, SampleReceiver, SubInner, Subscriber};
use crate::relay::{Context, SubscriberOptions};
use crate::types::{validate_domain, Domain, DurabilityKind, QoS, ReliabilityKind};

use super::guid::random_guid_prefix;
use super::message::VENDOR_ID_RUST_DDS;
use super::participant::{RtpsParticipant, RtpsReader, RtpsWriter};
use super::sedp::{SedpConfig, SedpService};
use super::spdp::{SpdpConfig, SpdpService};
use super::transport::{
    data_unicast_port, meta_multicast_port, meta_unicast_port, RtpsSocket, SPDP_MULTICAST_ADDR,
};

// ---------------------------------------------------------------------------
// RtpsUdpParticipant
// ---------------------------------------------------------------------------

/// A real, UDP-backed DDS participant: RTPS 2.3 wire protocol, SPDP
/// multicast discovery, SEDP unicast endpoint matching, BestEffort/Reliable
/// delivery. Implements [`Participant`] — usable anywhere
/// `Arc<dyn Participant>` is expected, exactly like
/// [`crate::mock::MockParticipant`].
///
/// Construct with [`RtpsUdpParticipant::new`]. Binds its meta/data unicast
/// sockets at the RTPS 2.3 §9.6.1 formula ports for `domain`
/// (`super::transport::meta_unicast_port`/`data_unicast_port`, participant
/// index 0), retrying nearby ports on collision exactly as
/// [`RtpsSocket::bind_unicast_v4`] already does for every other caller in
/// this module tree — so multiple local participants on the same domain
/// each still get a distinct, working port pair.
//fusa:req REQ-RTPS-041
//fusa:req REQ-PART-001
//fusa:req REQ-PART-002
pub struct RtpsUdpParticipant {
    domain: Domain,
    guid_prefix: super::guid::GuidPrefix,
    inner: Arc<RtpsParticipant>,
    /// Kept alive for the participant's lifetime — dropping the last
    /// `Arc<RtpsSocket>` reference (here, on `Self`'s own drop) releases
    /// the bound OS socket. `spdp`/`sedp`/`inner` above also hold their own
    /// clones of the sockets they need to *send* on.
    _meta_socket: Arc<RtpsSocket>,
    _data_socket: Arc<RtpsSocket>,
    _mcast_socket: Arc<RtpsSocket>,
    /// Every still-registered subscriber's queue, so `close()` can close
    /// them all — mirrors `mock::Broker`'s per-topic subscriber list, but
    /// flat (this participant does not need per-topic grouping for this
    /// purpose).
    subscribers: Mutex<Vec<Arc<SubInner>>>,
    /// Every background task this participant spawned (SPDP announce/
    /// evict/receive, SEDP receive, the SPDP→SEDP and SEDP→reader-sources
    /// match bridges, the data-socket receive/dispatch loop). Aborted on
    /// `close()`.
    tasks: Mutex<Vec<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl RtpsUdpParticipant {
    /// Creates a new UDP-backed participant on `domain`: binds the meta/
    /// data unicast sockets and the SPDP multicast socket, then starts
    /// every background task a live participant needs (SPDP announce/
    /// evict/receive, SEDP receive, the SPDP→SEDP and SEDP→
    /// [`RtpsParticipant`] discovery bridges, the data-socket receive/
    /// dispatch loop) — the same sequence
    /// `src/bin/rtps_interop_peer.rs::run` already performs as a standalone
    /// test/dev binary, now behind a library constructor.
    ///
    /// Returns `Error::DomainOutOfRange` for `domain` outside `[0, 232]`
    /// (checked before any socket is touched) and `Error::Other` wrapping
    /// the underlying `io::Error` if any socket fails to bind (e.g. no
    /// multicast-capable interface, or every candidate port in the retry
    /// range is already in use).
    //fusa:req REQ-RTPS-041
    //fusa:req REQ-PART-001
    pub async fn new(domain: Domain) -> Result<Arc<Self>, Error> {
        validate_domain(domain)?;
        let d = domain.0 as u32;
        let guid_prefix = random_guid_prefix();

        let mcast_port = meta_multicast_port(d).ok_or_else(|| {
            Error::Other(format!(
                "rtps: domain {} out of range for the SPDP multicast port formula",
                domain.0
            ))
        })?;
        let meta_base_port = meta_unicast_port(d, 0).ok_or_else(|| {
            Error::Other(format!(
                "rtps: domain {} out of range for the metatraffic unicast port formula",
                domain.0
            ))
        })?;
        let data_base_port = data_unicast_port(d, 0).ok_or_else(|| {
            Error::Other(format!(
                "rtps: domain {} out of range for the user-data unicast port formula",
                domain.0
            ))
        })?;

        let meta_socket = Arc::new(
            RtpsSocket::bind_unicast_v4(meta_base_port)
                .await
                .map_err(|e| Error::Other(format!("rtps: bind metatraffic socket: {e}")))?,
        );
        let data_socket = Arc::new(
            RtpsSocket::bind_unicast_v4(data_base_port)
                .await
                .map_err(|e| Error::Other(format!("rtps: bind user-data socket: {e}")))?,
        );
        let mcast_socket = Arc::new(
            RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, mcast_port)
                .await
                .map_err(|e| Error::Other(format!("rtps: bind SPDP multicast socket: {e}")))?,
        );

        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // SPDP: announce this participant periodically, receive/store peer
        // announcements, evict stale peers.
        let spdp_cfg = SpdpConfig::new(
            d,
            guid_prefix,
            meta_socket.local_port(),
            data_socket.local_port(),
        );
        let spdp = SpdpService::new(spdp_cfg, Arc::clone(&meta_socket));
        tasks.push(Arc::clone(&spdp).spawn_announce_loop());
        tasks.push(Arc::clone(&spdp).spawn_evict_loop());
        let (mcast_rx, mcast_recv_task) = mcast_socket.spawn_receive_loop(64);
        tasks.push(mcast_recv_task);
        tasks.push(Arc::clone(&spdp).spawn_receive_loop(mcast_rx));

        // SEDP: exchange publication/subscription announcements with every
        // SPDP-discovered peer, matching local/remote endpoints by topic.
        let sedp_cfg = SedpConfig::new(guid_prefix, data_socket.local_port());
        let sedp = SedpService::new(sedp_cfg, Arc::clone(&meta_socket), Arc::clone(&spdp));
        let (meta_rx, meta_recv_task) = meta_socket.spawn_receive_loop(64);
        tasks.push(meta_recv_task);
        tasks.push(Arc::clone(&sedp).spawn_receive_loop(meta_rx));

        // RTPS participant runtime: BestEffort/Reliable DATA data path over
        // the data socket, fed by both discovery services' match output.
        let inner = RtpsParticipant::new(
            guid_prefix,
            VENDOR_ID_RUST_DDS,
            Arc::clone(&data_socket),
            Arc::clone(&sedp),
        );
        tasks.push(inner.spawn_sedp_match_listener().await);
        tasks.push(inner.spawn_spdp_peer_listener(Arc::clone(&spdp)).await);
        let (data_rx, data_recv_task) = data_socket.spawn_receive_loop(64);
        tasks.push(data_recv_task);
        tasks.push(Arc::clone(&inner).spawn_receive_loop(data_rx));

        Ok(Arc::new(RtpsUdpParticipant {
            domain,
            guid_prefix,
            inner,
            _meta_socket: meta_socket,
            _data_socket: data_socket,
            _mcast_socket: mcast_socket,
            subscribers: Mutex::new(Vec::new()),
            tasks: Mutex::new(tasks),
            closed: AtomicBool::new(false),
        }))
    }

    /// This participant's own `GuidPrefix` — the RTPS-level identity peers
    /// see in SPDP/SEDP announcements and every DATA submessage's writer
    /// `Guid`.
    pub fn guid_prefix(&self) -> super::guid::GuidPrefix {
        self.guid_prefix
    }
}

#[async_trait]
impl Participant for RtpsUdpParticipant {
    //fusa:req REQ-PART-003
    async fn new_publisher(&self, topic: &str, qos: QoS) -> Result<Box<dyn Publisher>, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if topic.is_empty() {
            return Err(Error::TopicEmpty);
        }
        let (writer, heartbeat_task) = if qos.reliability == ReliabilityKind::Reliable {
            let (w, hb) = self.inner.new_reliable_writer(topic).await;
            (w, Some(hb))
        } else {
            (self.inner.new_writer(topic).await, None)
        };
        Ok(Box::new(RtpsPublisher {
            writer,
            max_sample_size: qos.max_sample_size,
            closed: AtomicBool::new(false),
            heartbeat_task: Mutex::new(heartbeat_task),
        }))
    }

    //fusa:req REQ-PART-004
    //fusa:req REQ-QOS-001
    //fusa:req REQ-QOS-002
    async fn new_subscriber(
        &self,
        topic: &str,
        qos: QoS,
        opts: SubscriberOptions,
    ) -> Result<(SampleReceiver, Box<dyn Subscriber>), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if topic.is_empty() {
            return Err(Error::TopicEmpty);
        }
        let reliable = qos.reliability == ReliabilityKind::Reliable;
        let transient_local = qos.durability == DurabilityKind::TransientLocal;
        let (receiver, reader) = match (reliable, transient_local) {
            (false, false) => self.inner.new_reader(topic, opts).await,
            (true, false) => self.inner.new_reliable_reader(topic, opts).await,
            (false, true) => self.inner.new_transient_local_reader(topic, opts).await,
            (true, true) => {
                self.inner
                    .new_reliable_transient_local_reader(topic, opts)
                    .await
            }
        };

        let inner = Arc::clone(&receiver.inner);
        self.subscribers.lock().unwrap().push(Arc::clone(&inner));

        let sub = RtpsSubscriber {
            reader: Arc::new(reader),
            inner,
        };
        Ok((receiver, Box::new(sub)))
    }

    fn domain(&self) -> Domain {
        self.domain
    }

    //fusa:req REQ-PART-005
    //fusa:req REQ-IEC-010
    async fn close(&self) -> Result<(), Error> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }
        for sub in self.subscribers.lock().unwrap().iter() {
            sub.close();
        }
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RtpsPublisher
// ---------------------------------------------------------------------------

/// Wraps [`RtpsWriter`] to implement [`Publisher`]. Created by
/// [`RtpsUdpParticipant::new_publisher`].
struct RtpsPublisher {
    writer: RtpsWriter,
    /// `QoS::max_sample_size` at creation time (0 = unlimited) — enforced
    /// here rather than inside [`RtpsWriter::write`] since the RTPS engine
    /// layer has no `QoS` of its own to consult, matching
    /// `mock::MockPublisher`'s equivalent check (§16).
    //fusa:req REQ-SEC-002
    max_sample_size: i32,
    closed: AtomicBool,
    /// `Some` for a reliable writer's periodic HEARTBEAT-sending task,
    /// aborted on `close()`; `None` for a BestEffort writer. Standing in
    /// for the writer-side `Close` path `RtpsWriter`'s own docs note the
    /// RTPS engine layer does not have yet (see
    /// `super::participant::RtpsParticipant::new_reliable_writer`'s docs).
    heartbeat_task: Mutex<Option<JoinHandle<()>>>,
}

#[async_trait]
impl Publisher for RtpsPublisher {
    //fusa:req REQ-PUB-001
    async fn write(&self, payload: Vec<u8>) -> Result<(), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if self.max_sample_size > 0 && payload.len() > self.max_sample_size as usize {
            return Err(Error::PayloadTooLarge);
        }
        self.writer
            .write(&payload)
            .await
            .map_err(|e| Error::Other(format!("rtps: write failed: {e}")))
    }

    //fusa:req REQ-PUB-002
    async fn write_ctx(&self, ctx: Context, payload: Vec<u8>) -> Result<(), Error> {
        if ctx.done() {
            return Err(Error::Timeout);
        }
        self.write(payload).await
    }

    //fusa:req REQ-PUB-003
    //fusa:req REQ-PUB-004
    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(task) = self.heartbeat_task.lock().unwrap().take() {
            task.abort();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RtpsSubscriber
// ---------------------------------------------------------------------------

/// Wraps [`RtpsReader`] plus its delivery queue's `Arc<SubInner>` (obtained
/// from the [`SampleReceiver`] returned alongside it — same field
/// `mock::MockSubscriber` reads to implement the identical contract) to
/// implement [`Subscriber`]. Created by
/// [`RtpsUdpParticipant::new_subscriber`].
struct RtpsSubscriber {
    reader: Arc<RtpsReader>,
    inner: Arc<SubInner>,
}

#[async_trait]
impl Subscriber for RtpsSubscriber {
    //fusa:req REQ-SUB-001
    //fusa:req REQ-SUB-002
    fn unsubscribe(&self) {
        // Stops future delivery immediately and unconditionally:
        // SubInner::push checks the `unsubscribed` flag before touching the
        // queue, so this alone satisfies the trait's "no more samples will
        // be delivered after this call" contract synchronously, with no
        // `.await` needed (`unsubscribe` is a sync trait method — see
        // `participant::Subscriber`).
        self.inner.unsubscribe();
        // Best-effort participant-side cleanup: also remove this reader
        // from RtpsParticipant's dispatch table, so it stops accumulating
        // drop-counter noise and a future reader on the same topic doesn't
        // share sources with a logically-dead one. This requires an
        // `.await` the trait's sync signature cannot provide, so it is
        // spawned rather than awaited — a no-op (not a panic) if this is
        // somehow called outside a tokio runtime, since every legitimate
        // caller already had to be inside one to have constructed an
        // `RtpsUdpParticipant`/`RtpsSubscriber` in the first place.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let reader = Arc::clone(&self.reader);
            handle.spawn(async move {
                reader.unsubscribe().await;
            });
        }
    }

    //fusa:req REQ-SUB-003
    //fusa:req REQ-SUB-004
    //fusa:req REQ-SUB-005
    async fn close(&self) -> Result<(), Error> {
        self.inner.close();
        self.reader.unsubscribe().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DEFAULT_QOS, RELIABLE_QOS};

    // A high, distinctive domain avoids colliding with any other test in
    // this crate: every other `rtps` unit test that needs an SPDP/SEDP
    // config binds its sockets on ephemeral (port 0) addresses and injects
    // `ParticipantProxy`/announcement bytes directly rather than relying on
    // the real domain-formula multicast port (see `participant.rs`'s
    // `spdp_peer_listener_bridges_discovery_to_sedp_announcement` test for
    // why) — this is the only test in the crate that exercises the real
    // formula-derived ports end-to-end, so no other test binds this
    // domain's ports concurrently.
    const TEST_DOMAIN: Domain = Domain(217);

    //fusa:test REQ-PART-001
    //fusa:test REQ-ASIL-006
    #[tokio::test]
    async fn domain_out_of_range_is_rejected_before_any_socket_bind() {
        assert!(matches!(
            RtpsUdpParticipant::new(Domain(-1)).await,
            Err(Error::DomainOutOfRange)
        ));
        assert!(matches!(
            RtpsUdpParticipant::new(Domain(233)).await,
            Err(Error::DomainOutOfRange)
        ));
    }

    //fusa:test REQ-PART-001
    #[tokio::test]
    async fn domain_accessor_reflects_constructor_argument() {
        let Ok(p) = RtpsUdpParticipant::new(TEST_DOMAIN).await else {
            return; // no multicast-capable interface in this environment
        };
        assert_eq!(p.domain(), TEST_DOMAIN);
    }

    //fusa:test REQ-PART-002
    //fusa:test REQ-PUB-001
    //fusa:test REQ-SUB-001
    #[tokio::test]
    async fn local_besteffort_pubsub_round_trips_through_the_public_traits() {
        // Exercises RtpsUdpParticipant purely through the public
        // Participant/Publisher/Subscriber trait objects — the actual
        // application-facing contract this wiring exists to satisfy — not
        // through any RTPS-internal type. Both endpoints are on the same
        // participant, so delivery happens on the in-process dispatch path
        // `RtpsWriter::write` already takes before ever touching a socket;
        // see the two-process interop test suite
        // (`tests/rtps_two_process_interop.rs`) for the real-network case.
        let Ok(p) = RtpsUdpParticipant::new(TEST_DOMAIN).await else {
            return;
        };
        let p: Arc<dyn Participant> = p;

        let (rx, _sub) = p
            .new_subscriber("Square", DEFAULT_QOS.clone(), SubscriberOptions::default())
            .await
            .unwrap();
        let pub_ = p
            .new_publisher("Square", DEFAULT_QOS.clone())
            .await
            .unwrap();

        pub_.write(b"hello".to_vec()).await.unwrap();
        let sample = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for sample")
            .expect("channel closed with no sample");
        assert_eq!(sample.payload, b"hello");
        assert_eq!(sample.topic, "Square");
    }

    //fusa:test REQ-QOS-001
    //fusa:test REQ-QOS-002
    #[tokio::test]
    async fn reliable_transient_local_qos_selects_the_matching_reader_constructor() {
        // Reliable + TransientLocal (RELIABLE_QOS) must deliver a
        // late-joining subscriber the last written sample — proves the QoS
        // -> reader-constructor mapping actually reaches
        // RtpsParticipant::new_reliable_transient_local_reader, not just
        // new_reader.
        let Ok(p) = RtpsUdpParticipant::new(TEST_DOMAIN).await else {
            return;
        };
        let p: Arc<dyn Participant> = p;

        let pub_ = p
            .new_publisher("Cached", RELIABLE_QOS.clone())
            .await
            .unwrap();
        pub_.write(b"cached-value".to_vec()).await.unwrap();

        let (rx, _sub) = p
            .new_subscriber("Cached", RELIABLE_QOS.clone(), SubscriberOptions::default())
            .await
            .unwrap();
        let sample = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for the TransientLocal late-joiner sample")
            .expect("channel closed with no sample");
        assert_eq!(sample.payload, b"cached-value");
    }

    //fusa:test REQ-PART-005
    //fusa:test REQ-SUB-003
    #[tokio::test]
    async fn close_is_idempotent_and_closes_open_subscriber_channels() {
        let Ok(p) = RtpsUdpParticipant::new(TEST_DOMAIN).await else {
            return;
        };
        let p: Arc<dyn Participant> = p;

        let (rx, _sub) = p
            .new_subscriber("Closing", DEFAULT_QOS.clone(), SubscriberOptions::default())
            .await
            .unwrap();

        p.close().await.unwrap();
        p.close().await.unwrap(); // idempotent — must not error or panic

        // The channel is closed (not merely unsubscribed): recv() must
        // drain (nothing was ever pushed) and return None, not hang.
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("recv() hung after close() instead of returning None");
        assert!(result.is_none());

        // new_publisher/new_subscriber after close() both return Closed.
        assert!(matches!(
            p.new_publisher("Closing", DEFAULT_QOS.clone()).await,
            Err(Error::Closed)
        ));
        assert!(matches!(
            p.new_subscriber("Closing", DEFAULT_QOS.clone(), SubscriberOptions::default())
                .await,
            Err(Error::Closed)
        ));
    }

    //fusa:test REQ-PART-003
    //fusa:test REQ-PART-004
    #[tokio::test]
    async fn empty_topic_is_rejected_for_both_publisher_and_subscriber() {
        let Ok(p) = RtpsUdpParticipant::new(TEST_DOMAIN).await else {
            return;
        };
        assert!(matches!(
            p.new_publisher("", DEFAULT_QOS.clone()).await,
            Err(Error::TopicEmpty)
        ));
        assert!(matches!(
            p.new_subscriber("", DEFAULT_QOS.clone(), SubscriberOptions::default())
                .await,
            Err(Error::TopicEmpty)
        ));
    }
}
