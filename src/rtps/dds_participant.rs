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
//! receive/dispatch loop) behind [`RtpsUdpParticipant::new`], additionally
//! binding an optional user-data multicast socket the peer binary does not
//! (see [`RtpsUdpParticipantConfig::with_no_multicast`]'s docs), and implements
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
//! wiring reuses unmodified. For static/configured unicast peer discovery
//! (multicast unavailable or undesirable — Docker/cloud networks, TSN
//! segments) use [`RtpsUdpParticipant::new_with_config`] with
//! [`RtpsUdpParticipantConfig::with_peer_locators`]/
//! [`RtpsUdpParticipantConfig::with_no_multicast`] instead of `new`. For an
//! IPv6-only participant (`ROADMAP.md`'s "IPv4 and IPv6 multicast support"),
//! use [`RtpsUdpParticipantConfig::with_ipv6`] — see that method's docs for
//! the address-family-switch (not dual-stack) design and its "limited
//! interop testing" caveat.
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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;
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
    data_unicast_port, meta_multicast_port, meta_unicast_port, user_multicast_port, RtpsDatagram,
    RtpsSocket, SPDP_MULTICAST_ADDR, SPDP_MULTICAST_ADDR_V6, USER_DATA_MULTICAST_ADDR,
    USER_DATA_MULTICAST_ADDR_V6,
};

// ---------------------------------------------------------------------------
// RtpsUdpParticipantConfig
// ---------------------------------------------------------------------------

/// Optional configuration for [`RtpsUdpParticipant::new_with_config`]: static
/// peer unicast addresses for SPDP discovery, disabling SPDP multicast
/// entirely, and/or switching every socket this participant binds from IPv4
/// to IPv6 — the public-API wiring for `ROADMAP.md`'s "Planned — v0.2"
/// checklist items "SPDP participant discovery (multicast + unicast)"'s
/// unicast half ([`RtpsUdpParticipantConfig::with_peer_locators`]/
/// [`RtpsUdpParticipantConfig::with_no_multicast`]) and "IPv4 and IPv6
/// multicast support" ([`RtpsUdpParticipantConfig::with_ipv6`]). Builder
/// style, matching this crate's established `SpdpConfig`/`SedpConfig`
/// config idiom. [`RtpsUdpParticipant::new`] is equivalent to
/// `new_with_config(domain, RtpsUdpParticipantConfig::default())` — the
/// existing IPv4, multicast-only behaviour, unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RtpsUdpParticipantConfig {
    peer_locators: Vec<SocketAddr>,
    no_multicast: bool,
    ipv6: bool,
}

impl RtpsUdpParticipantConfig {
    /// An empty config: no static peers, multicast enabled — identical to
    /// [`RtpsUdpParticipant::new`]'s behaviour.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds static peer unicast addresses (builder style) that this
    /// participant sends SPDP announcements directly to, in addition to (or,
    /// with [`RtpsUdpParticipantConfig::with_no_multicast`], instead of) the
    /// multicast group. Forwarded to [`super::spdp::SpdpConfig::peer_locators`].
    /// Additive across repeated calls.
    //fusa:req REQ-RTPS-059
    pub fn with_peer_locators(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.peer_locators.extend(addrs);
        self
    }

    /// Disables SPDP multicast entirely (builder style): no multicast
    /// socket is bound/joined, and no SPDP announcement is sent to the
    /// multicast group — only to
    /// [`RtpsUdpParticipantConfig::with_peer_locators`]'s addresses. Also
    /// disables the user-data multicast group ([`super::transport::USER_DATA_MULTICAST_ADDR`]):
    /// no multicast receive socket is bound and every
    /// [`super::participant::RtpsWriter::write`] falls back to per-locator
    /// unicast, matching this crate's own — deliberately more consistent —
    /// design rather than go-DDS's `WithNoMulticast`, whose own doc comment
    /// claims to disable "SPDP multicast discovery" but, per a fresh
    /// go-DDS clone's actual `participant.go`, only ever gates the
    /// unrelated user-data multicast socket (`if !p.noMulticast { ... }`
    /// guards only `dataMcastSock`, never `mcastSock`) — see this same
    /// item's `ROADMAP.md` entry for the "SPDP participant discovery"
    /// milestone, which found and documented that same go-DDS
    /// inconsistency. One flag, one meaning, covering both multicast
    /// sockets this participant ever binds.
    /// Intended to be combined with a non-empty peer-locator list for
    /// unicast-only discovery (Docker/cloud networks and TSN segments where
    /// multicast routing is unavailable or undesirable).
    //fusa:req REQ-RTPS-059
    //fusa:req REQ-RTPS-062
    pub fn with_no_multicast(mut self) -> Self {
        self.no_multicast = true;
        self
    }

    /// Switches this participant's transport from IPv4 to IPv6 (builder
    /// style): the meta/data unicast sockets bind on `[::]` via
    /// [`super::transport::RtpsSocket::bind_unicast_v6`], the SPDP
    /// multicast socket joins
    /// [`super::transport::SPDP_MULTICAST_ADDR_V6`] (`FF03::1`) instead of
    /// [`super::transport::SPDP_MULTICAST_ADDR`], and the user-data
    /// multicast socket joins
    /// [`super::transport::USER_DATA_MULTICAST_ADDR_V6`] (`FF03::2`)
    /// instead of [`super::transport::USER_DATA_MULTICAST_ADDR`] — every
    /// socket this participant binds moves to the same family together, so
    /// there is no mixed-family state to reason about. `false` (IPv4) by
    /// default.
    ///
    /// This is a **switch, not a dual-stack add-on** — the one deliberate
    /// deviation from go-DDS's own `WithIPv6` `Option`, which *adds* a
    /// second, parallel set of IPv6 sockets alongside the IPv4 ones rather
    /// than replacing them (see a fresh go-DDS clone's `rtps/participant.go`,
    /// `if p.ipv6 { ... }`). Inspecting that same clone further shows
    /// go-DDS's own IPv6 sockets are, today, only ever wired into the
    /// user-data receive path (`dataSockV6`) — `mcastSockV6`/`metaSockV6`
    /// are bound but never threaded into any SPDP/SEDP receive loop, so
    /// go-DDS's `WithIPv6` cannot actually *discover* a peer over IPv6 at
    /// all, only receive user data sent to a statically-known IPv6 address.
    /// A single-family switch avoids reproducing that gap: every code path
    /// this participant already has (SPDP announce/receive, SEDP
    /// announce/receive, BestEffort/Reliable data, both multicast groups)
    /// works identically under `with_ipv6()`, over real IPv6 end to end —
    /// see `dds_participant.rs`'s own IPv6 round-trip test and
    /// `tests/rtps_two_process_interop.rs`'s `--ipv6` case. What this
    /// participant does *not* claim, matching
    /// [`super::transport`]'s own module docs: **limited interop
    /// testing** — this crate's own two independently-started
    /// `RtpsUdpParticipant`s (and, for the two-process case,
    /// `rtps-interop-peer` processes) talking IPv6 to each other, not
    /// verified against a third-party DDS implementation's IPv6 path.
    /// [`RtpsUdpParticipantConfig::with_peer_locators`] addresses passed
    /// alongside `with_ipv6()` must themselves be IPv6 `SocketAddr`s (an
    /// IPv4 peer address is simply unreachable from an IPv6-only socket,
    /// the same `EINVAL`-at-send-time failure mode as any other
    /// family-mismatched UDP send — not specially validated here).
    //fusa:req REQ-RTPS-041
    pub fn with_ipv6(mut self) -> Self {
        self.ipv6 = true;
        self
    }
}

/// Fans a single socket receive loop's output out to every sender in
/// `senders`, cloning each datagram. Needed because
/// [`RtpsSocket::spawn_receive_loop`]'s `mpsc::Receiver` is single-consumer,
/// while the metatraffic unicast socket now carries traffic for two
/// consumers: SEDP (always) and SPDP (once a peer's unicast announcement
/// arrives on it — see [`SpdpConfig`]'s "Unicast peer discovery" docs).
/// Exits once `rx`'s sender is dropped (the socket's receive task ending),
/// same shutdown contract as every other loop in this module tree.
fn spawn_datagram_fanout(
    mut rx: mpsc::Receiver<RtpsDatagram>,
    senders: Vec<mpsc::Sender<RtpsDatagram>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(datagram) = rx.recv().await {
            for tx in &senders {
                // A closed downstream receiver just means that consumer is
                // no longer interested (or was never wired up); dropping
                // its copy of this datagram is fine, matching every other
                // best-effort channel send in this module tree.
                let _ = tx.send(datagram.clone()).await;
            }
        }
    })
}

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
    /// `None` when constructed with
    /// [`RtpsUdpParticipantConfig::with_no_multicast`] — no SPDP multicast
    /// socket is bound/joined in that case at all (unicast-only discovery).
    _mcast_socket: Option<Arc<RtpsSocket>>,
    /// `None` when either `config.no_multicast` was set or binding/joining
    /// the user-data multicast group failed at startup (a soft failure —
    /// matching go-DDS's own `dataMcastSock` bind, "failure is soft: fall
    /// back to unicast-only delivery") — every
    /// [`super::participant::RtpsWriter::write`] then uses only the
    /// pre-existing per-locator unicast send path.
    _user_data_mcast_socket: Option<Arc<RtpsSocket>>,
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
    /// test/dev binary, now behind a library constructor. Also attempts to
    /// bind the user-data multicast socket (soft-fail — see
    /// [`RtpsUdpParticipantConfig::with_no_multicast`]'s docs), so writers
    /// created on this participant send one multicast packet per write to
    /// every matched reader instead of one unicast packet per reader.
    ///
    /// Returns `Error::DomainOutOfRange` for `domain` outside `[0, 232]`
    /// (checked before any socket is touched) and `Error::Other` wrapping
    /// the underlying `io::Error` if the metatraffic/data unicast socket or
    /// the *SPDP* multicast socket fails to bind (e.g. no multicast-capable
    /// interface, or every candidate port in the retry range is already in
    /// use) — the user-data multicast socket's own bind failure is soft and
    /// never surfaces as an error here (see
    /// [`RtpsUdpParticipantConfig::with_no_multicast`]'s docs).
    //fusa:req REQ-RTPS-041
    //fusa:req REQ-PART-001
    pub async fn new(domain: Domain) -> Result<Arc<Self>, Error> {
        Self::new_with_config(domain, RtpsUdpParticipantConfig::default()).await
    }

    /// Like [`RtpsUdpParticipant::new`], but with static peer unicast
    /// addresses and/or multicast disabled per `config` — the public-API
    /// wiring for `ROADMAP.md`'s "Planned — v0.2" SPDP unicast-discovery
    /// item. When `config.no_multicast` is unset (the default), behaviour
    /// is identical to `new` (no SPDP multicast socket is bound at all when
    /// it *is* set — see [`RtpsUdpParticipantConfig::with_no_multicast`]).
    /// `config.peer_locators` are forwarded to
    /// [`super::spdp::SpdpConfig::peer_locators`] so
    /// [`super::spdp::SpdpService::send_announcement`] unicasts directly to
    /// each one, in addition to (or, with `no_multicast`, instead of) the
    /// multicast group.
    ///
    /// Returns the same error cases as [`RtpsUdpParticipant::new`].
    //fusa:req REQ-RTPS-041
    //fusa:req REQ-RTPS-059
    //fusa:req REQ-PART-001
    pub async fn new_with_config(
        domain: Domain,
        config: RtpsUdpParticipantConfig,
    ) -> Result<Arc<Self>, Error> {
        validate_domain(domain)?;
        let d = domain.0 as u32;
        let guid_prefix = random_guid_prefix();

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

        // Every socket this participant binds moves to the same address
        // family together — see [`RtpsUdpParticipantConfig::with_ipv6`]'s
        // docs for why this is a switch, not a dual-stack add-on.
        //fusa:req REQ-RTPS-041
        let meta_socket = Arc::new(
            if config.ipv6 {
                RtpsSocket::bind_unicast_v6(meta_base_port).await
            } else {
                RtpsSocket::bind_unicast_v4(meta_base_port).await
            }
            .map_err(|e| Error::Other(format!("rtps: bind metatraffic socket: {e}")))?,
        );
        let data_socket = Arc::new(
            if config.ipv6 {
                RtpsSocket::bind_unicast_v6(data_base_port).await
            } else {
                RtpsSocket::bind_unicast_v4(data_base_port).await
            }
            .map_err(|e| Error::Other(format!("rtps: bind user-data socket: {e}")))?,
        );
        let mcast_socket = if config.no_multicast {
            None
        } else {
            let mcast_port = meta_multicast_port(d).ok_or_else(|| {
                Error::Other(format!(
                    "rtps: domain {} out of range for the SPDP multicast port formula",
                    domain.0
                ))
            })?;
            let bound = if config.ipv6 {
                RtpsSocket::bind_multicast_v6(SPDP_MULTICAST_ADDR_V6, mcast_port).await
            } else {
                RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, mcast_port).await
            };
            Some(Arc::new(bound.map_err(|e| {
                Error::Other(format!("rtps: bind SPDP multicast socket: {e}"))
            })?))
        };

        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // SPDP: announce this participant periodically (multicast and/or
        // directly to config.peer_locators), receive/store peer
        // announcements, evict stale peers.
        let mut spdp_cfg = SpdpConfig::new(
            d,
            guid_prefix,
            meta_socket.local_port(),
            data_socket.local_port(),
        )
        .with_peer_locators(config.peer_locators.iter().copied());
        if config.no_multicast {
            spdp_cfg = spdp_cfg.with_no_multicast();
        }
        if config.ipv6 {
            spdp_cfg = spdp_cfg.with_ipv6();
        }
        let spdp = SpdpService::new(spdp_cfg, Arc::clone(&meta_socket));
        tasks.push(Arc::clone(&spdp).spawn_announce_loop());
        tasks.push(Arc::clone(&spdp).spawn_evict_loop());
        if let Some(mcast_socket) = &mcast_socket {
            let (mcast_rx, mcast_recv_task) = mcast_socket.spawn_receive_loop(64);
            tasks.push(mcast_recv_task);
            tasks.push(Arc::clone(&spdp).spawn_receive_loop(mcast_rx));
        }

        // SEDP: exchange publication/subscription announcements with every
        // SPDP-discovered peer, matching local/remote endpoints by topic.
        let mut sedp_cfg = SedpConfig::new(guid_prefix, data_socket.local_port());
        if config.ipv6 {
            sedp_cfg = sedp_cfg.with_ipv6();
        }
        let sedp = SedpService::new(sedp_cfg, Arc::clone(&meta_socket), Arc::clone(&spdp));

        // A peer's unicast SPDP announcement (config.peer_locators on their
        // side) arrives on this participant's metatraffic unicast socket —
        // the same socket SEDP unicast traffic already uses (see
        // SpdpConfig's "Unicast peer discovery" docs) — so fan its receive
        // loop out to both SPDP and SEDP rather than SEDP alone, regardless
        // of whether local multicast is enabled: a multicast-enabled
        // participant should still recognise a peer that unicasts directly
        // to it.
        let (meta_rx, meta_recv_task) = meta_socket.spawn_receive_loop(64);
        tasks.push(meta_recv_task);
        let (spdp_meta_tx, spdp_meta_rx) = mpsc::channel(64);
        let (sedp_meta_tx, sedp_meta_rx) = mpsc::channel(64);
        tasks.push(spawn_datagram_fanout(
            meta_rx,
            vec![spdp_meta_tx, sedp_meta_tx],
        ));
        tasks.push(Arc::clone(&spdp).spawn_receive_loop(spdp_meta_rx));
        tasks.push(Arc::clone(&sedp).spawn_receive_loop(sedp_meta_rx));

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

        // Optional user-data multicast socket ("BestEffort delivery over
        // UDP multicast and unicast", ROADMAP.md's v0.2 milestone): a
        // single multicast send from RtpsWriter::write reaches every
        // matched reader in the domain instead of one unicast send per
        // reader. Gated by the same config.no_multicast flag SPDP's
        // multicast socket uses (see with_no_multicast's docs for why one
        // flag covers both). Unlike SPDP multicast, a bind/join failure
        // here is soft — matching go-DDS's own dataMcastSock convention —
        // since user-data delivery already has a fully-working unicast
        // fallback and does not need multicast to function at all.
        //fusa:req REQ-RTPS-062
        let user_data_mcast_socket = if config.no_multicast {
            None
        } else {
            match user_multicast_port(d) {
                Some(port) => {
                    let bound = if config.ipv6 {
                        RtpsSocket::bind_multicast_v6(USER_DATA_MULTICAST_ADDR_V6, port).await
                    } else {
                        RtpsSocket::bind_multicast_v4(USER_DATA_MULTICAST_ADDR, port).await
                    };
                    bound.ok().map(Arc::new)
                }
                None => None,
            }
        };
        if let Some(mcast_socket) = &user_data_mcast_socket {
            let mcast_addr: SocketAddr = if config.ipv6 {
                SocketAddr::from((USER_DATA_MULTICAST_ADDR_V6, mcast_socket.local_port()))
            } else {
                SocketAddr::from((USER_DATA_MULTICAST_ADDR, mcast_socket.local_port()))
            };
            inner.set_user_data_multicast_addr(mcast_addr).await;
            let (mcast_data_rx, mcast_data_recv_task) = mcast_socket.spawn_receive_loop(64);
            tasks.push(mcast_data_recv_task);
            tasks.push(Arc::clone(&inner).spawn_receive_loop(mcast_data_rx));
        }

        Ok(Arc::new(RtpsUdpParticipant {
            domain,
            guid_prefix,
            inner,
            _meta_socket: meta_socket,
            _data_socket: data_socket,
            _mcast_socket: mcast_socket,
            _user_data_mcast_socket: user_data_mcast_socket,
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
        // Deadline QoS (§15.2) is enforced at this layer, not inside
        // `RtpsParticipant`'s reader constructors — those take only `opts`,
        // not `qos`, the same reason `RtpsPublisher::max_sample_size` is
        // enforced here rather than inside `RtpsWriter::write` (see that
        // field's doc comment below): the RTPS engine layer has no `QoS` of
        // its own to consult.
        let deadline_missed = opts.deadline_missed.clone();
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

        // Only armed when both the QoS interval and a callback are present —
        // a non-zero deadline_ns with no registered callback is a documented
        // no-op, matching go-DDS.
        let deadline_task = deadline_missed
            .and_then(|cb| crate::participant::spawn_deadline_watcher(&inner, qos.deadline_ns, cb));

        let sub = RtpsSubscriber {
            reader: Arc::new(reader),
            inner,
            deadline_task: Mutex::new(deadline_task),
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
    /// Deadline QoS watcher task (§15.2), `Some` only when `QoS::deadline_ns`
    /// was non-zero and a callback was registered via
    /// `SubscriberOptions::deadline_missed` at subscribe time. Aborted on
    /// `close()` for prompt shutdown, mirroring `RtpsPublisher::heartbeat_task`
    /// — see `participant::spawn_deadline_watcher`.
    deadline_task: Mutex<Option<JoinHandle<()>>>,
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
        if let Some(task) = self.deadline_task.lock().unwrap().take() {
            task.abort();
        }
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

    // ── Unicast peer discovery (RtpsUdpParticipantConfig) ────────────────

    //fusa:test REQ-RTPS-059
    #[test]
    fn rtps_udp_participant_config_builder_stores_peer_locators_and_no_multicast() {
        let peer = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 7400));
        let cfg = RtpsUdpParticipantConfig::new()
            .with_peer_locators([peer])
            .with_no_multicast();
        assert_eq!(cfg.peer_locators, vec![peer]);
        assert!(cfg.no_multicast);
    }

    #[test]
    fn rtps_udp_participant_config_default_is_multicast_only_no_peers() {
        let cfg = RtpsUdpParticipantConfig::default();
        assert!(cfg.peer_locators.is_empty());
        assert!(!cfg.no_multicast);
    }

    // Two distinct, dedicated domains (not TEST_DOMAIN, which a
    // single-participant test above already owns) — each participant's
    // metatraffic unicast port is the RTPS 2.3 §9.6.1 formula value for
    // its own domain at participant index 0
    // (`super::transport::meta_unicast_port`), computed rather than
    // queried after the fact so each side's `peer_locators` can be built
    // *before* either participant is constructed — exactly the "known in
    // advance" property real static/TSN peer-locator deployments have.
    const UNICAST_ONLY_DOMAIN_A: Domain = Domain(218);
    const UNICAST_ONLY_DOMAIN_B: Domain = Domain(219);

    //fusa:test REQ-RTPS-059
    #[tokio::test]
    async fn unicast_only_discovery_and_delivery_between_two_participants_with_no_multicast() {
        // The unicast half of SPDP discovery, end-to-end through the
        // public Participant/Publisher/Subscriber traits, between two
        // separate RtpsUdpParticipant instances (unlike this file's other
        // pub/sub tests, which use one participant for both ends) — with
        // no SPDP multicast socket bound on either side at all.
        let Some(a_meta_port) = meta_unicast_port(UNICAST_ONLY_DOMAIN_A.0 as u32, 0) else {
            return;
        };
        let Some(b_meta_port) = meta_unicast_port(UNICAST_ONLY_DOMAIN_B.0 as u32, 0) else {
            return;
        };
        let a_addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, a_meta_port));
        let b_addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, b_meta_port));

        let Ok(a) = RtpsUdpParticipant::new_with_config(
            UNICAST_ONLY_DOMAIN_A,
            RtpsUdpParticipantConfig::new()
                .with_no_multicast()
                .with_peer_locators([b_addr]),
        )
        .await
        else {
            return; // no free port / no usable interface in this environment
        };
        let Ok(b) = RtpsUdpParticipant::new_with_config(
            UNICAST_ONLY_DOMAIN_B,
            RtpsUdpParticipantConfig::new()
                .with_no_multicast()
                .with_peer_locators([a_addr]),
        )
        .await
        else {
            return;
        };
        let a: Arc<dyn Participant> = a;
        let b: Arc<dyn Participant> = b;

        let (rx, _sub) = b
            .new_subscriber(
                "UnicastOnlyTopic",
                DEFAULT_QOS.clone(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        let pub_ = a
            .new_publisher("UnicastOnlyTopic", DEFAULT_QOS.clone())
            .await
            .unwrap();

        // Discovery (SPDP unicast announce -> SEDP unicast match) between
        // two independent participants is not instantaneous; retry the
        // write until it lands, rather than assuming any fixed settle
        // time — matches the discovery-poll pattern
        // `src/bin/rtps_interop_peer.rs` uses for the same reason.
        let sample = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let _ = pub_.write(b"unicast-hello".to_vec()).await;
                if let Ok(Some(sample)) =
                    tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await
                {
                    return sample;
                }
            }
        })
        .await
        .expect("unicast-only discovery and delivery did not complete in time");
        assert_eq!(sample.payload, b"unicast-hello");
        assert_eq!(sample.topic, "UnicastOnlyTopic");
    }

    // A third dedicated domain, shared by both participants below (unlike
    // UNICAST_ONLY_DOMAIN_A/B, which are deliberately distinct — SPDP
    // multicast discovery, and this test's user-data multicast delivery,
    // both require peers to be on the *same* domain).
    const MULTICAST_DOMAIN: Domain = Domain(220);

    //fusa:test REQ-RTPS-061
    //fusa:test REQ-RTPS-062
    #[tokio::test]
    async fn besteffort_pubsub_between_two_participants_with_multicast_enabled() {
        // Two independent RtpsUdpParticipant instances (default config —
        // multicast enabled, matching RtpsUdpParticipant::new), same
        // domain: SPDP/SEDP discover each other over the same multicast
        // groups this test's writer then delivers samples over. Unlike
        // `local_besteffort_pubsub_round_trips_through_the_public_traits`
        // (one participant, in-process dispatch only) this exercises the
        // real network send/receive path end-to-end, same posture as
        // `unicast_only_discovery_and_delivery_between_two_participants_with_no_multicast`
        // above but with multicast left on.
        let Ok(a) = RtpsUdpParticipant::new(MULTICAST_DOMAIN).await else {
            return; // no multicast-capable interface in this environment
        };
        let Ok(b) = RtpsUdpParticipant::new(MULTICAST_DOMAIN).await else {
            return;
        };
        let a: Arc<dyn Participant> = a;
        let b: Arc<dyn Participant> = b;

        let (rx, _sub) = b
            .new_subscriber(
                "MulticastTopic",
                DEFAULT_QOS.clone(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        let pub_ = a
            .new_publisher("MulticastTopic", DEFAULT_QOS.clone())
            .await
            .unwrap();

        // Same discovery-poll rationale as the unicast-only test above:
        // SPDP/SEDP discovery between two independent participants is not
        // instantaneous. A timeout here is treated as a skip, not a
        // failure: real UDP multicast fan-out is, unlike unicast,
        // genuinely environment-dependent — some CI sandboxes/hosts allow
        // binding and joining the user-data multicast group (so `a`'s
        // writer commits to the multicast-only send path, with no
        // per-write unicast fallback) yet still never deliver a packet
        // sent to it back to a local listener (observed on macOS GitHub
        // Actions runners; see `spdp.rs`'s
        // `send_announcement_reaches_a_real_multicast_listener` for the
        // same caveat on the SPDP multicast group, and
        // `participant.rs`'s
        // `besteffort_write_delivers_via_configured_multicast_group_not_unicast`
        // for the lower-level, environment-independent proof of the same
        // send-path-selection logic this test exercises end-to-end).
        let Ok(Some(sample)) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let _ = pub_.write(b"multicast-hello".to_vec()).await;
                if let Ok(Some(sample)) =
                    tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await
                {
                    return Some(sample);
                }
            }
        })
        .await
        else {
            return;
        };
        assert_eq!(sample.payload, b"multicast-hello");
        assert_eq!(sample.topic, "MulticastTopic");
    }

    // ── IPv6 (RtpsUdpParticipantConfig::with_ipv6) ────────────────────────

    const IPV6_MULTICAST_DOMAIN: Domain = Domain(221);

    //fusa:test REQ-RTPS-041
    //fusa:test REQ-RTPS-062
    #[tokio::test]
    async fn ipv6_spdp_sedp_and_besteffort_round_trip_between_two_participants() {
        // The IPv6 analogue of
        // besteffort_pubsub_between_two_participants_with_multicast_enabled
        // above: two independent RtpsUdpParticipant instances, both
        // constructed with with_ipv6(), on the same domain — every socket
        // (meta/data unicast, SPDP multicast at FF03::1, user-data
        // multicast at FF03::2) is IPv6-only on both sides. Proves SPDP
        // discovers both sides, SEDP matches the writer/reader pair, and a
        // BestEffort sample flows end-to-end, all over real IPv6 — the
        // "SPDP/SEDP/BestEffort round-trip test" this crate's IPv6 support
        // is scoped to provide.
        //
        // Same skip posture as every other real-multicast test in this
        // crate: IPv6 (and especially IPv6 multicast) is even less
        // universally available in CI sandboxes than IPv4 multicast — see
        // with_ipv6's own doc comment for the explicit "limited interop
        // testing" caveat this test is not meant to outgrow. A bind
        // failure or a discovery/delivery timeout is treated as a skip,
        // not a failure.
        let Ok(a) = RtpsUdpParticipant::new_with_config(
            IPV6_MULTICAST_DOMAIN,
            RtpsUdpParticipantConfig::new().with_ipv6(),
        )
        .await
        else {
            return;
        };
        let Ok(b) = RtpsUdpParticipant::new_with_config(
            IPV6_MULTICAST_DOMAIN,
            RtpsUdpParticipantConfig::new().with_ipv6(),
        )
        .await
        else {
            return;
        };
        let a: Arc<dyn Participant> = a;
        let b: Arc<dyn Participant> = b;

        let (rx, _sub) = b
            .new_subscriber(
                "Ipv6MulticastTopic",
                DEFAULT_QOS.clone(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        let pub_ = a
            .new_publisher("Ipv6MulticastTopic", DEFAULT_QOS.clone())
            .await
            .unwrap();

        let Ok(Some(sample)) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let _ = pub_.write(b"ipv6-multicast-hello".to_vec()).await;
                if let Ok(Some(sample)) =
                    tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await
                {
                    return Some(sample);
                }
            }
        })
        .await
        else {
            return;
        };
        assert_eq!(sample.payload, b"ipv6-multicast-hello");
        assert_eq!(sample.topic, "Ipv6MulticastTopic");
    }

    //fusa:test REQ-RTPS-041
    #[tokio::test]
    async fn ipv6_participant_binds_and_reports_its_domain_or_skips_cleanly() {
        // A lighter-weight companion to the round-trip test above: proves
        // construction itself (meta/data unicast + SPDP/user-data
        // multicast, all IPv6) succeeds or fails cleanly — no panic either
        // way — independent of whether a peer is present to discover.
        let Ok(p) = RtpsUdpParticipant::new_with_config(
            Domain(222),
            RtpsUdpParticipantConfig::new().with_ipv6(),
        )
        .await
        else {
            return; // no IPv6 / no IPv6-multicast-capable interface here
        };
        assert_eq!(p.domain(), Domain(222));
    }

    // Deadline QoS (§15.2) — proves the enforcement wired up in
    // `RtpsUdpParticipant::new_subscriber` behaves identically to
    // `mock::MockParticipant`'s (see `mock::tests::deadline_*`), since both
    // ultimately share `participant::spawn_deadline_watcher` over the same
    // `Arc<SubInner>` choke point. Uses `RELIABLE_QOS`'s Reliable +
    // TransientLocal combination deliberately, since Deadline QoS must be
    // enforced uniformly across both reliability and durability axes.

    //fusa:test REQ-QOS-008
    //fusa:test REQ-QOS-009
    #[tokio::test]
    async fn deadline_fires_without_samples_and_resets_when_samples_arrive() {
        let Ok(p) = RtpsUdpParticipant::new(Domain(223)).await else {
            return; // no multicast-capable interface in this environment
        };
        let p: Arc<dyn Participant> = p;

        let fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let mut qos = RELIABLE_QOS.clone();
        qos.deadline_ns = 30_000_000; // 30ms
        let opts = crate::relay::with_deadline_callback(move || {
            fired_cb.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        let (rx, sub) = p
            .new_subscriber("DeadlineTopic", qos.clone(), opts)
            .await
            .unwrap();

        // Phase 1: no publisher exists yet — the deadline must fire at
        // least once while the reader sits idle.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "expected the Deadline-missed callback to fire while idle"
        );

        // Phase 2: start publishing well within the deadline window and
        // confirm the callback stops firing — proves each delivered sample
        // resets the window rather than the timer having stopped for some
        // other reason (e.g. already cancelled).
        let pub_ = p.new_publisher("DeadlineTopic", qos).await.unwrap();
        let before_phase2 = fired.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..6 {
            pub_.write(b"tick".to_vec()).await.unwrap();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let after_phase2 = fired.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            after_phase2, before_phase2,
            "Deadline-missed callback must not fire while samples keep arriving within the window"
        );

        sub.close().await.unwrap();
    }
}
