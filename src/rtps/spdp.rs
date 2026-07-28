// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! SPDP — Simple Participant Discovery Protocol (RTPS 2.3 §8.5.3 / §9.6.1).
//!
//! This is Tier 1 sub-phase 4 of the parity build-out plan in
//! `ROADMAP.md` ("Tier 1 — RTPS wire-protocol port" → "SPDP"): on startup,
//! a participant announces itself on the well-known multicast group
//! (`239.255.0.1`, see `super::transport::SPDP_MULTICAST_ADDR`) at a
//! periodic interval with optional jitter. Incoming announcements are
//! decoded and stored in a known-participants table so that SEDP (sub-phase
//! 5) can reach them over unicast.
//!
//! Wire layout and service behaviour ported 1:1 from go-DDS's
//! `rtps/spdp.go` (379 LOC, the ecosystem's RTPS correctness oracle — see
//! `ROADMAP.md` Tier 1): [`build_participant_data`]/[`parse_participant_data`]
//! mirror `buildParticipantData`/`parseParticipantData` byte-for-byte;
//! [`SpdpService`] mirrors `spdpService`'s announce/receive/evict loops and
//! known-peers table. See each test's doc comment for the exact go-DDS
//! reproduction command.
//!
//! Not in this sub-phase's scope (later Tier 1/2 work, per `ROADMAP.md`):
//! SEDP peer notification (`onNewPeer`/`onPeerEvicted` — landed separately,
//! see [`SpdpService::set_peer_listener`]) and the `livelinessCb`
//! participant-liveliness callback. The `DiscoveryPlugin` authentication
//! hook (`PID_DISCOVERY_TOKEN`) deferred here landed later, as the v0.5
//! Security milestone's own final checklist item — see this module's
//! "Discovery authentication" section below.
//!
//! # Unicast peer discovery (the "+ unicast" half of SPDP)
//!
//! `ROADMAP.md`'s "Planned — v0.2" SPDP checklist item covers both
//! multicast (above, done since this module's initial landing) and static
//! unicast peer discovery, for environments where multicast routing is
//! unavailable or undesirable (Docker/cloud networks, TSN segments).
//! [`SpdpConfig::peer_locators`]/[`SpdpConfig::with_peer_locators`] adds a
//! list of known peer unicast addresses that [`SpdpService::send_announcement`]
//! sends the same `ParticipantData` announcement to directly (unicast, via
//! the same `send_socket` already used for the multicast send), in addition
//! to the multicast group; [`SpdpConfig::no_multicast`]/
//! [`SpdpConfig::with_no_multicast`] independently disables the multicast
//! send (composed with a non-empty `peer_locators` for unicast-only
//! discovery). No new wire format: the `ParticipantData` payload and RTPS
//! framing are byte-identical to the multicast case (already verified
//! byte-for-byte against go-DDS above) — only the *destination address* of
//! an already-correct encode changes.
//!
//! Mirrors go-DDS's `WithPeerLocators`/`WithNoMulticast` `Option`s
//! (`rtps/participant.go`) in shape — a peer-address list plus an
//! independent multicast-disable flag — translated to this crate's own
//! builder-style config idiom (`SpdpConfig`) rather than go-DDS's
//! functional-options-string signature. One documented deviation, found by
//! inspecting a fresh go-DDS clone rather than assumed: go-DDS's own
//! `peerLocators` field is currently stored by `WithPeerLocators` but never
//! read by `spdpService.sendAnnouncement` (no unicast send is actually
//! wired there), and `noMulticast` only gates the *unrelated* user-data
//! multicast socket (`dataMcastSock`, the next roadmap checklist item), not
//! the SPDP multicast socket/send — `rtps/packet_test.go`'s own
//! `TestWithNoMulticast_ParticipantStarts` comment says as much ("the
//! option is stored but not yet used to skip the bind — that is wired at
//! SPDP level"). So there is no working byte/behavioural oracle to verify
//! this sub-feature against; this implementation follows go-DDS's own doc
//! comments (the stated intent of `WithPeerLocators`/`WithNoMulticast`) as
//! the design reference instead, and rust-DDS's SPDP layer ends up actually
//! wiring the send-time behaviour go-DDS's own API surface still only
//! promises.
//!
//! Receive-side: a unicast SPDP announcement is addressed to a peer's
//! metatraffic unicast port (the same port SEDP unicast traffic already
//! flows to — go-DDS's own `metaSock` field comment describes it as
//! handling "SPDP send + SEDP send/receive (unicast)"), so
//! [`super::dds_participant::RtpsUdpParticipant`] fans the meta socket's
//! incoming datagrams out to both this service and
//! [`super::sedp::SedpService`] — see that module's constructor docs.
//! [`SpdpService::handle_packet`]/[`SpdpService::spawn_receive_loop`]
//! themselves are unchanged: they already accept any
//! `mpsc::Receiver<RtpsDatagram>`, regardless of whether the datagrams on
//! it arrived via a multicast-joined socket or a plain unicast one.
//!
//! # Discovery authentication (HMAC-SHA-256 SPDP signing)
//!
//! `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" milestone's sixth
//! and final checklist item, "HMAC-SHA-256 discovery authentication": an
//! optional [`SpdpConfig::discovery_plugin`]
//! (`Arc<dyn `[`crate::security::discovery::DiscoveryPlugin`]`>`, the
//! module docs' `HmacDiscoveryPlugin` in practice) signs every outbound
//! announcement and verifies every inbound one, mirroring go-DDS's
//! `discoveryPlugin` field (`rtps/participant.go`) threaded into
//! `spdpService.buildParticipantData`/`handlePacket` (`rtps/spdp.go`).
//!
//! [`build_participant_data`] appends the signature as a new `PL_CDR_LE`
//! parameter, `PID_DISCOVERY_TOKEN` (already reserved in
//! [`super::cdr::PID_DISCOVERY_TOKEN`] ahead of this item landing), keyed
//! over this participant's own `guid_prefix` — matching go-DDS's
//! `enc.addParam(pidDiscoveryToken, p.discoveryPlugin.SignDiscovery(p.guidPrefix[:]))`,
//! appended in the same position (after the lease duration, immediately
//! before the sentinel). [`SpdpService::handle_packet`] mirrors go-DDS's
//! receive-side check exactly: [`extract_discovery_token`] scans the
//! decoded payload for `PID_DISCOVERY_TOKEN` (matching go-DDS's
//! `extractDiscoveryToken`, returning `None`/`nil` if absent — never a
//! decode error), and a peer whose token does not verify against the
//! *sender's* `GuidPrefix` (from the RTPS message [`Header`], the same
//! field [`parse_participant_data`] itself trusts) is silently discarded:
//! [`SpdpService::store_peer`] is never called for it, so it never becomes
//! a known peer and SEDP is never notified — indistinguishable from a
//! datagram that never arrived, matching go-DDS's own `return nil` at this
//! point in `handlePacket`.
//!
//! When [`SpdpConfig::discovery_plugin`] is unset (`None`, the default —
//! [`SpdpConfig::new`] does not set one), behaviour is unchanged from
//! every earlier sub-phase: no token is emitted, and every inbound
//! announcement is accepted regardless of its token, matching go-DDS's own
//! `if p.discoveryPlugin != nil { ... }`/`if s.p.discoveryPlugin != nil { ... }`
//! guards (nil plugin ⇒ unauthenticated discovery, the pre-existing
//! default on both sides of the port).
//!
//! # Async model
//!
//! Consistent with `transport.rs` (sub-phase 3) and the crate-wide tokio
//! commitment: the announce loop is driven by `tokio::time::interval`
//! (replacing go-DDS's `time.NewTicker`), the receive loop consumes an
//! `mpsc::Receiver<RtpsDatagram>` produced by
//! [`RtpsSocket::spawn_receive_loop`](super::transport::RtpsSocket::spawn_receive_loop)
//! (replacing go-DDS's `s.p.mcastSock.recv` channel read), and the eviction
//! loop is a second `tokio::time::interval` ticking once per second
//! (replacing go-DDS's `evictLoop`). Each loop is spawned as its own
//! `tokio::task` — the caller stops a loop by `.abort()`-ing its returned
//! `JoinHandle`, the same idiom `transport.rs` already established for
//! `spawn_receive_loop` (replacing go-DDS's `close(s.stop)`).
//!
//! One deliberate deviation from go-DDS: go-DDS's `nextSeqNum` draws from a
//! single **process-wide** atomic counter shared by every participant in
//! the process (`rtps/sedp.go`'s package-level `seqCounter`). RTPS only
//! requires per-writer monotonicity (RTPS 2.3 §8.3.5), so
//! [`SpdpService`] instead keeps its sequence counter scoped to the
//! service instance — simpler and no less correct, since each
//! `SpdpService` is exactly one SPDP writer.
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001) and no panics on
//! malformed/truncated decode input (REQ-ASIL-003 / REQ-RTPS-009):
//! [`parse_participant_data`] and [`SpdpService::handle_packet`] treat
//! malformed input as "ignore this datagram", never as a crash.
//!
//! Internal only: not re-exported from the crate root, not yet wired into
//! `Participant`/`Publisher`/`Subscriber`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use super::cdr::{
    PlCdrDecoder, PlCdrEncoder, PID_BUILTIN_ENDPOINT_SET, PID_DEFAULT_UNICAST_LOCATOR,
    PID_DISCOVERY_TOKEN, PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID,
    PID_PARTICIPANT_LEASE_DURATION, PID_PROTOCOL_VERSION, PID_VENDOR_ID,
};
use super::guid::{
    Guid, GuidPrefix, ENDPOINT_SEDP_PUB_ANNOUNCER, ENDPOINT_SEDP_PUB_DETECTOR,
    ENDPOINT_SEDP_SUB_ANNOUNCER, ENDPOINT_SEDP_SUB_DETECTOR, ENDPOINT_SPDP_ANNOUNCER,
    ENDPOINT_SPDP_DETECTOR, ENTITYID_PARTICIPANT, ENTITYID_SPDP_READER, ENTITYID_SPDP_WRITER,
};
use super::locator::Locator;
use super::message::{
    decode_data_submessage, encode_data_submessage, wrap_in_rtps_message, Header, SequenceNumber,
    SubmessageIter, VendorId, PROTOCOL_VERSION_2_3, SUBMSG_DATA, VENDOR_ID_RUST_DDS,
};
use super::transport::{
    meta_multicast_port, RtpsDatagram, RtpsSocket, SPDP_MULTICAST_ADDR, SPDP_MULTICAST_ADDR_V6,
};
use crate::security::discovery::DiscoveryPlugin;

/// Fallback lease duration applied to a peer whose announcement did not
/// carry a (non-zero) `PID_PARTICIPANT_LEASE_DURATION`. Matches go-DDS's
/// `defaultLeaseDuration`.
//fusa:req REQ-RTPS-028
pub const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(10);

/// Default interval between SPDP announcements, used when
/// [`SpdpConfig::new`] is not overridden with
/// [`SpdpConfig::with_announce_period`]. Matches go-DDS's
/// `spdpAnnouncePeriod`.
//fusa:req REQ-RTPS-027
pub const SPDP_ANNOUNCE_PERIOD: Duration = Duration::from_secs(2);

/// Interval between eviction sweeps of the known-peers table. Matches
/// go-DDS's `evictLoop`'s `time.NewTicker(time.Second)`.
//fusa:req REQ-RTPS-028
const EVICT_PERIOD: Duration = Duration::from_secs(1);

/// The lease duration this crate always advertises in its own outbound
/// ParticipantProxy data (`PID_PARTICIPANT_LEASE_DURATION`). Matches
/// go-DDS's `buildParticipantData`, which hard-codes 10 seconds rather than
/// deriving it from `defaultLeaseDuration` (the two happen to be equal).
const ADVERTISED_LEASE_SECS: u32 = 10;

/// All six SPDP+SEDP builtin endpoints this crate's `ParticipantProxy`
/// advertises support for (`PID_BUILTIN_ENDPOINT_SET` = `0x3f`). Matches
/// go-DDS's `buildParticipantData`.
const ALL_BUILTIN_ENDPOINTS: u32 = ENDPOINT_SPDP_ANNOUNCER
    | ENDPOINT_SPDP_DETECTOR
    | ENDPOINT_SEDP_PUB_ANNOUNCER
    | ENDPOINT_SEDP_PUB_DETECTOR
    | ENDPOINT_SEDP_SUB_ANNOUNCER
    | ENDPOINT_SEDP_SUB_DETECTOR;

// ---------------------------------------------------------------------------
// SpdpConfig
// ---------------------------------------------------------------------------

/// Fixed configuration for one participant's [`SpdpService`]: identity
/// (`guid_prefix`, `vendor_id`), the two unicast ports it advertises for
/// SEDP/user-data traffic, and the announce cadence.
///
/// Not [`Copy`] (unlike earlier sub-phases' fixed-size configs) because
/// [`SpdpConfig::peer_locators`] is a growable list; use `.clone()` where an
/// implicit copy previously sufficed.
///
/// `Debug`/`PartialEq`/`Eq` are implemented by hand (below) rather than
/// derived, because [`SpdpConfig::discovery_plugin`]'s `Arc<dyn
/// DiscoveryPlugin>` cannot derive any of the three: the trait object has
/// no `Debug` bound and no structural equality. The hand-written impls
/// compare/print every other field exactly as `derive` would;
/// `discovery_plugin` prints as `Some`/`None` only (not its contents) and
/// compares via `Arc::ptr_eq` when both sides are `Some` — two configs are
/// equal only if they share the *same* plugin instance (or both have
/// none), matching `Arc<T>`'s own usual `ptr_eq`-based identity notion
/// where `T` isn't itself comparable.
//fusa:req REQ-RTPS-025
#[derive(Clone)]
pub struct SpdpConfig {
    /// Domain ID, used to compute the SPDP multicast port (RTPS 2.3
    /// §9.6.1).
    pub domain: u32,
    /// This participant's own `GuidPrefix`. Announcements whose header
    /// carries this same prefix are ignored (self-filtering; see
    /// [`SpdpService::handle_packet`]).
    pub guid_prefix: GuidPrefix,
    /// `VendorId` stamped into the RTPS message header and the outbound
    /// `PID_VENDOR_ID` parameter. Defaults to
    /// [`VENDOR_ID_RUST_DDS`](super::message::VENDOR_ID_RUST_DDS) via
    /// [`SpdpConfig::new`]; overridable for testing byte-exact parity
    /// against go-DDS reference output (which uses its own `0x0127`).
    pub vendor_id: VendorId,
    /// The metatraffic (SEDP) unicast port this participant listens on,
    /// advertised as `PID_METATRAFFIC_UNICAST_LOCATOR`.
    pub meta_unicast_port: u16,
    /// The user-data unicast port this participant listens on, advertised
    /// as `PID_DEFAULT_UNICAST_LOCATOR`.
    pub data_unicast_port: u16,
    /// Interval between announcements.
    pub announce_period: Duration,
    /// Upper bound of a uniformly-random delay added before each
    /// *periodic* announcement (not the initial one), to avoid
    /// synchronised floods when many participants start simultaneously.
    /// `Duration::ZERO` (the [`SpdpConfig::new`] default) disables jitter.
    pub jitter: Duration,
    /// Static peer unicast addresses to send SPDP announcements directly
    /// to, in addition to the multicast group (or instead of it, when
    /// [`SpdpConfig::no_multicast`] is set). Empty by default — set via
    /// [`SpdpConfig::with_peer_locators`]. Mirrors go-DDS's
    /// `WithPeerLocators`/`peerLocators` in shape; see the module docs'
    /// "Unicast peer discovery" section for the one behavioural deviation
    /// (go-DDS's own field is unwired, this one is not).
    pub peer_locators: Vec<SocketAddr>,
    /// When `true`, [`SpdpService::send_announcement`] does not send to the
    /// multicast group at all — only to [`SpdpConfig::peer_locators`].
    /// `false` by default — set via [`SpdpConfig::with_no_multicast`].
    /// Intended to be combined with a non-empty `peer_locators` for
    /// unicast-only discovery; setting it with an empty `peer_locators`
    /// means this participant sends no SPDP announcements at all (it can
    /// still be *found* by a peer that lists it in that peer's own
    /// `peer_locators`). Mirrors go-DDS's `WithNoMulticast`/`noMulticast` in
    /// shape — see the module docs' "Unicast peer discovery" section for
    /// the one behavioural deviation.
    pub no_multicast: bool,
    /// When `true`, [`build_participant_data`] advertises `LOCATOR_KIND_UDPV6`
    /// zero-address locators (instead of `LOCATOR_KIND_UDPV4`) and
    /// [`SpdpService::send_announcement`] sends to
    /// [`super::transport::SPDP_MULTICAST_ADDR_V6`] instead of
    /// [`SPDP_MULTICAST_ADDR`] — the address-family switch behind
    /// [`super::dds_participant::RtpsUdpParticipantConfig::with_ipv6`].
    /// `false` by default — set via [`SpdpConfig::with_ipv6`]. See that
    /// method's docs for why this is a switch, not a dual-stack add-on.
    //fusa:req REQ-RTPS-025
    pub ipv6: bool,
    /// Signs outbound SPDP announcements and verifies inbound ones — see
    /// the module docs' "Discovery authentication" section. `None` by
    /// default (set via [`SpdpConfig::new`]): unauthenticated discovery,
    /// unchanged from every earlier sub-phase. Set via
    /// [`SpdpConfig::with_discovery_plugin`]. Mirrors go-DDS's
    /// `discoveryPlugin` field (`rtps/participant.go`), which lives on
    /// `*participant` rather than a value-config struct — this crate's
    /// `SpdpConfig` already fills that "everything one `SpdpService`
    /// needs" role for every other per-participant SPDP setting, so this
    /// one field joins it rather than introducing a second config type.
    //fusa:req REQ-SEC-028
    pub discovery_plugin: Option<Arc<dyn DiscoveryPlugin>>,
}

impl std::fmt::Debug for SpdpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpdpConfig")
            .field("domain", &self.domain)
            .field("guid_prefix", &self.guid_prefix)
            .field("vendor_id", &self.vendor_id)
            .field("meta_unicast_port", &self.meta_unicast_port)
            .field("data_unicast_port", &self.data_unicast_port)
            .field("announce_period", &self.announce_period)
            .field("jitter", &self.jitter)
            .field("peer_locators", &self.peer_locators)
            .field("no_multicast", &self.no_multicast)
            .field("ipv6", &self.ipv6)
            .field("discovery_plugin", &self.discovery_plugin.is_some())
            .finish()
    }
}

impl PartialEq for SpdpConfig {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain
            && self.guid_prefix == other.guid_prefix
            && self.vendor_id == other.vendor_id
            && self.meta_unicast_port == other.meta_unicast_port
            && self.data_unicast_port == other.data_unicast_port
            && self.announce_period == other.announce_period
            && self.jitter == other.jitter
            && self.peer_locators == other.peer_locators
            && self.no_multicast == other.no_multicast
            && self.ipv6 == other.ipv6
            && match (&self.discovery_plugin, &other.discovery_plugin) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl Eq for SpdpConfig {}

impl SpdpConfig {
    /// Builds a config with this crate's own vendor ID, the default
    /// 2-second announce period, and no jitter.
    //fusa:req REQ-RTPS-025
    pub fn new(
        domain: u32,
        guid_prefix: GuidPrefix,
        meta_unicast_port: u16,
        data_unicast_port: u16,
    ) -> Self {
        SpdpConfig {
            domain,
            guid_prefix,
            vendor_id: VENDOR_ID_RUST_DDS,
            meta_unicast_port,
            data_unicast_port,
            announce_period: SPDP_ANNOUNCE_PERIOD,
            jitter: Duration::ZERO,
            peer_locators: Vec::new(),
            no_multicast: false,
            ipv6: false,
            discovery_plugin: None,
        }
    }

    /// Overrides the announce period (builder style).
    pub fn with_announce_period(mut self, period: Duration) -> Self {
        self.announce_period = period;
        self
    }

    /// Overrides the jitter upper bound (builder style).
    pub fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    /// Adds static peer unicast addresses (builder style) — see
    /// [`SpdpConfig::peer_locators`]. Additive across repeated calls,
    /// matching go-DDS's `WithPeerLocators(addrs ...string)` (which
    /// `append`s rather than replaces).
    //fusa:req REQ-RTPS-059
    pub fn with_peer_locators(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.peer_locators.extend(addrs);
        self
    }

    /// Disables SPDP multicast send (builder style) — see
    /// [`SpdpConfig::no_multicast`].
    //fusa:req REQ-RTPS-059
    pub fn with_no_multicast(mut self) -> Self {
        self.no_multicast = true;
        self
    }

    /// Switches this config's advertised locator kind and multicast
    /// destination from IPv4 to IPv6 (builder style) — see [`SpdpConfig::ipv6`].
    //fusa:req REQ-RTPS-025
    pub fn with_ipv6(mut self) -> Self {
        self.ipv6 = true;
        self
    }

    /// Sets the [`DiscoveryPlugin`] this participant signs outbound SPDP
    /// announcements with and verifies inbound ones against (builder
    /// style) — see [`SpdpConfig::discovery_plugin`] and the module docs'
    /// "Discovery authentication" section. `None` (unauthenticated
    /// discovery) by default. A later call replaces an earlier one, rather
    /// than composing multiple plugins — matches every other single-value
    /// `SpdpConfig` builder method in this `impl` block.
    //fusa:req REQ-SEC-028
    pub fn with_discovery_plugin(mut self, plugin: Arc<dyn DiscoveryPlugin>) -> Self {
        self.discovery_plugin = Some(plugin);
        self
    }
}

// ---------------------------------------------------------------------------
// ParticipantProxy
// ---------------------------------------------------------------------------

/// The addresses and metadata needed to exchange SEDP traffic with a
/// remote participant, decoded from its SPDP announcement. Matches
/// go-DDS's `participantProxy`.
//fusa:req REQ-RTPS-026
#[derive(Clone, Debug, PartialEq)]
pub struct ParticipantProxy {
    pub guid: Guid,
    pub metatraffic_unicast: Locator,
    pub default_unicast: Locator,
    pub builtin_endpoints: u32,
    /// `Duration::ZERO` means "not present in the announcement" — callers
    /// (i.e. [`SpdpService::store_peer`]) apply [`DEFAULT_LEASE_DURATION`]
    /// in that case, matching go-DDS's `storePeer`.
    pub lease_duration: Duration,
    /// `None` until [`SpdpService::store_peer`] records it; a bare
    /// [`parse_participant_data`] call never sets this, matching go-DDS's
    /// `parseParticipantData` (which never touches `lastSeen` either —
    /// only `storePeer` does).
    pub last_seen: Option<Instant>,
}

// ---------------------------------------------------------------------------
// build_participant_data / parse_participant_data
// ---------------------------------------------------------------------------

/// Builds the `PL_CDR_LE`-encoded ParticipantProxy payload advertised in
/// this participant's SPDP DATA submessage. Matches go-DDS's
/// `buildParticipantData` byte-for-byte (parameter order: protocol
/// version, vendor ID, participant GUID, builtin endpoint set, metatraffic
/// unicast locator, default unicast locator, lease duration).
///
/// The metatraffic/default unicast locators always carry the all-zero
/// (`0.0.0.0`) address — matching go-DDS's own `locatorFromUDP(&net.UDPAddr{IP:
/// net.IPv4zero}, ...)` — since the advertising participant does not know
/// which of its own interfaces a given peer will see it from; receivers
/// fill in the real address from the announcement's UDP source address
/// (see [`parse_participant_data`]).
///
/// When `cfg.discovery_plugin` is set, one further parameter is appended
/// after the lease duration and before the sentinel: `PID_DISCOVERY_TOKEN`,
/// the plugin's `sign_discovery(&cfg.guid_prefix.0)` output — see the
/// module docs' "Discovery authentication" section. Omitted entirely when
/// `cfg.discovery_plugin` is `None` (the default), leaving every earlier
/// sub-phase's byte-exact output unchanged.
//fusa:req REQ-RTPS-025
//fusa:req REQ-SEC-028
pub fn build_participant_data(cfg: &SpdpConfig) -> Vec<u8> {
    let mut enc = PlCdrEncoder::new();

    enc.add_bytes(
        PID_PROTOCOL_VERSION,
        &[PROTOCOL_VERSION_2_3.major, PROTOCOL_VERSION_2_3.minor, 0, 0],
    );
    enc.add_bytes(
        PID_VENDOR_ID,
        &[cfg.vendor_id.0[0], cfg.vendor_id.0[1], 0, 0],
    );

    let guid = Guid {
        prefix: cfg.guid_prefix,
        entity: ENTITYID_PARTICIPANT,
    };
    enc.add_guid(PID_PARTICIPANT_GUID, &guid);

    enc.add_u32(PID_BUILTIN_ENDPOINT_SET, ALL_BUILTIN_ENDPOINTS);

    let meta_locator = zero_locator(cfg.ipv6, cfg.meta_unicast_port);
    enc.add_locator(PID_METATRAFFIC_UNICAST_LOCATOR, &meta_locator);

    let data_locator = zero_locator(cfg.ipv6, cfg.data_unicast_port);
    enc.add_locator(PID_DEFAULT_UNICAST_LOCATOR, &data_locator);

    let mut lease = Vec::with_capacity(8);
    lease.extend_from_slice(&ADVERTISED_LEASE_SECS.to_le_bytes());
    lease.extend_from_slice(&0u32.to_le_bytes());
    enc.add_bytes(PID_PARTICIPANT_LEASE_DURATION, &lease);

    if let Some(plugin) = &cfg.discovery_plugin {
        let tag = plugin.sign_discovery(&cfg.guid_prefix.0);
        enc.add_bytes(PID_DISCOVERY_TOKEN, &tag);
    }

    enc.finish()
}

/// Scans a decoded `PL_CDR_LE` `payload` for `PID_DISCOVERY_TOKEN` and
/// returns a copy of its value, or `None` if the PID is absent — matches
/// go-DDS's `extractDiscoveryToken` (`rtps/spdp.go`). Returns `None` (never
/// an error) if `payload` does not even parse as a valid `PL_CDR_LE`
/// encapsulation, the same tolerant-decode posture as
/// [`parse_participant_data`]; never panics (REQ-RTPS-009).
//fusa:req REQ-SEC-028
//fusa:req REQ-RTPS-009
pub fn extract_discovery_token(payload: &[u8]) -> Option<Vec<u8>> {
    let decoder = PlCdrDecoder::new(payload).ok()?;
    for param in decoder {
        if param.pid == PID_DISCOVERY_TOKEN {
            return Some(param.value.to_vec());
        }
    }
    None
}

/// Builds a zero-address `Locator` of the family selected by `ipv6` at
/// `port` — the [`build_participant_data`] zero-address-locator convention
/// (see that function's doc comment; `sedp.rs`'s `build_endpoint_data` has
/// its own copy of the same idea, matching the pre-existing
/// `fill_in_zero_address` duplication between the two modules), extended to
/// also select `LOCATOR_KIND_UDPV6` over `LOCATOR_KIND_UDPV4` when `ipv6` is
/// set — the wire encoding itself is unchanged from what
/// [`super::locator::Locator::udp_v4`]/`udp_v6` already verify
/// byte-for-byte against go-DDS (see `locator.rs`'s own tests); only *which*
/// of the two this function picks is new.
//fusa:req REQ-RTPS-025
fn zero_locator(ipv6: bool, port: u16) -> Locator {
    if ipv6 {
        Locator::udp_v6([0u8; 16], u32::from(port))
    } else {
        Locator::udp_v4([0, 0, 0, 0], u32::from(port))
    }
}

/// The SPDP multicast destination address for [`SpdpService::send_announcement`]:
/// [`SPDP_MULTICAST_ADDR_V6`] at `port` when `ipv6` is set, else
/// [`SPDP_MULTICAST_ADDR`] — the same address-family switch as
/// [`zero_locator`], pulled into its own pure function so it is testable
/// without a real socket/domain (see this module's IPv6 tests).
//fusa:req REQ-RTPS-017
fn spdp_multicast_dst(ipv6: bool, port: u16) -> SocketAddr {
    if ipv6 {
        SocketAddr::from((SPDP_MULTICAST_ADDR_V6, port))
    } else {
        SocketAddr::from((SPDP_MULTICAST_ADDR, port))
    }
}

/// Decodes a `PL_CDR_LE` ParticipantProxy `payload` (an SPDP DATA
/// submessage's payload) into a [`ParticipantProxy`]. `prefix` is the
/// sending participant's `GuidPrefix`, taken from the enclosing RTPS
/// message [`Header`] (used as the fallback GUID if the payload carries no
/// `PID_PARTICIPANT_GUID`, and matched against a decoded
/// `PID_PARTICIPANT_GUID` the same way go-DDS's `parseParticipantData`
/// does — the payload's own value wins if present). `from` is the UDP
/// datagram's sender address; when a decoded locator's address is all-zero
/// (`0.0.0.0`/`::`, see [`build_participant_data`]'s doc comment), `from`'s
/// address is filled in, provided its family matches the locator's own
/// `kind` (`LOCATOR_KIND_UDPV4` filled from a `SocketAddr::V4` sender,
/// `LOCATOR_KIND_UDPV6` from a `SocketAddr::V6` one) — matches go-DDS's
/// `parseParticipantData` fill-in behaviour exactly for the IPv4 case (its
/// only case; go-DDS's own IPv4/IPv6 SPDP payloads are never mixed-family
/// today; see [`SpdpConfig::ipv6`]'s doc comment), extended to the IPv6 case
/// by the same rule.
///
/// Returns `None` only if `payload` does not start with a valid `PL_CDR_LE`
/// encapsulation header; a payload that parses but is missing individual
/// parameters still yields `Some` with those fields left at their
/// [`Default`]/zero values, matching go-DDS's tolerant field-by-field
/// decode loop. Never panics (REQ-RTPS-009).
//fusa:req REQ-RTPS-026
//fusa:req REQ-RTPS-009
pub fn parse_participant_data(
    prefix: GuidPrefix,
    payload: &[u8],
    from: SocketAddr,
) -> Option<ParticipantProxy> {
    let decoder = PlCdrDecoder::new(payload).ok()?;

    let mut proxy = ParticipantProxy {
        guid: Guid {
            prefix,
            entity: ENTITYID_PARTICIPANT,
        },
        metatraffic_unicast: Locator::default(),
        default_unicast: Locator::default(),
        builtin_endpoints: 0,
        lease_duration: Duration::ZERO,
        last_seen: None,
    };

    for param in decoder {
        match param.pid {
            PID_METATRAFFIC_UNICAST_LOCATOR => {
                if let Ok(mut loc) = Locator::decode(param.value) {
                    fill_in_zero_address(&mut loc, from);
                    proxy.metatraffic_unicast = loc;
                }
            }
            PID_DEFAULT_UNICAST_LOCATOR => {
                if let Ok(mut loc) = Locator::decode(param.value) {
                    fill_in_zero_address(&mut loc, from);
                    proxy.default_unicast = loc;
                }
            }
            PID_BUILTIN_ENDPOINT_SET => {
                if param.value.len() >= 4 {
                    proxy.builtin_endpoints = u32::from_le_bytes([
                        param.value[0],
                        param.value[1],
                        param.value[2],
                        param.value[3],
                    ]);
                }
            }
            PID_PARTICIPANT_LEASE_DURATION => {
                if param.value.len() >= 4 {
                    let secs = u32::from_le_bytes([
                        param.value[0],
                        param.value[1],
                        param.value[2],
                        param.value[3],
                    ]);
                    if secs > 0 {
                        proxy.lease_duration = Duration::from_secs(u64::from(secs));
                    }
                }
            }
            PID_PARTICIPANT_GUID => {
                if let Ok(g) = Guid::decode(param.value) {
                    proxy.guid = g;
                }
            }
            _ => {}
        }
    }

    Some(proxy)
}

/// If `loc`'s address is all-zero (`0.0.0.0`/`::`), fills in `from`'s
/// octets — matches go-DDS's `if proxy.metatrafficUnicast.Address ==
/// ([16]byte{}) { ... }` fill-in for the IPv4 case (its only case; see
/// [`SpdpConfig::ipv6`]'s doc comment), extended here to also fill an
/// IPv6-kind locator from an IPv6 sender. A locator/sender family mismatch
/// (e.g. a `LOCATOR_KIND_UDPV6` locator decoded from a datagram whose UDP
/// source turned out to be IPv4, which should not happen in practice since
/// a participant's own socket family determines both) is left unfilled
/// rather than guessed at — matches [`Locator::udp_addr`]'s own
/// never-guess convention for an unrecognised/mismatched case.
//fusa:req REQ-RTPS-026
fn fill_in_zero_address(loc: &mut Locator, from: SocketAddr) {
    if loc.address != [0u8; 16] {
        return;
    }
    match (loc.kind, from) {
        (super::locator::LOCATOR_KIND_UDPV4, SocketAddr::V4(v4)) => {
            loc.address[12..16].copy_from_slice(&v4.ip().octets());
        }
        (super::locator::LOCATOR_KIND_UDPV6, SocketAddr::V6(v6)) => {
            loc.address.copy_from_slice(&v6.ip().octets());
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// SpdpService
// ---------------------------------------------------------------------------

/// Manages one participant's SPDP announce/receive/evict loops and its
/// known-peers table. Matches go-DDS's `spdpService`.
///
/// Construct with [`SpdpService::new`], then spawn whichever of
/// [`spawn_announce_loop`](SpdpService::spawn_announce_loop),
/// [`spawn_receive_loop`](SpdpService::spawn_receive_loop), and
/// [`spawn_evict_loop`](SpdpService::spawn_evict_loop) are needed —
/// mirrors go-DDS's `start()`, which launches all three as goroutines.
/// Each returns a `JoinHandle<()>`; `.abort()` it to stop that loop
/// (the tokio idiom already established by
/// [`transport::RtpsSocket::spawn_receive_loop`](super::transport::RtpsSocket::spawn_receive_loop),
/// replacing go-DDS's `close(s.stop)`).
#[derive(Debug)]
pub struct SpdpService {
    config: SpdpConfig,
    send_socket: Arc<RtpsSocket>,
    seq_counter: AtomicU32,
    peers: RwLock<HashMap<GuidPrefix, ParticipantProxy>>,
    /// Set via [`SpdpService::set_peer_listener`]; see that method's docs.
    peer_listener: RwLock<Option<mpsc::UnboundedSender<ParticipantProxy>>>,
    announces_sent: AtomicU64,
    announces_received: AtomicU64,
    peer_evictions: AtomicU64,
}

impl SpdpService {
    /// Creates a new service. `send_socket` is the unicast socket used to
    /// *send* announcements to the SPDP multicast group (matches go-DDS's
    /// `p.metaSock.send(dst, msg)` — a unicast socket sending to a
    /// multicast destination, not a multicast-joined socket). Receiving
    /// requires a separate multicast-joined socket
    /// ([`RtpsSocket::bind_multicast_v4`](super::transport::RtpsSocket::bind_multicast_v4));
    /// its `spawn_receive_loop`-produced `mpsc::Receiver` is handed to
    /// [`SpdpService::spawn_receive_loop`] separately, keeping this service
    /// decoupled from the transport layer's socket lifecycle.
    //fusa:req REQ-RTPS-027
    pub fn new(config: SpdpConfig, send_socket: Arc<RtpsSocket>) -> Arc<Self> {
        Arc::new(SpdpService {
            config,
            send_socket,
            seq_counter: AtomicU32::new(0),
            peers: RwLock::new(HashMap::new()),
            peer_listener: RwLock::new(None),
            announces_sent: AtomicU64::new(0),
            announces_received: AtomicU64::new(0),
            peer_evictions: AtomicU64::new(0),
        })
    }

    /// This service's configuration.
    pub fn config(&self) -> &SpdpConfig {
        &self.config
    }

    /// Registers `tx` to receive a copy of every [`ParticipantProxy`] this
    /// service stores from a decoded SPDP announcement — including repeat
    /// announcements from an already-known peer, not just newly-seen ones
    /// (matching go-DDS's `spdpService.handlePacket`, which calls
    /// `s.p.sedp.onNewPeer(proxy)` unconditionally on every successfully
    /// decoded announcement, not gated on "is this peer new"). At most one
    /// listener is kept; a later call replaces an earlier one.
    ///
    /// This exists for the same reason [`super::sedp::SedpService::set_match_listener`]
    /// does: go-DDS's `spdpService` reaches directly into its owning
    /// `*participant` (`s.p.sedp.onNewPeer`) to notify SEDP of a
    /// newly-observed peer; `SpdpService` predates the RTPS participant
    /// runtime type that sub-phase 6 introduces (`super::participant`), so
    /// it cannot depend on `sedp`/`participant` directly without inverting
    /// the module dependency graph (`sedp` already depends on `spdp`). A
    /// future caller — [`super::participant::RtpsParticipant::spawn_spdp_peer_listener`] —
    /// bridges the two by forwarding each event into
    /// [`super::sedp::SedpService::on_new_peer`].
    //fusa:req REQ-RTPS-042
    pub async fn set_peer_listener(&self, tx: mpsc::UnboundedSender<ParticipantProxy>) {
        *self.peer_listener.write().await = Some(tx);
    }

    fn next_seq_num(&self) -> u32 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Builds and sends one SPDP announcement: to the domain's multicast
    /// group (unless [`SpdpConfig::no_multicast`] is set) and directly
    /// (unicast) to every address in [`SpdpConfig::peer_locators`]. Matches
    /// go-DDS's `sendAnnouncement`, extended with the unicast-peer send
    /// go-DDS's own `peerLocators` field does not yet wire up (see the
    /// module docs' "Unicast peer discovery" section).
    ///
    /// Every configured destination is attempted even if an earlier one
    /// fails (best-effort per destination, matching this method's own
    /// pre-existing single-destination behaviour of swallowing send errors
    /// in [`SpdpService::spawn_announce_loop`]); if `no_multicast` is unset
    /// but the domain's multicast port formula overflows, that failure is
    /// recorded the same way a failed unicast send is, rather than
    /// aborting before any peer send is attempted. Returns the last error
    /// encountered, if any; `Ok(())` if every attempted destination (there
    /// may be zero, if `no_multicast` is set and `peer_locators` is empty)
    /// succeeded.
    //fusa:req REQ-RTPS-027
    //fusa:req REQ-RTPS-059
    pub async fn send_announcement(&self) -> std::io::Result<()> {
        self.announces_sent.fetch_add(1, Ordering::Relaxed);

        let payload = build_participant_data(&self.config);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber {
                high: 0,
                low: self.next_seq_num(),
            },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: self.config.vendor_id,
            guid_prefix: self.config.guid_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        let mut last_err = None;

        if !self.config.no_multicast {
            match meta_multicast_port(self.config.domain) {
                Some(port) => {
                    let dst = spdp_multicast_dst(self.config.ipv6, port);
                    if let Err(e) = self.send_socket.send_to(&msg, dst).await {
                        last_err = Some(e);
                    }
                }
                None => {
                    last_err = Some(std::io::Error::other(format!(
                        "rtps: domain {} out of range for SPDP multicast port",
                        self.config.domain
                    )));
                }
            }
        }

        for &peer in &self.config.peer_locators {
            if let Err(e) = self.send_socket.send_to(&msg, peer).await {
                last_err = Some(e);
            }
        }

        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Spawns the periodic announce loop: sends immediately (matching
    /// go-DDS's `s.sendAnnouncement()` before entering its ticker loop),
    /// then every `config.announce_period` — with a uniformly-random delay
    /// of up to `config.jitter` inserted before each *periodic* send, never
    /// before the initial one, matching go-DDS's `announceLoop`.
    //fusa:req REQ-RTPS-027
    pub fn spawn_announce_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let _ = self.send_announcement().await;

            let mut interval = tokio::time::interval(self.config.announce_period);
            // The first tick of a freshly-created `interval` fires
            // immediately; consume it without sending since the initial
            // send above already covers t=0.
            interval.tick().await;

            loop {
                interval.tick().await;
                if self.config.jitter > Duration::ZERO {
                    tokio::time::sleep(random_duration_below(self.config.jitter)).await;
                }
                let _ = self.send_announcement().await;
            }
        })
    }

    /// Spawns the receive loop: consumes `rx` (produced by
    /// [`RtpsSocket::spawn_receive_loop`](super::transport::RtpsSocket::spawn_receive_loop)
    /// on a multicast-joined socket) and decodes/stores each SPDP
    /// announcement. Matches go-DDS's `receiveLoop`. Exits once `rx` is
    /// closed (its sender dropped).
    //fusa:req REQ-RTPS-026
    pub fn spawn_receive_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<RtpsDatagram>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(datagram) = rx.recv().await {
                self.handle_packet(&datagram.data, datagram.from).await;
            }
        })
    }

    /// Spawns the once-per-second eviction sweep of the known-peers table.
    /// Matches go-DDS's `evictLoop`.
    //fusa:req REQ-RTPS-028
    pub fn spawn_evict_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(EVICT_PERIOD);
            loop {
                interval.tick().await;
                self.evict_expired().await;
            }
        })
    }

    /// Decodes one received datagram and, if it is a well-formed SPDP
    /// announcement from a peer (not this participant's own), stores it.
    /// Matches go-DDS's `handlePacket`. Malformed input, non-DATA
    /// submessages, and DATA submessages not from the SPDP writer entity
    /// are silently ignored — never panics (REQ-RTPS-009).
    ///
    /// When `self.config.discovery_plugin` is set, a well-formed
    /// announcement is additionally required to carry a
    /// `PID_DISCOVERY_TOKEN` that verifies against the *sender's*
    /// `GuidPrefix` (the RTPS message header's, not any
    /// `PID_PARTICIPANT_GUID` the payload itself claims — matching
    /// go-DDS's `s.p.discoveryPlugin.VerifyDiscovery(hdr.GuidPrefix[:], token)`);
    /// one that does not is discarded exactly like malformed input — never
    /// stored, never notified to SEDP — see the module docs' "Discovery
    /// authentication" section.
    //fusa:req REQ-RTPS-026
    //fusa:req REQ-RTPS-028
    //fusa:req REQ-RTPS-009
    //fusa:req REQ-SEC-029
    async fn handle_packet(&self, data: &[u8], from: SocketAddr) {
        let Ok(header) = Header::decode(data) else {
            return;
        };
        // Ignore our own announcements.
        if header.guid_prefix == self.config.guid_prefix {
            return;
        }
        let body = &data[Header::LEN..];
        for result in SubmessageIter::new(body) {
            let Ok(raw) = result else {
                break;
            };
            if raw.id != SUBMSG_DATA {
                continue;
            }
            let Ok(ds) = decode_data_submessage(raw.flags, raw.body) else {
                continue;
            };
            if ds.writer_entity_id != ENTITYID_SPDP_WRITER {
                continue;
            }
            let Some(payload) = ds.payload else {
                continue;
            };
            // Verify the discovery authentication token when a plugin is
            // configured — matches go-DDS's own guard; an absent or
            // wrongly-signed token is silently discarded, never treated as
            // an unauthenticated pass. See the module docs' "Discovery
            // authentication" section.
            if let Some(plugin) = &self.config.discovery_plugin {
                let token = extract_discovery_token(&payload).unwrap_or_default();
                if !plugin.verify_discovery(&header.guid_prefix.0, &token) {
                    continue;
                }
            }
            if let Some(proxy) = parse_participant_data(header.guid_prefix, &payload, from) {
                self.store_peer(proxy).await;
            }
        }
    }

    /// Records `proxy` in the known-peers table, keyed by GUID prefix,
    /// stamping `last_seen = Instant::now()` and applying
    /// [`DEFAULT_LEASE_DURATION`] if `proxy.lease_duration` is zero.
    /// Returns `true` if this is a newly-seen peer (matches go-DDS's
    /// `storePeer`, whose return-equivalent — `!existed` — feeds its
    /// liveliness callback; that callback is out of this sub-phase's
    /// scope, but the signal is preserved for a future caller).
    //fusa:req REQ-RTPS-026
    async fn store_peer(&self, mut proxy: ParticipantProxy) -> bool {
        self.announces_received.fetch_add(1, Ordering::Relaxed);
        proxy.last_seen = Some(Instant::now());
        if proxy.lease_duration.is_zero() {
            proxy.lease_duration = DEFAULT_LEASE_DURATION;
        }
        let is_new = {
            let mut peers = self.peers.write().await;
            peers.insert(proxy.guid.prefix, proxy.clone()).is_none()
        };
        if let Some(tx) = self.peer_listener.read().await.as_ref() {
            // Unconditional, matching go-DDS's own per-packet call — see
            // set_peer_listener's docs. A closed receiver just means no one
            // is listening (yet); dropping the event is fine.
            let _ = tx.send(proxy);
        }
        is_new
    }

    /// Removes every peer whose lease has expired (`now - last_seen >
    /// lease_duration`) and bumps [`SpdpService::peer_evictions`]. Matches
    /// go-DDS's `evictExpired`.
    //fusa:req REQ-RTPS-028
    async fn evict_expired(&self) {
        let now = Instant::now();
        let mut evicted = 0u64;
        let mut peers = self.peers.write().await;
        peers.retain(|_, peer| {
            let lease = if peer.lease_duration.is_zero() {
                DEFAULT_LEASE_DURATION
            } else {
                peer.lease_duration
            };
            // A peer that somehow has no `last_seen` yet (never happens via
            // `store_peer`, which always sets it) is treated as just seen
            // rather than immediately evicted.
            let last_seen = peer.last_seen.unwrap_or(now);
            let expired = now.duration_since(last_seen) > lease;
            if expired {
                evicted += 1;
            }
            !expired
        });
        drop(peers);
        if evicted > 0 {
            self.peer_evictions.fetch_add(evicted, Ordering::Relaxed);
        }
    }

    /// A snapshot of every currently-known peer. Matches go-DDS's
    /// `allPeers`.
    pub async fn known_peers(&self) -> Vec<ParticipantProxy> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Total announcements sent since this service was created.
    pub fn announces_sent(&self) -> u64 {
        self.announces_sent.load(Ordering::Relaxed)
    }

    /// Total valid SPDP announcements received from peers (each `storePeer`
    /// call, including re-announcements from an already-known peer).
    pub fn announces_received(&self) -> u64 {
        self.announces_received.load(Ordering::Relaxed)
    }

    /// Total peers evicted for an expired lease since this service was
    /// created.
    pub fn peer_evictions(&self) -> u64 {
        self.peer_evictions.load(Ordering::Relaxed)
    }
}

/// Returns a uniformly-random `Duration` in `[0, max)`. `max == 0` returns
/// `Duration::ZERO`. Matches go-DDS's
/// `time.Duration(rand.Int63n(int64(s.p.spdpJitter)))` in spirit (a random
/// delay strictly less than the configured jitter bound), not
/// bit-for-bit — jitter is a timing behaviour, not a wire-format value,
/// so there is no byte-exact oracle to match here.
fn random_duration_below(max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    use rand::Rng;
    let max_nanos = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX);
    let n = rand::thread_rng().gen_range(0..max_nanos.max(1));
    Duration::from_nanos(n)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ascending_prefix() -> GuidPrefix {
        let mut b = [0u8; 12];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i + 1) as u8; // safe: i in [0,11], (i+1) in [1,12] fits u8
        }
        GuidPrefix(b)
    }

    // Reference bytes/values reproduced from go-DDS's actual rtps package
    // (real buildParticipantData/parseParticipantData/
    // marshalDataSubmessage/wrapInRTPSMessage, not reimplemented). Go
    // reproduction (package-local scratch test file,
    // `rtps/zzrepro_spdp_test.go`, never committed to go-DDS, deleted after
    // use):
    //
    //   var prefix GuidPrefix
    //   for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    //
    //   metaSock, _ := newUnicastSocket(17410) // binds exactly port 17410
    //   dataSock, _ := newUnicastSocket(17411)
    //   p := &participant{guidPrefix: prefix, metaSock: metaSock, dataSock: dataSock}
    //   s := newSPDPService(p)
    //
    //   payload := s.buildParticipantData()
    //   fmt.Printf("%x\n", payload)
    //   // -> 0300000015000400020300001600040001270000500010000102030405060708
    //   //    090a0b0c000001c1580004003f000000320018000100000002440000000000000
    //   //    00000000000000000000002f0018000100000003440000000000000000000000
    //   //    00000000000000020008000a0000000000000001000000
    //   fmt.Println(len(payload)) // -> 120
    //
    //   submsg := marshalDataSubmessage(EntityIdSPDPWriter, EntityIdSPDPReader,
    //       SequenceNumber{High: 0, Low: 1}, payload)
    //   msg := wrapInRTPSMessage(prefix, submsg)
    //   fmt.Printf("%x\n", msg)
    //   // -> 52545053020301270102030405060708090a0b0c15058c000000100000010
    //   //    0c7000100c200000000010000000300000015000400020300001600040001
    //   //    270000500010000102030405060708090a0b0c000001c1580004003f00000
    //   //    0320018000100000002440000000000000000000000000000000000002f0
    //   //    0180001000000034400000000000000000000000000000000000002000800
    //   //    0a0000000000000001000000
    //
    //   from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 12345}
    //   proxy := parseParticipantData(prefix, payload, from)
    //   // guid=0102030405060708090a0b0c000001c1
    //   // metaUnicast={Kind:1 Port:17410 Address:[...12 zero bytes..,10,0,0,9]}
    //   // defaultUnicast={Kind:1 Port:17411 Address:[...12 zero bytes..,10,0,0,9]}
    //   // builtin=0x3f lease=10s
    //
    // Full run: `go test ./rtps/... -run TestZZReproSPDPBytes -v`
    // (go-DDS commit 3329f86 / rust-DDS branch feat/rtps-spdp).

    fn reference_config() -> SpdpConfig {
        SpdpConfig {
            domain: 0,
            guid_prefix: ascending_prefix(),
            vendor_id: VendorId([0x01, 0x27]), // go-DDS's own vendor id, for byte-exact parity
            meta_unicast_port: 17410,
            data_unicast_port: 17411,
            announce_period: SPDP_ANNOUNCE_PERIOD,
            jitter: Duration::ZERO,
            peer_locators: Vec::new(),
            no_multicast: false,
            ipv6: false,
            discovery_plugin: None,
        }
    }

    //fusa:test REQ-RTPS-025
    #[test]
    fn build_participant_data_matches_go_dds_reference() {
        let payload = build_participant_data(&reference_config());
        assert_eq!(payload.len(), 120);
        assert_eq!(
            hex::encode(&payload),
            "0300000015000400020300001600040001270000500010000102030405060708090a0b0c000001c1580004003f000000320018000100000002440000000000000000000000000000000000002f001800010000000344000000000000000000000000000000000000020008000a0000000000000001000000"
        );
    }

    //fusa:test REQ-RTPS-025
    //fusa:test REQ-RTPS-021
    //fusa:test REQ-RTPS-023
    #[test]
    fn full_spdp_announcement_matches_go_dds_reference() {
        let cfg = reference_config();
        let payload = build_participant_data(&cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: cfg.vendor_id,
            guid_prefix: cfg.guid_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);
        assert_eq!(
            hex::encode(&msg),
            "52545053020301270102030405060708090a0b0c15058c0000001000000100c7000100c200000000010000000300000015000400020300001600040001270000500010000102030405060708090a0b0c000001c1580004003f000000320018000100000002440000000000000000000000000000000000002f001800010000000344000000000000000000000000000000000000020008000a0000000000000001000000"
        );
    }

    //fusa:test REQ-RTPS-026
    #[test]
    fn parse_participant_data_matches_go_dds_reference() {
        let payload = build_participant_data(&reference_config());
        let from = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 9), 12345));
        let proxy = parse_participant_data(ascending_prefix(), &payload, from).unwrap();

        assert_eq!(
            proxy.guid,
            Guid {
                prefix: ascending_prefix(),
                entity: ENTITYID_PARTICIPANT,
            }
        );
        assert_eq!(proxy.builtin_endpoints, 0x3f);
        assert_eq!(proxy.lease_duration, Duration::from_secs(10));

        let mut expected_addr = [0u8; 16];
        expected_addr[12..16].copy_from_slice(&[10, 0, 0, 9]);
        assert_eq!(
            proxy.metatraffic_unicast,
            Locator {
                kind: super::super::locator::LOCATOR_KIND_UDPV4,
                port: 17410,
                address: expected_addr,
            }
        );
        assert_eq!(
            proxy.default_unicast,
            Locator {
                kind: super::super::locator::LOCATOR_KIND_UDPV4,
                port: 17411,
                address: expected_addr,
            }
        );
        // parse_participant_data itself never stamps last_seen — only
        // SpdpService::store_peer does (matches go-DDS's parseParticipantData).
        assert_eq!(proxy.last_seen, None);
    }

    // ── IPv6 (SpdpConfig::ipv6 / RtpsUdpParticipantConfig::with_ipv6) ────
    //
    // No go-DDS byte oracle for these: go-DDS's own `WithIPv6` never
    // advertises an IPv6 locator in ParticipantProxy at all (a fresh clone's
    // `buildParticipantData` always calls `locatorFromUDP` with the
    // IPv4-only `p.metaSock`/`p.dataSock`, never `p.metaSockV6`/
    // `p.dataSockV6` — see the module docs' "Unicast peer discovery" section
    // for the same kind of finding on a different go-DDS `Option`). These
    // tests instead prove the Rust-side family-selection logic is internally
    // consistent: the already-byte-verified `Locator::udp_v6` encoding
    // (`locator.rs`) is emitted/decoded/filled-in correctly when
    // `SpdpConfig::ipv6` is set, symmetrically with the IPv4 case above.

    //fusa:test REQ-RTPS-025
    #[test]
    fn build_participant_data_emits_udpv6_locators_when_ipv6_is_set() {
        let mut cfg = reference_config();
        cfg.ipv6 = true;
        let payload = build_participant_data(&cfg);
        let from = SocketAddr::from((std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9), 12345));
        let proxy = parse_participant_data(ascending_prefix(), &payload, from).unwrap();

        let mut expected_addr = [0u8; 16];
        expected_addr
            .copy_from_slice(&std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9).octets());
        assert_eq!(
            proxy.metatraffic_unicast,
            Locator {
                kind: super::super::locator::LOCATOR_KIND_UDPV6,
                port: 17410,
                address: expected_addr,
            }
        );
        assert_eq!(
            proxy.default_unicast,
            Locator {
                kind: super::super::locator::LOCATOR_KIND_UDPV6,
                port: 17411,
                address: expected_addr,
            }
        );
    }

    //fusa:test REQ-RTPS-026
    #[test]
    fn fill_in_zero_address_does_not_fill_a_family_mismatch() {
        // A UDPv4-kind zero locator seen from an IPv6 sender (or vice
        // versa) — should not happen in practice (a participant's own
        // socket family determines both), but must not panic or silently
        // fabricate a family-crossed address; left unfilled instead.
        let v4_zero = Locator::udp_v4([0, 0, 0, 0], 7410);
        let v6_from = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 12345));
        let proxy_payload = {
            let mut enc = PlCdrEncoder::new();
            enc.add_locator(PID_METATRAFFIC_UNICAST_LOCATOR, &v4_zero);
            enc.finish()
        };
        let proxy = parse_participant_data(ascending_prefix(), &proxy_payload, v6_from).unwrap();
        assert_eq!(proxy.metatraffic_unicast.address, [0u8; 16]);
    }

    //fusa:test REQ-RTPS-025
    #[test]
    fn spdp_config_with_ipv6_builder_sets_the_flag() {
        let cfg = SpdpConfig::new(0, ascending_prefix(), 7410, 7411).with_ipv6();
        assert!(cfg.ipv6);
        assert!(!SpdpConfig::new(0, ascending_prefix(), 7410, 7411).ipv6);
    }

    //fusa:test REQ-RTPS-017
    #[test]
    fn spdp_multicast_dst_selects_the_configured_address_family() {
        assert_eq!(
            spdp_multicast_dst(false, 7400),
            SocketAddr::from((SPDP_MULTICAST_ADDR, 7400))
        );
        assert_eq!(
            spdp_multicast_dst(true, 7400),
            SocketAddr::from((SPDP_MULTICAST_ADDR_V6, 7400))
        );
    }

    //fusa:test REQ-RTPS-026
    #[test]
    fn parse_participant_data_keeps_nonzero_locator_address_unchanged() {
        // A locator whose address is already non-zero must not be
        // overwritten by the sender's IP — the fill-in only applies to the
        // literal all-zero case.
        let mut enc = PlCdrEncoder::new();
        let real_locator = Locator::udp_v4([192, 168, 1, 1], 7410);
        enc.add_locator(PID_METATRAFFIC_UNICAST_LOCATOR, &real_locator);
        let payload = enc.finish();

        let from = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 9), 12345));
        let proxy = parse_participant_data(ascending_prefix(), &payload, from).unwrap();
        assert_eq!(proxy.metatraffic_unicast, real_locator);
    }

    //fusa:test REQ-RTPS-026
    //fusa:test REQ-RTPS-009
    #[test]
    fn parse_participant_data_rejects_bad_cdr_header_without_panicking() {
        assert_eq!(
            parse_participant_data(
                ascending_prefix(),
                &[0xFF, 0xFF, 0x00, 0x00],
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
            ),
            None
        );
    }

    //fusa:test REQ-RTPS-026
    #[test]
    fn parse_participant_data_tolerates_missing_parameters() {
        // An empty (sentinel-only) parameter list is still a valid
        // PL_CDR_LE payload; every field should fall back to its default.
        let payload = PlCdrEncoder::new().finish();
        let proxy = parse_participant_data(
            ascending_prefix(),
            &payload,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        assert_eq!(proxy.builtin_endpoints, 0);
        assert_eq!(proxy.lease_duration, Duration::ZERO);
        assert_eq!(
            proxy.guid,
            Guid {
                prefix: ascending_prefix(),
                entity: ENTITYID_PARTICIPANT,
            }
        );
    }

    //fusa:test REQ-RTPS-025
    #[test]
    fn all_builtin_endpoints_matches_go_dds_reference() {
        assert_eq!(ALL_BUILTIN_ENDPOINTS, 0x3f);
    }

    //fusa:test REQ-RTPS-027
    //fusa:test REQ-RTPS-059
    #[test]
    fn spdp_config_defaults_match_go_dds_reference() {
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        assert_eq!(cfg.announce_period, Duration::from_secs(2));
        assert_eq!(cfg.jitter, Duration::ZERO);
        assert_eq!(cfg.vendor_id, VENDOR_ID_RUST_DDS);
        assert!(cfg.peer_locators.is_empty());
        assert!(!cfg.no_multicast);
    }

    //fusa:test REQ-RTPS-027
    #[test]
    fn spdp_config_builder_overrides() {
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411)
            .with_announce_period(Duration::from_millis(500))
            .with_jitter(Duration::from_millis(50));
        assert_eq!(cfg.announce_period, Duration::from_millis(500));
        assert_eq!(cfg.jitter, Duration::from_millis(50));
    }

    //fusa:test REQ-RTPS-059
    #[test]
    fn spdp_config_peer_locators_and_no_multicast_builder_overrides() {
        let peer_a = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 7400));
        let peer_b = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 7500));
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411)
            .with_peer_locators([peer_a])
            .with_peer_locators([peer_b])
            .with_no_multicast();
        // Additive across repeated calls, matching go-DDS's
        // WithPeerLocators(addrs ...string)'s append semantics.
        assert_eq!(cfg.peer_locators, vec![peer_a, peer_b]);
        assert!(cfg.no_multicast);
    }

    #[test]
    fn random_duration_below_zero_is_zero() {
        assert_eq!(random_duration_below(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn random_duration_below_is_bounded() {
        let max = Duration::from_millis(10);
        for _ in 0..100 {
            let d = random_duration_below(max);
            assert!(d < max, "{d:?} was not < {max:?}");
        }
    }

    // ── Async service-level tests (real loopback sockets) ───────────────

    use super::super::transport::RtpsSocket;

    async fn bound_socket() -> Arc<RtpsSocket> {
        Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap())
    }

    //fusa:test REQ-RTPS-026
    //fusa:test REQ-RTPS-028
    #[tokio::test]
    async fn store_and_evict_round_trip() {
        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(cfg, send_socket);

        let mut other_prefix = ascending_prefix();
        other_prefix.0[0] = 0xFF; // distinct from our own guid_prefix
        let proxy = ParticipantProxy {
            guid: Guid {
                prefix: other_prefix,
                entity: ENTITYID_PARTICIPANT,
            },
            metatraffic_unicast: Locator::default(),
            default_unicast: Locator::default(),
            builtin_endpoints: 0x3f,
            lease_duration: Duration::ZERO, // → falls back to DEFAULT_LEASE_DURATION
            last_seen: None,
        };

        let is_new = service.store_peer(proxy.clone()).await;
        assert!(is_new);
        assert_eq!(service.announces_received(), 1);

        let peers = service.known_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].guid, proxy.guid);
        assert_eq!(peers[0].lease_duration, DEFAULT_LEASE_DURATION);
        assert!(peers[0].last_seen.is_some());

        // Re-announcing the same peer is not "new".
        let is_new_again = service.store_peer(proxy.clone()).await;
        assert!(!is_new_again);
        assert_eq!(service.known_peers().await.len(), 1);

        // Force an already-expired lease by storing with a lease so short
        // it has already elapsed by the time evict_expired runs.
        let mut expiring = proxy.clone();
        expiring.lease_duration = Duration::from_nanos(1);
        service.store_peer(expiring).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        service.evict_expired().await;

        assert_eq!(service.known_peers().await.len(), 0);
        assert_eq!(service.peer_evictions(), 1);
    }

    //fusa:test REQ-RTPS-026
    //fusa:test REQ-RTPS-028
    #[tokio::test]
    async fn handle_packet_ignores_own_announcement() {
        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(cfg.clone(), send_socket);

        let payload = build_participant_data(&cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: cfg.vendor_id,
            guid_prefix: cfg.guid_prefix, // same prefix as `service` itself
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)))
            .await;
        assert_eq!(service.known_peers().await.len(), 0);
        assert_eq!(service.announces_received(), 0);
    }

    //fusa:test REQ-RTPS-026
    #[tokio::test]
    async fn handle_packet_stores_a_peer_announcement() {
        let send_socket = bound_socket().await;
        let own_cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(own_cfg, send_socket);

        let mut peer_prefix = ascending_prefix();
        peer_prefix.0[0] = 0xFF;
        let peer_cfg = SpdpConfig::new(0, peer_prefix, 27410, 27411);
        let payload = build_participant_data(&peer_cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: peer_cfg.vendor_id,
            guid_prefix: peer_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 12345)))
            .await;

        let peers = service.known_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].guid.prefix, peer_prefix);
        assert_eq!(peers[0].metatraffic_unicast.port, 27410);
    }

    // ── Discovery authentication (HMAC-SHA-256 SPDP signing) ─────────────

    use crate::security::discovery::HmacDiscoveryPlugin;

    //fusa:test REQ-SEC-028
    #[test]
    fn build_participant_data_omits_discovery_token_by_default() {
        // Baseline, unchanged from every earlier sub-phase: no plugin
        // configured ⇒ no PID_DISCOVERY_TOKEN in the output at all.
        let payload = build_participant_data(&reference_config());
        assert_eq!(extract_discovery_token(&payload), None);
    }

    //fusa:test REQ-SEC-028
    #[test]
    fn build_participant_data_embeds_discovery_token_when_plugin_configured() {
        let plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"spdp-signing-key".to_vec()));
        let cfg = reference_config().with_discovery_plugin(Arc::clone(&plugin));

        let payload = build_participant_data(&cfg);
        let token = extract_discovery_token(&payload).expect("token must be present");
        let expected = plugin.sign_discovery(&cfg.guid_prefix.0);
        assert_eq!(token, expected);
        assert_eq!(token.len(), 32);

        // Every other field this crate's own byte-exact reference test
        // (build_participant_data_matches_go_dds_reference) already pins
        // is untouched — the token is strictly additive.
        let baseline = build_participant_data(&reference_config());
        assert_eq!(payload.len(), baseline.len() + 4 + 32); // (pid, len) header + 32-byte tag
        assert!(payload.starts_with(&baseline[..baseline.len() - 4])); // everything but the old sentinel
    }

    //fusa:test REQ-SEC-028
    #[test]
    fn extract_discovery_token_returns_none_for_malformed_or_absent() {
        // Too short to even carry a PL_CDR_LE encapsulation header.
        assert_eq!(extract_discovery_token(&[0x00, 0x01]), None);
        // Well-formed PL_CDR_LE payload, but no PID_DISCOVERY_TOKEN param.
        let payload = build_participant_data(&reference_config());
        assert_eq!(extract_discovery_token(&payload), None);
    }

    /// Full announce-send / receive-verify round trip: a peer signed with
    /// the *same* key as the receiver's configured plugin is accepted and
    /// stored, exactly as an unauthenticated peer would be without this
    /// feature.
    //fusa:test REQ-SEC-028
    //fusa:test REQ-SEC-029
    #[tokio::test]
    async fn handle_packet_accepts_peer_with_valid_discovery_token() {
        let send_socket = bound_socket().await;
        let shared_key = b"shared-spdp-discovery-key".to_vec();
        let own_plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(shared_key.clone()));
        let own_cfg =
            SpdpConfig::new(0, ascending_prefix(), 17410, 17411).with_discovery_plugin(own_plugin);
        let service = SpdpService::new(own_cfg, send_socket);

        let mut peer_prefix = ascending_prefix();
        peer_prefix.0[0] = 0xFF;
        let peer_plugin: Arc<dyn DiscoveryPlugin> = Arc::new(HmacDiscoveryPlugin::new(shared_key));
        let peer_cfg =
            SpdpConfig::new(0, peer_prefix, 27410, 27411).with_discovery_plugin(peer_plugin);
        let payload = build_participant_data(&peer_cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: peer_cfg.vendor_id,
            guid_prefix: peer_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 12345)))
            .await;

        let peers = service.known_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].guid.prefix, peer_prefix);
    }

    /// A peer whose announcement carries no `PID_DISCOVERY_TOKEN` at all
    /// (unsigned) is rejected by a receiver that has a plugin configured —
    /// matches go-DDS's `VerifyDiscovery` contract of treating a nil/empty
    /// tag as invalid, not as an unauthenticated pass-through.
    //fusa:test REQ-SEC-029
    #[tokio::test]
    async fn handle_packet_rejects_peer_with_no_discovery_token() {
        let send_socket = bound_socket().await;
        let own_plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"receiver-key".to_vec()));
        let own_cfg =
            SpdpConfig::new(0, ascending_prefix(), 17410, 17411).with_discovery_plugin(own_plugin);
        let service = SpdpService::new(own_cfg, send_socket);

        let mut peer_prefix = ascending_prefix();
        peer_prefix.0[0] = 0xFF;
        // Unsigned peer — no discovery_plugin configured on its own config.
        let peer_cfg = SpdpConfig::new(0, peer_prefix, 27410, 27411);
        let payload = build_participant_data(&peer_cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: peer_cfg.vendor_id,
            guid_prefix: peer_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 12345)))
            .await;

        assert_eq!(service.known_peers().await.len(), 0);
    }

    /// A peer signed under a *different* key than the receiver's is
    /// rejected — the forged/mismatched-key case this whole feature exists
    /// to catch.
    //fusa:test REQ-SEC-029
    #[tokio::test]
    async fn handle_packet_rejects_peer_with_wrong_key_discovery_token() {
        let send_socket = bound_socket().await;
        let own_plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"receiver-key".to_vec()));
        let own_cfg =
            SpdpConfig::new(0, ascending_prefix(), 17410, 17411).with_discovery_plugin(own_plugin);
        let service = SpdpService::new(own_cfg, send_socket);

        let mut peer_prefix = ascending_prefix();
        peer_prefix.0[0] = 0xFF;
        let wrong_key_plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"attacker-key".to_vec()));
        let peer_cfg =
            SpdpConfig::new(0, peer_prefix, 27410, 27411).with_discovery_plugin(wrong_key_plugin);
        let payload = build_participant_data(&peer_cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: peer_cfg.vendor_id,
            guid_prefix: peer_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 12345)))
            .await;

        assert_eq!(service.known_peers().await.len(), 0);
    }

    /// A tampered token (single bit flip in transit) is rejected — the
    /// on-the-wire-tampering case, distinct from a wrong-key mismatch
    /// above.
    //fusa:test REQ-SEC-029
    #[tokio::test]
    async fn handle_packet_rejects_peer_with_tampered_discovery_token() {
        let send_socket = bound_socket().await;
        let shared_key = b"shared-spdp-discovery-key".to_vec();
        let own_plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(shared_key.clone()));
        let own_cfg =
            SpdpConfig::new(0, ascending_prefix(), 17410, 17411).with_discovery_plugin(own_plugin);
        let service = SpdpService::new(own_cfg, send_socket);

        let mut peer_prefix = ascending_prefix();
        peer_prefix.0[0] = 0xFF;
        let peer_plugin: Arc<dyn DiscoveryPlugin> = Arc::new(HmacDiscoveryPlugin::new(shared_key));
        let peer_cfg =
            SpdpConfig::new(0, peer_prefix, 27410, 27411).with_discovery_plugin(peer_plugin);
        let mut payload = build_participant_data(&peer_cfg);
        // The 32-byte token occupies the 32 bytes immediately before the
        // trailing 4-byte PID_SENTINEL — flip its last byte, not the
        // sentinel's own (which would corrupt parsing instead of just the
        // signature).
        let tag_last_byte = payload.len() - 4 - 1;
        payload[tag_last_byte] ^= 0xFF;

        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: peer_cfg.vendor_id,
            guid_prefix: peer_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 12345)))
            .await;

        assert_eq!(service.known_peers().await.len(), 0);
    }

    //fusa:test REQ-SEC-028
    #[test]
    fn spdp_config_equality_requires_matching_discovery_plugin_presence_and_identity() {
        let cfg_none = reference_config();
        assert_eq!(cfg_none, reference_config());

        let plugin: Arc<dyn DiscoveryPlugin> = Arc::new(HmacDiscoveryPlugin::new(b"k".to_vec()));
        let cfg_some = reference_config().with_discovery_plugin(Arc::clone(&plugin));
        assert_ne!(cfg_none, cfg_some);

        let cfg_some_same_plugin = reference_config().with_discovery_plugin(Arc::clone(&plugin));
        assert_eq!(cfg_some, cfg_some_same_plugin);

        let other_plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"k".to_vec()));
        let cfg_other_plugin = reference_config().with_discovery_plugin(other_plugin);
        assert_ne!(cfg_some, cfg_other_plugin);
    }

    //fusa:test REQ-RTPS-026
    //fusa:test REQ-RTPS-009
    #[tokio::test]
    async fn handle_packet_ignores_malformed_input_without_panicking() {
        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(cfg, send_socket);

        service
            .handle_packet(
                b"not an rtps message",
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            )
            .await;
        service
            .handle_packet(&[], SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await;
        assert_eq!(service.known_peers().await.len(), 0);
    }

    //fusa:test REQ-RTPS-027
    #[tokio::test]
    async fn send_announcement_reaches_a_real_multicast_listener() {
        // End-to-end: bind a real multicast receive socket on the SPDP
        // group/port, spawn its receive loop, send one announcement from a
        // second SpdpService, and confirm the datagram arrives with the
        // expected RTPS magic bytes. Skips (rather than fails) if this
        // environment has no multicast-capable interface — matches the
        // skip convention already established in `transport.rs`'s own
        // multicast tests.
        let recv_port = RtpsSocket::bind_unicast_v4(0).await.unwrap().local_port();
        let Ok(mcast_socket) = RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, recv_port).await
        else {
            return;
        };
        let (mut rx, recv_handle) = mcast_socket.spawn_receive_loop(8);

        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(cfg, send_socket);

        // Send directly to the loopback multicast listener's actual bound
        // port rather than the domain-formula port, so the test is
        // hermetic (no collision with a real SPDP listener on this host).
        let payload = build_participant_data(service.config());
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: service.config().vendor_id,
            guid_prefix: service.config().guid_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);
        // Some CI sandboxes (observed on macOS GitHub Actions runners) allow
        // binding/joining the multicast group above but reject the actual
        // send with EHOSTUNREACH — a network-policy restriction, not a bug
        // in this crate. Skip rather than fail in that case too, consistent
        // with the bind-time skip above.
        if service
            .send_socket
            .send_to(&msg, SocketAddr::from((SPDP_MULTICAST_ADDR, recv_port)))
            .await
            .is_err()
        {
            recv_handle.abort();
            return;
        }

        let datagram = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("multicast receive loop did not deliver a datagram in time")
            .expect("channel closed unexpectedly");
        assert_eq!(&datagram.data[0..4], b"RTPS");

        recv_handle.abort();
    }

    //fusa:test REQ-RTPS-059
    #[tokio::test]
    async fn send_announcement_reaches_a_peer_via_unicast_without_multicast() {
        // The unicast half of SPDP discovery: a peer listed in
        // peer_locators receives the announcement directly, with no
        // multicast socket involved at all — proven here by giving the
        // service an out-of-range domain (1000: 7400 + 250*1000 overflows
        // u16, so meta_multicast_port(1000) is None) that would make a
        // multicast send fail outright; send_announcement still succeeds
        // because with_no_multicast() means that path is never attempted.
        let peer_socket = bound_socket().await;
        let peer_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, peer_socket.local_port()));
        // Reuse peer_socket's own receive loop to observe what arrives.
        let (mut peer_rx, peer_recv_handle) = peer_socket.spawn_receive_loop(8);

        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(1000, ascending_prefix(), 17410, 17411)
            .with_peer_locators([peer_addr])
            .with_no_multicast();
        let service = SpdpService::new(cfg, send_socket);

        service
            .send_announcement()
            .await
            .expect("unicast-only send_announcement must succeed despite the out-of-range domain, since no multicast send is attempted");

        let datagram = tokio::time::timeout(Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("unicast SPDP announcement did not reach the configured peer in time")
            .expect("channel closed unexpectedly");
        assert_eq!(&datagram.data[0..4], b"RTPS");

        peer_recv_handle.abort();
    }

    //fusa:test REQ-RTPS-059
    #[tokio::test]
    async fn send_announcement_reaches_multiple_peers_via_unicast() {
        let peer_a_socket = bound_socket().await;
        let peer_b_socket = bound_socket().await;
        let peer_a_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, peer_a_socket.local_port()));
        let peer_b_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, peer_b_socket.local_port()));
        let (mut peer_a_rx, peer_a_handle) = peer_a_socket.spawn_receive_loop(8);
        let (mut peer_b_rx, peer_b_handle) = peer_b_socket.spawn_receive_loop(8);

        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(1000, ascending_prefix(), 17410, 17411)
            .with_peer_locators([peer_a_addr, peer_b_addr])
            .with_no_multicast();
        let service = SpdpService::new(cfg, send_socket);
        service.send_announcement().await.unwrap();

        for rx in [&mut peer_a_rx, &mut peer_b_rx] {
            let datagram = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("unicast SPDP announcement did not reach every configured peer in time")
                .expect("channel closed unexpectedly");
            assert_eq!(&datagram.data[0..4], b"RTPS");
        }

        peer_a_handle.abort();
        peer_b_handle.abort();
    }

    //fusa:test REQ-RTPS-059
    #[tokio::test]
    async fn peer_locator_datagram_is_processed_identically_to_a_multicast_one() {
        // Confirms the *receiving* side needs no special-casing: a
        // service's handle_packet stores a peer from a unicast-delivered
        // announcement exactly the way it does for a multicast-delivered
        // one — SpdpService itself is transport-agnostic (see the module
        // docs' "Unicast peer discovery" section).
        let send_socket = bound_socket().await;
        let own_cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(own_cfg, send_socket);

        let mut peer_prefix = ascending_prefix();
        peer_prefix.0[0] = 0xFF;
        let peer_cfg = SpdpConfig::new(0, peer_prefix, 27410, 27411);
        let payload = build_participant_data(&peer_cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: peer_cfg.vendor_id,
            guid_prefix: peer_prefix,
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        // Deliver it as if it had arrived on a plain unicast socket (no
        // multicast join anywhere in this test) at an arbitrary source
        // address — handle_packet does not know or care which kind of
        // socket a datagram arrived on.
        service
            .handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 27410)))
            .await;

        let peers = service.known_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].guid.prefix, peer_prefix);
    }

    //fusa:test REQ-RTPS-027
    #[tokio::test]
    async fn spawn_announce_loop_stops_when_aborted() {
        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411)
            .with_announce_period(Duration::from_millis(20));
        let service = SpdpService::new(cfg, send_socket);
        let handle = Arc::clone(&service).spawn_announce_loop();

        tokio::time::sleep(Duration::from_millis(60)).await;
        // At least the initial send plus one periodic tick should have
        // happened by now.
        assert!(service.announces_sent() >= 2);

        handle.abort();
        let result = handle.await;
        assert!(result.unwrap_err().is_cancelled());
    }

    //fusa:test REQ-RTPS-028
    #[tokio::test]
    async fn spawn_evict_loop_stops_when_aborted() {
        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(cfg, send_socket);
        let handle = Arc::clone(&service).spawn_evict_loop();
        handle.abort();
        let result = handle.await;
        assert!(result.unwrap_err().is_cancelled());
    }

    //fusa:test REQ-RTPS-026
    #[tokio::test]
    async fn spawn_receive_loop_stops_when_channel_closed() {
        let send_socket = bound_socket().await;
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        let service = SpdpService::new(cfg, send_socket);
        let (tx, rx) = mpsc::channel(8);
        let handle = service.spawn_receive_loop(rx);
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("receive loop did not stop after channel close")
            .unwrap();
    }
}
