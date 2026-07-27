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
//! SEDP peer notification (`onNewPeer`/`onPeerEvicted`), the
//! `DiscoveryPlugin` authentication hook (`PID_DISCOVERY_TOKEN`), and the
//! `livelinessCb` participant-liveliness callback.
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
    PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID, PID_PARTICIPANT_LEASE_DURATION,
    PID_PROTOCOL_VERSION, PID_VENDOR_ID,
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
use super::transport::{meta_multicast_port, RtpsDatagram, RtpsSocket, SPDP_MULTICAST_ADDR};

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
//fusa:req REQ-RTPS-025
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

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
//fusa:req REQ-RTPS-025
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

    let meta_locator = Locator::udp_v4([0, 0, 0, 0], u32::from(cfg.meta_unicast_port));
    enc.add_locator(PID_METATRAFFIC_UNICAST_LOCATOR, &meta_locator);

    let data_locator = Locator::udp_v4([0, 0, 0, 0], u32::from(cfg.data_unicast_port));
    enc.add_locator(PID_DEFAULT_UNICAST_LOCATOR, &data_locator);

    let mut lease = Vec::with_capacity(8);
    lease.extend_from_slice(&ADVERTISED_LEASE_SECS.to_le_bytes());
    lease.extend_from_slice(&0u32.to_le_bytes());
    enc.add_bytes(PID_PARTICIPANT_LEASE_DURATION, &lease);

    enc.finish()
}

/// Decodes a `PL_CDR_LE` ParticipantProxy `payload` (an SPDP DATA
/// submessage's payload) into a [`ParticipantProxy`]. `prefix` is the
/// sending participant's `GuidPrefix`, taken from the enclosing RTPS
/// message [`Header`] (used as the fallback GUID if the payload carries no
/// `PID_PARTICIPANT_GUID`, and matched against a decoded
/// `PID_PARTICIPANT_GUID` the same way go-DDS's `parseParticipantData`
/// does — the payload's own value wins if present). `from` is the UDP
/// datagram's sender address; when a decoded locator's address is all-zero
/// (`0.0.0.0`, see [`build_participant_data`]'s doc comment), `from`'s IPv4
/// address is filled in — matches go-DDS's `parseParticipantData` fill-in
/// behaviour exactly.
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

    let from_v4 = match from {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    };

    for param in decoder {
        match param.pid {
            PID_METATRAFFIC_UNICAST_LOCATOR => {
                if let Ok(mut loc) = Locator::decode(param.value) {
                    fill_in_zero_address(&mut loc, from_v4);
                    proxy.metatraffic_unicast = loc;
                }
            }
            PID_DEFAULT_UNICAST_LOCATOR => {
                if let Ok(mut loc) = Locator::decode(param.value) {
                    fill_in_zero_address(&mut loc, from_v4);
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

/// If `loc`'s address is all-zero (`0.0.0.0`), fills in `from_v4`'s octets
/// — matches go-DDS's `if proxy.metatrafficUnicast.Address == ([16]byte{})
/// { ... }` fill-in.
fn fill_in_zero_address(loc: &mut Locator, from_v4: Option<std::net::Ipv4Addr>) {
    if loc.address == [0u8; 16] {
        if let Some(ip) = from_v4 {
            loc.address[12..16].copy_from_slice(&ip.octets());
        }
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

    /// Builds and sends one SPDP announcement to the domain's multicast
    /// group. Matches go-DDS's `sendAnnouncement`.
    //fusa:req REQ-RTPS-027
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

        let port = meta_multicast_port(self.config.domain).ok_or_else(|| {
            std::io::Error::other(format!(
                "rtps: domain {} out of range for SPDP multicast port",
                self.config.domain
            ))
        })?;
        let dst = SocketAddr::from((SPDP_MULTICAST_ADDR, port));
        self.send_socket.send_to(&msg, dst).await?;
        Ok(())
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
    //fusa:req REQ-RTPS-026
    //fusa:req REQ-RTPS-028
    //fusa:req REQ-RTPS-009
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
    #[test]
    fn spdp_config_defaults_match_go_dds_reference() {
        let cfg = SpdpConfig::new(0, ascending_prefix(), 17410, 17411);
        assert_eq!(cfg.announce_period, Duration::from_secs(2));
        assert_eq!(cfg.jitter, Duration::ZERO);
        assert_eq!(cfg.vendor_id, VENDOR_ID_RUST_DDS);
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
        let service = SpdpService::new(cfg, send_socket);

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
