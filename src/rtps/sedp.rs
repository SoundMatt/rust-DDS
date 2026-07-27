// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! SEDP — Simple Endpoint Discovery Protocol (RTPS 2.3 §8.5.4 / §9.6.2).
//!
//! This is Tier 1 sub-phase 5 of the parity build-out plan in
//! `ROADMAP.md` ("Tier 1 — RTPS wire-protocol port" → "SEDP"): once SPDP
//! (sub-phase 4) has found a remote participant, SEDP exchanges unicast
//! publication/subscription ("endpoint") announcements with it over that
//! participant's metatraffic unicast port, so that local and remote
//! writers/readers sharing a topic name can be matched. Wire layout and
//! service behaviour ported 1:1 from go-DDS's `rtps/sedp.go` (343 LOC, the
//! ecosystem's RTPS correctness oracle — see `ROADMAP.md` Tier 1):
//! [`build_endpoint_data`] mirrors `sedpService.buildEndpointData`
//! byte-for-byte; [`SedpService`] mirrors `sedpService`'s
//! register/announce/receive/match logic and endpoint tables. See each
//! test's doc comment for the exact go-DDS reproduction command.
//!
//! Not in this sub-phase's scope (later Tier 1/2 work, per `ROADMAP.md`):
//! actual sample data delivery (that's sub-phase 6, "BestEffort data
//! path"), the `EndpointPlugin`/`DiscoveryPlugin` authentication hook
//! (`PID_ENDPOINT_TOKEN`), and the participant-liveliness callback.
//!
//! # No RTPS participant runtime yet
//!
//! go-DDS's `sedpService` holds a `*participant` and reaches into its
//! `rtpsReader`/`rtpsWriter` bookkeeping (`s.p.readerByEID(...).addSourceGUID`,
//! `s.p.addWriterLocator`) and its sibling `spdpService` (`s.p.spdp.allPeers()`)
//! directly. rust-DDS has no equivalent RTPS participant runtime type yet
//! (that composition lands with sub-phase 6, "BestEffort data path", which is
//! where reader/writer objects and their receive-side dispatch are built) —
//! so [`SedpService`] holds an [`Arc<SpdpService>`](super::spdp::SpdpService)
//! directly (the one piece of that composition sub-phase 4 already provides)
//! and, in place of notifying a reader object in-line,
//! [`SedpService::on_remote_writer`] *returns* the matched local reader
//! `EntityId`s and [`SedpService::register_reader`] *returns* the matched
//! remote writer `Guid`s for a future caller to act on. The endpoint tables
//! themselves ([`SedpService::known_remote_writers`],
//! [`SedpService::known_remote_readers`],
//! [`SedpService::matched_writer_locator`],
//! [`SedpService::matched_reader_locators`]) are otherwise the same shape as
//! go-DDS's `remoteWriters`/`remoteReaders`/`remoteReaderLocs`/
//! `p.writerLocators`, so that future caller has everything it needs.
//!
//! # Async model
//!
//! Same idiom as `spdp.rs` (sub-phase 4): every long-running loop is its own
//! `tokio::task`, independently stoppable via `.abort()` on its returned
//! `JoinHandle`; a plain `tokio::sync::RwLock` guards the endpoint tables
//! (bookkeeping only ever held briefly, no long-lived critical sections).
//! Unlike SPDP's split multicast-receive/unicast-send sockets, SEDP send and
//! receive both happen over the *same* unicast metatraffic socket (matching
//! go-DDS's single `p.metaSock` serving both roles) — a caller typically
//! binds one [`RtpsSocket`](super::transport::RtpsSocket), passes it (via
//! `Arc`) as [`SedpService::new`]'s `send_socket`, and separately feeds that
//! same socket's own [`RtpsSocket::spawn_receive_loop`](super::transport::RtpsSocket::spawn_receive_loop)
//! output into [`SedpService::spawn_receive_loop`].
//!
//! One deliberate deviation from go-DDS, carried forward from `spdp.rs`'s own
//! documented deviation: go-DDS's `nextSeqNum` draws from a single
//! process-wide atomic counter (`rtps/sedp.go`'s package-level `seqCounter`,
//! shared with *every* SPDP/SEDP writer in the process). RTPS only requires
//! per-writer monotonicity (RTPS 2.3 §8.3.5) — a strictly-increasing
//! process-wide counter trivially preserves that per writer too — so
//! [`SedpService`] keeps its own sequence counter scoped to the service
//! instance (shared between its two logical writers, the SEDP publications
//! and subscriptions announcers), independent of [`SpdpService`]'s. Simpler,
//! no less correct.
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001) and no panics on
//! malformed/truncated decode input (REQ-ASIL-003 / REQ-RTPS-009):
//! [`SedpService::handle_packet`] and everything it calls treats malformed
//! input as "ignore this datagram", never as a crash.
//!
//! Internal only: not re-exported from the crate root, not yet wired into
//! `Participant`/`Publisher`/`Subscriber`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use super::cdr::{
    PlCdrDecoder, PlCdrEncoder, PID_DEFAULT_UNICAST_LOCATOR, PID_ENDPOINT_GUID, PID_TOPIC_NAME,
    PID_TYPE_NAME,
};
use super::guid::{
    EntityId, Guid, GuidPrefix, ENTITYID_SEDP_PUB_READER, ENTITYID_SEDP_PUB_WRITER,
    ENTITYID_SEDP_SUB_READER, ENTITYID_SEDP_SUB_WRITER, ENTITYID_UNKNOWN,
};
use super::locator::Locator;
use super::message::{
    decode_data_submessage, encode_data_submessage, wrap_in_rtps_message, Header, SequenceNumber,
    SubmessageIter, VendorId, PROTOCOL_VERSION_2_3, SUBMSG_DATA, VENDOR_ID_RUST_DDS,
};
use super::spdp::{ParticipantProxy, SpdpService};
use super::transport::{RtpsDatagram, RtpsSocket};

/// The opaque type name this crate always advertises in `PID_TYPE_NAME` —
/// matches go-DDS's `buildEndpointData`, which hard-codes `"CDR_BLOB"` for
/// raw byte payloads rather than a per-topic IDL type name (Tier 3's
/// `dds-tools::xtypes` is where real type-name/typed-payload support lands).
const ENDPOINT_TYPE_NAME: &str = "CDR_BLOB";

// ---------------------------------------------------------------------------
// EndpointInfo
// ---------------------------------------------------------------------------

/// Describes a local or remote DDS endpoint (a writer or a reader). Matches
/// go-DDS's `endpointInfo`.
//fusa:req REQ-RTPS-029
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointInfo {
    pub guid: Guid,
    pub topic_name: String,
    pub is_writer: bool,
}

// ---------------------------------------------------------------------------
// SedpConfig
// ---------------------------------------------------------------------------

/// Fixed configuration for one participant's [`SedpService`]: identity
/// (`guid_prefix`, `vendor_id`) and the user-data unicast port advertised in
/// every outbound `EndpointData` announcement.
//fusa:req REQ-RTPS-029
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SedpConfig {
    /// This participant's own `GuidPrefix`. Announcements whose header
    /// carries this same prefix are ignored (self-filtering; see
    /// [`SedpService::handle_packet`]) — same convention as
    /// [`SpdpConfig`](super::spdp::SpdpConfig).
    pub guid_prefix: GuidPrefix,
    /// `VendorId` stamped into the RTPS message header of every outbound
    /// announcement. Defaults to [`VENDOR_ID_RUST_DDS`] via
    /// [`SedpConfig::new`]; overridable for testing byte-exact parity
    /// against go-DDS reference output (which uses its own `0x0127`).
    pub vendor_id: VendorId,
    /// The user-data unicast port this participant listens on, advertised
    /// as each announcement's `PID_DEFAULT_UNICAST_LOCATOR` — matches
    /// go-DDS's `buildEndpointData`'s `locatorFromUDP(&net.UDPAddr{IP:
    /// net.IPv4zero}, s.p.dataSock.port)`.
    pub data_unicast_port: u16,
}

impl SedpConfig {
    /// Builds a config with this crate's own vendor ID.
    //fusa:req REQ-RTPS-029
    pub fn new(guid_prefix: GuidPrefix, data_unicast_port: u16) -> Self {
        SedpConfig {
            guid_prefix,
            vendor_id: VENDOR_ID_RUST_DDS,
            data_unicast_port,
        }
    }
}

// ---------------------------------------------------------------------------
// build_endpoint_data
// ---------------------------------------------------------------------------

/// Builds the `PL_CDR_LE`-encoded `EndpointData` payload advertised in one
/// SEDP publication/subscription DATA submessage. Matches go-DDS's
/// `buildEndpointData` byte-for-byte (parameter order: endpoint GUID, topic
/// name, type name — always `"CDR_BLOB"` — default unicast locator).
///
/// The default unicast locator always carries the all-zero (`0.0.0.0`)
/// address, filled in by the receiver from the announcement's UDP source
/// address — same convention as [`build_participant_data`]
/// (super::spdp::build_participant_data), and matching go-DDS's own
/// `locatorFromUDP(&net.UDPAddr{IP: net.IPv4zero}, ...)`.
///
/// No `PID_ENDPOINT_TOKEN` is ever emitted here — the `EndpointPlugin`
/// authentication hook is later Tier 1/2 work (see the module docs), so
/// there is no plugin to consult, matching go-DDS's own behaviour when
/// `discoveryPlugin` does not implement `EndpointPlugin`.
//fusa:req REQ-RTPS-029
pub fn build_endpoint_data(cfg: &SedpConfig, info: &EndpointInfo) -> Vec<u8> {
    let mut enc = PlCdrEncoder::new();
    enc.add_guid(PID_ENDPOINT_GUID, &info.guid);
    enc.add_string(PID_TOPIC_NAME, &info.topic_name);
    enc.add_string(PID_TYPE_NAME, ENDPOINT_TYPE_NAME);
    let locator = Locator::udp_v4([0, 0, 0, 0], u32::from(cfg.data_unicast_port));
    enc.add_locator(PID_DEFAULT_UNICAST_LOCATOR, &locator);
    enc.finish()
}

/// If `loc`'s address is all-zero (`0.0.0.0`), fills in `from_v4`'s octets.
/// Matches go-DDS's `handleEndpointAnnounce` fill-in — the same convention
/// [`super::spdp::parse_participant_data`] applies for SPDP.
fn fill_in_zero_address(loc: &mut Locator, from_v4: Option<std::net::Ipv4Addr>) {
    if loc.address == [0u8; 16] {
        if let Some(ip) = from_v4 {
            loc.address[12..16].copy_from_slice(&ip.octets());
        }
    }
}

// ---------------------------------------------------------------------------
// SedpService
// ---------------------------------------------------------------------------

/// Manages one participant's SEDP endpoint registration, announcement, and
/// remote-endpoint matching. Matches go-DDS's `sedpService`.
///
/// Construct with [`SedpService::new`], then [`SedpService::register_writer`]/
/// [`SedpService::register_reader`] each local endpoint as it is created and
/// spawn [`SedpService::spawn_receive_loop`] to process incoming remote
/// announcements. See the module docs' "No RTPS participant runtime yet"
/// section for how this differs from go-DDS's in-line reader notification.
#[derive(Debug)]
pub struct SedpService {
    config: SedpConfig,
    send_socket: Arc<RtpsSocket>,
    spdp: Arc<SpdpService>,
    seq_counter: AtomicU32,
    local_writers: RwLock<HashMap<EntityId, EndpointInfo>>,
    local_readers: RwLock<HashMap<EntityId, EndpointInfo>>,
    remote_writers: RwLock<HashMap<Guid, EndpointInfo>>,
    remote_readers: RwLock<HashMap<Guid, EndpointInfo>>,
    remote_reader_locators: RwLock<HashMap<Guid, Locator>>,
    /// Data-delivery locator for each remote writer matched against at
    /// least one local reader's topic. Matches go-DDS's
    /// `participant.writerLocators` — kept here rather than on a
    /// participant type since none exists yet (see the module docs).
    writer_locators: RwLock<HashMap<Guid, Locator>>,
    endpoint_matches: AtomicU64,
    announces_sent: AtomicU64,
    announces_received: AtomicU64,
}

impl SedpService {
    /// Creates a new service. `send_socket` is used to *send* announcements
    /// to a peer's metatraffic unicast address; `spdp` is this participant's
    /// already-running [`SpdpService`], consulted for the current
    /// known-peers table when broadcasting to "every known participant"
    /// (matches go-DDS's `s.p.spdp.allPeers()`). See the module docs' async
    /// model section for how `send_socket` and the receive loop typically
    /// share one underlying socket.
    //fusa:req REQ-RTPS-031
    pub fn new(
        config: SedpConfig,
        send_socket: Arc<RtpsSocket>,
        spdp: Arc<SpdpService>,
    ) -> Arc<Self> {
        Arc::new(SedpService {
            config,
            send_socket,
            spdp,
            seq_counter: AtomicU32::new(0),
            local_writers: RwLock::new(HashMap::new()),
            local_readers: RwLock::new(HashMap::new()),
            remote_writers: RwLock::new(HashMap::new()),
            remote_readers: RwLock::new(HashMap::new()),
            remote_reader_locators: RwLock::new(HashMap::new()),
            writer_locators: RwLock::new(HashMap::new()),
            endpoint_matches: AtomicU64::new(0),
            announces_sent: AtomicU64::new(0),
            announces_received: AtomicU64::new(0),
        })
    }

    /// This service's configuration.
    pub fn config(&self) -> &SedpConfig {
        &self.config
    }

    fn next_seq_num(&self) -> u32 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    // ── Local endpoint registration ─────────────────────────────────────

    /// Records a local writer and announces it to every known peer. Matches
    /// go-DDS's `registerWriter`.
    //fusa:req REQ-RTPS-031
    pub async fn register_writer(&self, eid: EntityId, topic_name: impl Into<String>) {
        let info = EndpointInfo {
            guid: Guid {
                prefix: self.config.guid_prefix,
                entity: eid,
            },
            topic_name: topic_name.into(),
            is_writer: true,
        };
        self.local_writers.write().await.insert(eid, info.clone());
        self.announce_writer(&info, None).await;
    }

    /// Records a local reader, announces it to every known peer, and
    /// returns the `Guid`s of any already-discovered remote writers sharing
    /// its topic (matches go-DDS's `registerReader`'s
    /// `r.addSourceGUID(rw.guid)` loop — see the module docs' "No RTPS
    /// participant runtime yet" section for why this returns rather than
    /// notifies in-line).
    //fusa:req REQ-RTPS-031
    pub async fn register_reader(&self, eid: EntityId, topic_name: impl Into<String>) -> Vec<Guid> {
        let topic_name = topic_name.into();
        let info = EndpointInfo {
            guid: Guid {
                prefix: self.config.guid_prefix,
                entity: eid,
            },
            topic_name: topic_name.clone(),
            is_writer: false,
        };
        self.local_readers.write().await.insert(eid, info.clone());

        let matched: Vec<Guid> = self
            .remote_writers
            .read()
            .await
            .values()
            .filter(|rw| rw.topic_name == topic_name)
            .map(|rw| rw.guid)
            .collect();

        self.announce_reader(&info, None).await;
        matched
    }

    /// Announces every local writer and reader to `proxy` alone (not the
    /// whole known-peers table) and requests its endpoints in turn — called
    /// when SPDP discovers a new participant. Matches go-DDS's `onNewPeer`.
    //fusa:req REQ-RTPS-031
    pub async fn on_new_peer(&self, proxy: &ParticipantProxy) {
        let writers: Vec<EndpointInfo> =
            self.local_writers.read().await.values().cloned().collect();
        let readers: Vec<EndpointInfo> =
            self.local_readers.read().await.values().cloned().collect();

        for w in &writers {
            self.announce_writer(w, Some(proxy)).await;
        }
        for r in &readers {
            self.announce_reader(r, Some(proxy)).await;
        }
    }

    // ── Announcement send path ──────────────────────────────────────────

    /// Sends a SEDP publications-writer announcement for `info`. If
    /// `only_to` is `None`, sends to every peer currently known to
    /// [`SpdpService`]. Matches go-DDS's `announceWriter`.
    //fusa:req REQ-RTPS-031
    async fn announce_writer(&self, info: &EndpointInfo, only_to: Option<&ParticipantProxy>) {
        let payload = build_endpoint_data(&self.config, info);
        let submsg = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            SequenceNumber {
                high: 0,
                low: self.next_seq_num(),
            },
            &payload,
        );
        self.broadcast(&submsg, only_to).await;
    }

    /// Sends a SEDP subscriptions-writer announcement for `info`. Matches
    /// go-DDS's `announceReader`.
    //fusa:req REQ-RTPS-031
    async fn announce_reader(&self, info: &EndpointInfo, only_to: Option<&ParticipantProxy>) {
        let payload = build_endpoint_data(&self.config, info);
        let submsg = encode_data_submessage(
            ENTITYID_SEDP_SUB_WRITER,
            ENTITYID_SEDP_SUB_READER,
            SequenceNumber {
                high: 0,
                low: self.next_seq_num(),
            },
            &payload,
        );
        self.broadcast(&submsg, only_to).await;
    }

    async fn broadcast(&self, submsg: &[u8], only_to: Option<&ParticipantProxy>) {
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: self.config.vendor_id,
            guid_prefix: self.config.guid_prefix,
        };
        let msg = wrap_in_rtps_message(header, submsg);

        if let Some(peer) = only_to {
            self.send_to(&msg, peer).await;
            return;
        }
        for peer in self.spdp.known_peers().await {
            self.send_to(&msg, &peer).await;
        }
    }

    async fn send_to(&self, msg: &[u8], peer: &ParticipantProxy) {
        let Some(dst) = peer.metatraffic_unicast.udp_addr() else {
            return;
        };
        if self.send_socket.send_to(msg, dst).await.is_ok() {
            self.announces_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ── Receive path ─────────────────────────────────────────────────────

    /// Spawns the receive loop: consumes `rx` (produced by
    /// [`RtpsSocket::spawn_receive_loop`](super::transport::RtpsSocket::spawn_receive_loop)
    /// on this service's metatraffic unicast socket) and decodes/matches
    /// each SEDP announcement. Matches go-DDS's `receiveLoop`. Exits once
    /// `rx` is closed.
    //fusa:req REQ-RTPS-034
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

    /// Decodes one received datagram and, if it is a well-formed SEDP
    /// publication or subscription announcement from a peer (not this
    /// participant's own), dispatches it to [`SedpService::on_remote_writer`]/
    /// [`SedpService::on_remote_reader`]. Matches go-DDS's `handlePacket`.
    /// Malformed input, non-DATA submessages, and DATA submessages from
    /// neither SEDP writer entity are silently ignored — never panics
    /// (REQ-RTPS-009).
    //fusa:req REQ-RTPS-034
    //fusa:req REQ-RTPS-009
    async fn handle_packet(&self, data: &[u8], from: SocketAddr) {
        let Ok(header) = Header::decode(data) else {
            return;
        };
        if header.guid_prefix == self.config.guid_prefix {
            return; // own packet
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
            let Some(payload) = ds.payload else {
                continue;
            };
            match ds.writer_entity_id {
                ENTITYID_SEDP_PUB_WRITER => {
                    self.handle_endpoint_announce(header.guid_prefix, &payload, true, from)
                        .await;
                }
                ENTITYID_SEDP_SUB_WRITER => {
                    self.handle_endpoint_announce(header.guid_prefix, &payload, false, from)
                        .await;
                }
                _ => {}
            }
        }
    }

    /// Decodes a `PL_CDR_LE` `EndpointData` `payload` into an
    /// [`EndpointInfo`] and dispatches it. Matches go-DDS's
    /// `handleEndpointAnnounce`; never panics on malformed input
    /// (REQ-RTPS-009). An announcement missing a topic name is dropped,
    /// matching go-DDS's `if info.topicName == "" { return }`.
    //fusa:req REQ-RTPS-030
    //fusa:req REQ-RTPS-009
    async fn handle_endpoint_announce(
        &self,
        remote_prefix: GuidPrefix,
        payload: &[u8],
        is_writer: bool,
        from: SocketAddr,
    ) {
        let Ok(decoder) = PlCdrDecoder::new(payload) else {
            return;
        };

        let mut info = EndpointInfo {
            guid: Guid {
                prefix: remote_prefix,
                entity: ENTITYID_UNKNOWN,
            },
            topic_name: String::new(),
            is_writer,
        };
        let mut data_locator = Locator::default();
        let from_v4 = match from {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        };

        for param in decoder {
            match param.pid {
                PID_ENDPOINT_GUID => {
                    if let Ok(g) = Guid::decode(param.value) {
                        info.guid = g;
                    }
                }
                PID_TOPIC_NAME => {
                    if let Ok(t) = super::cdr::decode_string(param.value) {
                        info.topic_name = t;
                    }
                }
                PID_DEFAULT_UNICAST_LOCATOR => {
                    if let Ok(mut loc) = Locator::decode(param.value) {
                        fill_in_zero_address(&mut loc, from_v4);
                        data_locator = loc;
                    }
                }
                _ => {}
            }
        }

        if info.topic_name.is_empty() {
            return;
        }
        self.announces_received.fetch_add(1, Ordering::Relaxed);

        if is_writer {
            self.on_remote_writer(info, data_locator).await;
        } else {
            self.on_remote_reader(info, data_locator).await;
        }
    }

    /// Records a discovered remote writer and matches it against local
    /// readers sharing its topic, recording `data_locator` in
    /// [`SedpService::matched_writer_locator`] for each match. Returns the
    /// `EntityId`s of matched local readers — matches go-DDS's
    /// `onRemoteWriter`'s notification loop (adapted; see the module docs'
    /// "No RTPS participant runtime yet" section).
    //fusa:req REQ-RTPS-032
    async fn on_remote_writer(&self, info: EndpointInfo, data_locator: Locator) -> Vec<EntityId> {
        let guid = info.guid;
        let topic_name = info.topic_name.clone();
        self.remote_writers.write().await.insert(guid, info);

        let local_readers = self.local_readers.read().await;
        let mut matched = Vec::new();
        for lr in local_readers.values() {
            if lr.topic_name == topic_name {
                self.endpoint_matches.fetch_add(1, Ordering::Relaxed);
                matched.push(lr.guid.entity);
            }
        }
        drop(local_readers);

        if !matched.is_empty() {
            self.writer_locators
                .write()
                .await
                .insert(guid, data_locator);
        }
        matched
    }

    /// Records a discovered remote reader and its data-delivery locator so
    /// that [`SedpService::matched_reader_locators`] can later return only
    /// the peers interested in a given topic. Matches go-DDS's
    /// `onRemoteReader`.
    //fusa:req REQ-RTPS-032
    async fn on_remote_reader(&self, info: EndpointInfo, data_locator: Locator) {
        let guid = info.guid;
        self.remote_readers.write().await.insert(guid, info);
        self.remote_reader_locators
            .write()
            .await
            .insert(guid, data_locator);
    }

    /// Removes every remote endpoint (writer or reader) belonging to
    /// `prefix` from the SEDP tables, and drops any matched writer
    /// locators for that prefix too. Called when SPDP evicts a
    /// participant whose lease has expired. Matches go-DDS's
    /// `onPeerEvicted`.
    //fusa:req REQ-RTPS-033
    pub async fn on_peer_evicted(&self, prefix: GuidPrefix) {
        self.remote_writers
            .write()
            .await
            .retain(|guid, _| guid.prefix != prefix);
        self.remote_readers
            .write()
            .await
            .retain(|guid, _| guid.prefix != prefix);
        self.remote_reader_locators
            .write()
            .await
            .retain(|guid, _| guid.prefix != prefix);
        self.writer_locators
            .write()
            .await
            .retain(|guid, _| guid.prefix != prefix);
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// A snapshot of every currently-known remote writer.
    pub async fn known_remote_writers(&self) -> Vec<EndpointInfo> {
        self.remote_writers.read().await.values().cloned().collect()
    }

    /// A snapshot of every currently-known remote reader.
    pub async fn known_remote_readers(&self) -> Vec<EndpointInfo> {
        self.remote_readers.read().await.values().cloned().collect()
    }

    /// The data-delivery locator recorded for `writer_guid`, if it has been
    /// matched against at least one local reader's topic.
    pub async fn matched_writer_locator(&self, writer_guid: Guid) -> Option<Locator> {
        self.writer_locators.read().await.get(&writer_guid).copied()
    }

    /// The data-delivery locators of every currently-known remote reader
    /// subscribed to `topic_name` — the set a local writer for that topic
    /// should deliver samples to.
    pub async fn matched_reader_locators(&self, topic_name: &str) -> Vec<Locator> {
        let readers = self.remote_readers.read().await;
        let locators = self.remote_reader_locators.read().await;
        readers
            .values()
            .filter(|r| r.topic_name == topic_name)
            .filter_map(|r| locators.get(&r.guid).copied())
            .collect()
    }

    /// Cumulative count of local↔remote topic endpoint matches.
    pub fn endpoint_matches(&self) -> u64 {
        self.endpoint_matches.load(Ordering::Relaxed)
    }

    /// Total announcements successfully sent since this service was
    /// created.
    pub fn announces_sent(&self) -> u64 {
        self.announces_sent.load(Ordering::Relaxed)
    }

    /// Total valid SEDP announcements received from peers.
    pub fn announces_received(&self) -> u64 {
        self.announces_received.load(Ordering::Relaxed)
    }
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

    fn writer_eid() -> EntityId {
        EntityId([0x00, 0x00, 0x01, 0x03])
    }

    fn reader_eid() -> EntityId {
        EntityId([0x00, 0x00, 0x01, 0x04])
    }

    fn reference_config() -> SedpConfig {
        SedpConfig {
            guid_prefix: ascending_prefix(),
            vendor_id: VendorId([0x01, 0x27]), // go-DDS's own vendor id, for byte-exact parity
            data_unicast_port: 17411,
        }
    }

    // Reference bytes/values reproduced from go-DDS's actual rtps package
    // (real buildEndpointData/marshalDataSubmessage/wrapInRTPSMessage/
    // newPLCDRDecoder, not reimplemented). Go reproduction (package-local
    // scratch test file, `rtps/zzrepro_sedp_test.go`, never committed to
    // go-DDS, deleted after use):
    //
    //   var prefix GuidPrefix
    //   for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    //
    //   metaSock, _ := newUnicastSocket(17410) // binds exactly port 17410
    //   dataSock, _ := newUnicastSocket(17411)
    //   p := &participant{guidPrefix: prefix, metaSock: metaSock, dataSock: dataSock}
    //   s := newSEDPService(p)
    //
    //   writerEid := EntityId{0x00, 0x00, 0x01, 0x03}
    //   info := &endpointInfo{guid: GUID{Prefix: prefix, Entity: writerEid},
    //       topicName: "Square", isWriter: true}
    //   payload := s.buildEndpointData(info)
    //   fmt.Printf("%x\n", payload)
    //   // -> 030000005a0010000102030405060708090a0b0c0000010305000c00070000
    //   //    00537175617265000007001000090000004344525f424c4f424200000000
    //   //    2f00180001000000034400000000000000000000000000000000000001
    //   //    000000
    //   fmt.Println(len(payload)) // -> 92
    //
    //   submsg := marshalDataSubmessage(EntityIdSEDPPubWriter, EntityIdSEDPPubReader,
    //       SequenceNumber{High: 0, Low: 1}, payload)
    //   msg := wrapInRTPSMessage(prefix, submsg)
    //   fmt.Printf("%x\n", msg)
    //   // -> 52545053020301270102030405060708090a0b0c150570000000100000000
    //   //    3c7000003c20000000001000000030000005a0010000102030405060708090
    //   //    a0b0c0000010305000c0007000000537175617265000007001000090000004
    //   //    344525f424c4f42000000002f0018000100000003440000000000000000000
    //   //    0000000000000000001000000
    //
    //   readerEid := EntityId{0x00, 0x00, 0x01, 0x04}
    //   rinfo := &endpointInfo{guid: GUID{Prefix: prefix, Entity: readerEid},
    //       topicName: "Square", isWriter: false}
    //   rpayload := s.buildEndpointData(rinfo)
    //   fmt.Printf("%x\n", rpayload)
    //   // -> 030000005a0010000102030405060708090a0b0c0000010405000c00070000
    //   //    00537175617265000007001000090000004344525f424c4f424200000000
    //   //    2f00180001000000034400000000000000000000000000000000000001
    //   //    000000
    //
    //   from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 12345}
    //   // decode payload via newPLCDRDecoder + pidEndpointGUID/pidTopicName/
    //   // pidDefaultUnicastLocator, applying the same zero-address fill-in
    //   // handleEndpointAnnounce does:
    //   // decoded guid=0102030405060708090a0b0c00000103 topic=Square
    //   // locator_kind=1 locator_port=17411 locator_addr=<12 zero bytes>0a000009
    //
    // Full run: `go test ./rtps/... -run TestZZReproSEDPBytes -v`
    // (go-DDS commit d61fd41 / rust-DDS branch feat/rtps-sedp).

    //fusa:test REQ-RTPS-029
    #[test]
    fn build_endpoint_data_writer_matches_go_dds_reference() {
        let cfg = reference_config();
        let info = EndpointInfo {
            guid: Guid {
                prefix: ascending_prefix(),
                entity: writer_eid(),
            },
            topic_name: "Square".to_string(),
            is_writer: true,
        };
        let payload = build_endpoint_data(&cfg, &info);
        assert_eq!(payload.len(), 92);
        assert_eq!(
            hex::encode(&payload),
            "030000005a0010000102030405060708090a0b0c0000010305000c0007000000537175617265000007001000090000004344525f424c4f42000000002f00180001000000034400000000000000000000000000000000000001000000"
        );
    }

    //fusa:test REQ-RTPS-029
    #[test]
    fn build_endpoint_data_reader_matches_go_dds_reference() {
        let cfg = reference_config();
        let info = EndpointInfo {
            guid: Guid {
                prefix: ascending_prefix(),
                entity: reader_eid(),
            },
            topic_name: "Square".to_string(),
            is_writer: false,
        };
        let payload = build_endpoint_data(&cfg, &info);
        assert_eq!(
            hex::encode(&payload),
            "030000005a0010000102030405060708090a0b0c0000010405000c0007000000537175617265000007001000090000004344525f424c4f42000000002f00180001000000034400000000000000000000000000000000000001000000"
        );
    }

    //fusa:test REQ-RTPS-029
    #[test]
    fn full_sedp_pub_announcement_matches_go_dds_reference() {
        let cfg = reference_config();
        let info = EndpointInfo {
            guid: Guid {
                prefix: ascending_prefix(),
                entity: writer_eid(),
            },
            topic_name: "Square".to_string(),
            is_writer: true,
        };
        let payload = build_endpoint_data(&cfg, &info);
        let submsg = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
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
            "52545053020301270102030405060708090a0b0c1505700000001000000003c7000003c20000000001000000030000005a0010000102030405060708090a0b0c0000010305000c0007000000537175617265000007001000090000004344525f424c4f42000000002f00180001000000034400000000000000000000000000000000000001000000"
        );
    }

    //fusa:test REQ-RTPS-030
    #[test]
    fn handle_endpoint_announce_decode_matches_go_dds_reference() {
        // Exercises the same decode + zero-address fill-in logic as
        // handle_endpoint_announce, at the field level (see the doc comment
        // above for the go-DDS reference values).
        let cfg = reference_config();
        let info = EndpointInfo {
            guid: Guid {
                prefix: ascending_prefix(),
                entity: writer_eid(),
            },
            topic_name: "Square".to_string(),
            is_writer: true,
        };
        let payload = build_endpoint_data(&cfg, &info);

        let decoder = PlCdrDecoder::new(&payload).unwrap();
        let mut guid = None;
        let mut topic = None;
        let mut locator = Locator::default();
        let from_v4 = Some(Ipv4Addr::new(10, 0, 0, 9));
        for param in decoder {
            match param.pid {
                PID_ENDPOINT_GUID => guid = Some(Guid::decode(param.value).unwrap()),
                PID_TOPIC_NAME => {
                    topic = Some(super::super::cdr::decode_string(param.value).unwrap())
                }
                PID_DEFAULT_UNICAST_LOCATOR => {
                    let mut loc = Locator::decode(param.value).unwrap();
                    fill_in_zero_address(&mut loc, from_v4);
                    locator = loc;
                }
                _ => {}
            }
        }
        assert_eq!(
            guid,
            Some(Guid {
                prefix: ascending_prefix(),
                entity: writer_eid(),
            })
        );
        assert_eq!(topic.as_deref(), Some("Square"));
        assert_eq!(locator.kind, super::super::locator::LOCATOR_KIND_UDPV4);
        assert_eq!(locator.port, 17411);
        let mut expected_addr = [0u8; 16];
        expected_addr[12..16].copy_from_slice(&[10, 0, 0, 9]);
        assert_eq!(locator.address, expected_addr);
    }

    //fusa:test REQ-RTPS-030
    #[test]
    fn handle_endpoint_announce_keeps_nonzero_locator_address_unchanged() {
        let real_locator = Locator::udp_v4([192, 168, 1, 1], 7411);
        let mut loc = real_locator;
        fill_in_zero_address(&mut loc, Some(Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(loc, real_locator);
    }

    // ── Async service-level tests (real loopback sockets) ───────────────

    async fn bound_socket() -> Arc<RtpsSocket> {
        Arc::new(RtpsSocket::bind_unicast_v4(0).await.unwrap())
    }

    fn spdp_for(prefix: GuidPrefix, send: Arc<RtpsSocket>) -> Arc<SpdpService> {
        use super::super::spdp::SpdpConfig;
        SpdpService::new(SpdpConfig::new(0, prefix, 17410, 17411), send)
    }

    //fusa:test REQ-RTPS-031
    #[tokio::test]
    async fn register_writer_records_local_endpoint() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        sedp.register_writer(writer_eid(), "Square").await;
        // No peers known yet, so announce_writer's broadcast is a no-op —
        // registration itself is what we assert here.
        let matched = sedp.register_reader(reader_eid(), "Square").await;
        assert!(matched.is_empty());
    }

    //fusa:test REQ-RTPS-031
    //fusa:test REQ-RTPS-032
    #[tokio::test]
    async fn register_reader_matches_already_known_remote_writer() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        let remote_guid = Guid {
            prefix: {
                let mut p = ascending_prefix();
                p.0[0] = 0xFF;
                p
            },
            entity: writer_eid(),
        };
        sedp.remote_writers.write().await.insert(
            remote_guid,
            EndpointInfo {
                guid: remote_guid,
                topic_name: "Square".to_string(),
                is_writer: true,
            },
        );

        let matched = sedp.register_reader(reader_eid(), "Square").await;
        assert_eq!(matched, vec![remote_guid]);
    }

    //fusa:test REQ-RTPS-032
    #[tokio::test]
    async fn on_remote_writer_matches_local_reader_and_records_locator() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        sedp.register_reader(reader_eid(), "Square").await;

        let mut remote_prefix = ascending_prefix();
        remote_prefix.0[0] = 0xFF;
        let remote_guid = Guid {
            prefix: remote_prefix,
            entity: writer_eid(),
        };
        let info = EndpointInfo {
            guid: remote_guid,
            topic_name: "Square".to_string(),
            is_writer: true,
        };
        let locator = Locator::udp_v4([10, 0, 0, 9], 27411);
        let matched = sedp.on_remote_writer(info, locator).await;

        assert_eq!(matched, vec![reader_eid()]);
        assert_eq!(sedp.endpoint_matches(), 1);
        assert_eq!(
            sedp.matched_writer_locator(remote_guid).await,
            Some(locator)
        );
        assert_eq!(sedp.known_remote_writers().await.len(), 1);
    }

    //fusa:test REQ-RTPS-032
    #[tokio::test]
    async fn on_remote_writer_with_no_matching_local_reader_records_no_locator() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        let mut remote_prefix = ascending_prefix();
        remote_prefix.0[0] = 0xFF;
        let remote_guid = Guid {
            prefix: remote_prefix,
            entity: writer_eid(),
        };
        let info = EndpointInfo {
            guid: remote_guid,
            topic_name: "NoSuchTopic".to_string(),
            is_writer: true,
        };
        let matched = sedp
            .on_remote_writer(info, Locator::udp_v4([10, 0, 0, 9], 27411))
            .await;

        assert!(matched.is_empty());
        assert_eq!(sedp.endpoint_matches(), 0);
        assert_eq!(sedp.matched_writer_locator(remote_guid).await, None);
    }

    //fusa:test REQ-RTPS-032
    #[tokio::test]
    async fn on_remote_reader_and_matched_reader_locators() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        let mut remote_prefix = ascending_prefix();
        remote_prefix.0[0] = 0xFF;
        let remote_guid = Guid {
            prefix: remote_prefix,
            entity: reader_eid(),
        };
        let info = EndpointInfo {
            guid: remote_guid,
            topic_name: "Square".to_string(),
            is_writer: false,
        };
        let locator = Locator::udp_v4([10, 0, 0, 9], 27411);
        sedp.on_remote_reader(info, locator).await;

        assert_eq!(sedp.known_remote_readers().await.len(), 1);
        assert_eq!(sedp.matched_reader_locators("Square").await, vec![locator]);
        assert!(sedp.matched_reader_locators("OtherTopic").await.is_empty());
    }

    //fusa:test REQ-RTPS-033
    #[tokio::test]
    async fn on_peer_evicted_removes_all_endpoints_for_prefix() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        let mut remote_prefix = ascending_prefix();
        remote_prefix.0[0] = 0xFF;

        sedp.register_reader(reader_eid(), "Square").await;
        let writer_guid = Guid {
            prefix: remote_prefix,
            entity: writer_eid(),
        };
        sedp.on_remote_writer(
            EndpointInfo {
                guid: writer_guid,
                topic_name: "Square".to_string(),
                is_writer: true,
            },
            Locator::udp_v4([10, 0, 0, 9], 27411),
        )
        .await;
        let reader_guid = Guid {
            prefix: remote_prefix,
            entity: reader_eid(),
        };
        sedp.on_remote_reader(
            EndpointInfo {
                guid: reader_guid,
                topic_name: "Square".to_string(),
                is_writer: false,
            },
            Locator::udp_v4([10, 0, 0, 9], 27412),
        )
        .await;

        assert_eq!(sedp.known_remote_writers().await.len(), 1);
        assert_eq!(sedp.known_remote_readers().await.len(), 1);
        assert!(sedp.matched_writer_locator(writer_guid).await.is_some());

        sedp.on_peer_evicted(remote_prefix).await;

        assert!(sedp.known_remote_writers().await.is_empty());
        assert!(sedp.known_remote_readers().await.is_empty());
        assert_eq!(sedp.matched_writer_locator(writer_guid).await, None);
        assert!(sedp.matched_reader_locators("Square").await.is_empty());
    }

    //fusa:test REQ-RTPS-034
    #[tokio::test]
    async fn handle_packet_ignores_own_announcement() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let cfg = SedpConfig::new(prefix, 17411);
        let sedp = SedpService::new(cfg, send_socket, spdp);

        let info = EndpointInfo {
            guid: Guid {
                prefix,
                entity: writer_eid(),
            },
            topic_name: "Square".to_string(),
            is_writer: true,
        };
        let payload = build_endpoint_data(&cfg, &info);
        let submsg = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: cfg.vendor_id,
            guid_prefix: prefix, // same prefix as `sedp` itself
        };
        let msg = wrap_in_rtps_message(header, &submsg);

        sedp.handle_packet(&msg, SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)))
            .await;
        assert_eq!(sedp.known_remote_writers().await.len(), 0);
        assert_eq!(sedp.announces_received(), 0);
    }

    //fusa:test REQ-RTPS-034
    #[tokio::test]
    async fn handle_packet_dispatches_pub_and_sub_announcements() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let cfg = SedpConfig::new(prefix, 17411);
        let sedp = SedpService::new(cfg, send_socket, spdp);

        let mut remote_prefix = ascending_prefix();
        remote_prefix.0[0] = 0xFF;
        let remote_cfg = SedpConfig::new(remote_prefix, 27411);

        let winfo = EndpointInfo {
            guid: Guid {
                prefix: remote_prefix,
                entity: writer_eid(),
            },
            topic_name: "Square".to_string(),
            is_writer: true,
        };
        let wpayload = build_endpoint_data(&remote_cfg, &winfo);
        let wsubmsg = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            SequenceNumber { high: 0, low: 1 },
            &wpayload,
        );

        let rinfo = EndpointInfo {
            guid: Guid {
                prefix: remote_prefix,
                entity: reader_eid(),
            },
            topic_name: "Circle".to_string(),
            is_writer: false,
        };
        let rpayload = build_endpoint_data(&remote_cfg, &rinfo);
        let rsubmsg = encode_data_submessage(
            ENTITYID_SEDP_SUB_WRITER,
            ENTITYID_SEDP_SUB_READER,
            SequenceNumber { high: 0, low: 2 },
            &rpayload,
        );

        let mut both = wsubmsg;
        both.extend_from_slice(&rsubmsg);
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: remote_cfg.vendor_id,
            guid_prefix: remote_prefix,
        };
        let msg = wrap_in_rtps_message(header, &both);

        sedp.handle_packet(&msg, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 12345)))
            .await;

        assert_eq!(sedp.announces_received(), 2);
        let writers = sedp.known_remote_writers().await;
        assert_eq!(writers.len(), 1);
        assert_eq!(writers[0].topic_name, "Square");
        let readers = sedp.known_remote_readers().await;
        assert_eq!(readers.len(), 1);
        assert_eq!(readers[0].topic_name, "Circle");
    }

    //fusa:test REQ-RTPS-034
    //fusa:test REQ-RTPS-009
    #[tokio::test]
    async fn handle_packet_ignores_malformed_input_without_panicking() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        sedp.handle_packet(
            b"not an rtps message",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .await;
        sedp.handle_packet(&[], SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await;
        assert_eq!(sedp.known_remote_writers().await.len(), 0);
    }

    //fusa:test REQ-RTPS-030
    //fusa:test REQ-RTPS-009
    #[tokio::test]
    async fn handle_endpoint_announce_drops_missing_topic_name_without_panicking() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);

        // A well-formed but empty (sentinel-only) PL_CDR_LE payload has no
        // PID_TOPIC_NAME, so it must be dropped rather than stored.
        let payload = PlCdrEncoder::new().finish();
        let mut remote_prefix = ascending_prefix();
        remote_prefix.0[0] = 0xFF;
        sedp.handle_endpoint_announce(
            remote_prefix,
            &payload,
            true,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .await;
        assert_eq!(sedp.known_remote_writers().await.len(), 0);
        assert_eq!(sedp.announces_received(), 0);
    }

    //fusa:test REQ-RTPS-031
    #[tokio::test]
    async fn on_new_peer_announces_local_endpoints_to_one_peer() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let cfg = SedpConfig::new(prefix, 17411);
        let sedp = SedpService::new(cfg, Arc::clone(&send_socket), spdp);

        sedp.register_writer(writer_eid(), "Square").await;
        sedp.register_reader(reader_eid(), "Square").await;

        // A real receiving socket standing in for the "new peer"; assert
        // that on_new_peer's unicast sends actually land on it (two
        // datagrams: one writer announcement, one reader announcement).
        let receiver = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let recv_port = receiver.local_port();
        let (mut rx, recv_handle) = receiver.spawn_receive_loop(8);

        let proxy = ParticipantProxy {
            guid: Guid {
                prefix: {
                    let mut p = ascending_prefix();
                    p.0[0] = 0xFF;
                    p
                },
                entity: super::super::guid::ENTITYID_PARTICIPANT,
            },
            metatraffic_unicast: Locator::udp_v4([127, 0, 0, 1], u32::from(recv_port)),
            default_unicast: Locator::default(),
            builtin_endpoints: 0,
            lease_duration: std::time::Duration::ZERO,
            last_seen: None,
        };

        sedp.on_new_peer(&proxy).await;

        let first = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("no datagram received in time")
            .expect("channel closed unexpectedly");
        assert_eq!(&first.data[0..4], b"RTPS");
        let second = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("no second datagram received in time")
            .expect("channel closed unexpectedly");
        assert_eq!(&second.data[0..4], b"RTPS");

        assert_eq!(sedp.announces_sent(), 2);
        recv_handle.abort();
    }

    //fusa:test REQ-RTPS-034
    #[tokio::test]
    async fn spawn_receive_loop_stops_when_channel_closed() {
        let prefix = ascending_prefix();
        let send_socket = bound_socket().await;
        let spdp = spdp_for(prefix, Arc::clone(&send_socket));
        let sedp = SedpService::new(SedpConfig::new(prefix, 17411), send_socket, spdp);
        let (tx, rx) = mpsc::channel(8);
        let handle = sedp.spawn_receive_loop(rx);
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("receive loop did not stop after channel close")
            .unwrap();
    }
}
