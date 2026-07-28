# Roadmap

This document has two parts:

1. **[Parity build-out](#parity-build-out--go-dds-architecture-alignment)** — a
   detailed, tiered plan for bringing rust-DDS to feature parity with
   [go-DDS](https://github.com/SoundMatt/go-DDS), the reference DDS
   implementation in the RELAY ecosystem, including a proposed Cargo workspace
   restructure. This is the authoritative build-out plan; the per-version
   milestones below (v0.2–v0.9) are the same work, already tagged to the tier
   that scopes it.
2. **Per-version milestones** (below) — what ships in each `0.x` release,
   tagged `(Tier N)` against the plan above.

---

## Parity Build-Out — go-DDS Architecture Alignment

**Status:** planning only. No implementation or workspace changes in this
revision — this section exists to scope the work before it starts.

**Tracking:** mirrors the multi-module split proposed in
[go-DDS#71](https://github.com/SoundMatt/go-DDS/issues/71) ("repo re-org —
split into multi-module layout for stable v1 core"), which cpp-DDS and
rust-DDS are both being brought toward under a shared 5-group architecture.
Module names below are proposed pending ratification of the DDS entry in
RELAY spec §13.7.2's standard module-name registry, tracked at
[RELAY#59](https://github.com/SoundMatt/RELAY/issues/59) — **not yet landed,
names may change.** Nothing here should be read as final until #59 merges;
starting Tier 1 work does not need to wait on it (see
[Module naming caveat](#module-naming-caveat) below).

### The parity gap, in concrete terms

As of go-DDS `2160603` / rust-DDS `44e4de8`:

| | rust-DDS | go-DDS |
|---|---|---|
| Source layout | 8 files, single crate (`src/{adapt,error,participant,relay,types}.rs`, `src/mock/mod.rs`, `src/bin/main.rs`) | ~24 packages, single Go module |
| Total LOC (incl. tests) | ~3.4k | 46,687 |
| Production LOC (excl. tests) | ~3.0k | 16,450 |
| Transport | `mock` only — in-process, zero network I/O | `mock` **and** a real pure-Go RTPS/UDP stack (`rtps`, 4,106 production LOC / 10,776 incl. tests — the single largest package by a wide margin), plus `shmem` (776 LOC) and a CycloneDDS CGo bridge (`cyclone`, 413 LOC) |
| Reliability / discovery | none | SPDP + SEDP discovery, HEARTBEAT/ACKNACK reliable delivery, fragmentation — all wire-level |
| Safety / security | none | `safety` (658 LOC, E2E protection) + `security` (639 LOC) + `cert` |
| Types / codegen | none | `idl` (1,382 LOC), `cdr` (348 LOC), `xtypes` (460 LOC) |
| TSN QoS | none | `tsn` (824 LOC) |
| Protocol bridges | none | `bridge/{grpc,rest,wan}` (582 + 275 + 378 = 1,235 LOC); no dedicated mqtt or domain bridge package exists in go-DDS today either — see [Tier 4](#tier-4--bridges) |
| Observability | none | `otel` (64), `admin` (197), `monitor` (504), `record` (395), `services` (231) LOC |
| Tooling | CLI: `version`/`capabilities`/`status` | `cmd/{ddstool,go-dds,latmon,monitor}` (1,462 LOC) |

The single biggest gap by both LOC and by architectural importance is `rtps`:
rust-DDS today only exchanges samples between two `MockParticipant`s in the
same process. It cannot talk on a wire to anything — not another rust-DDS
instance in a different process, not go-DDS, not a commercial DDS stack. That
is why RTPS is Tier 1 and everything else is downstream of it.

### Target workspace architecture

Per the shared 5-group split (mirroring go-DDS#71's proposed
`go.mod`/`bridges/go.mod`/`tools/go.mod`/`observability/go.mod`/`safety/go.mod`
layout, translated to a Cargo workspace):

| Crate (proposed, pending RELAY#59) | Concern | go-DDS equivalent packages | Current rust-DDS source |
|---|---|---|---|
| `dds-core` | core types, `Participant`/`Publisher`/`Subscriber`, RTPS, mock, shared memory, security | `dds`, `rtps`, `mock`, `shmem`, `auto`, `pool`, `security` | `src/types.rs`, `src/participant.rs`, `src/mock/mod.rs`, `src/error.rs`, `src/adapt.rs`, `src/relay.rs` |
| `dds-safety` | E2E safety protection, TSN QoS, cert/evidence | `safety`, `tsn`, `cert/` | none |
| `dds-tools` | IDL parsing, CDR serialization, XTypes, codegen CLI | `idl`, `cdr`, `xtypes`, `cmd/ddstool` | none |
| `dds-bridges` | protocol bridges: mqtt/wan/rest/grpc/domain | `bridge/{mqtt,wan,rest,grpc}` (+ unbuilt domain bridge) | none |
| `dds-observability` | otel/admin/monitor/record/services equivalents | `otel`, `admin`, `monitor`, `record`, `services` | none |

**Interim structure vs. full cutover.** Don't create all five crate
directories on day one — go-DDS's own #71 rationale (don't split a module
boundary until the coupling it prevents actually starts to hurt) applies
here too, and an empty `crates/dds-bridges` with nothing in it for three
tiers is just workspace-manifest overhead. Proposed sequencing:

- **Through all of Tier 1 (RTPS):** stay a single crate. Add
  `src/rtps/` as a new module tree (`participant.rs`, `message.rs`,
  `guid.rs`, `locator.rs`, `spdp.rs`, `sedp.rs`, `reliable.rs`,
  `fragment.rs`, `transport.rs`, `cdr.rs` — mirroring go-DDS's `rtps/`
  file-per-concern layout 1:1, see [Tier 1](#tier-1--rtps-wire-protocol-port)
  below). RTPS internals will churn heavily while SPDP/SEDP/reliability are
  being got right against a live peer; a workspace boundary just adds
  re-publish friction during that churn for no isolation benefit, since
  nothing outside the crate depends on `rtps::` yet.
- **Cargo workspace cutover, at the Tier 1 → Tier 2 boundary:** once RTPS is
  interop-tested and stable, convert the root `Cargo.toml` into a workspace
  manifest (`[workspace] members = ["crates/dds-core"]`) and move all
  existing `src/` content plus the new `src/rtps/` tree into
  `crates/dds-core/src/`. This is also the natural point to cut because
  Tier 2's `security` work is itself scoped into `dds-core` by the target
  architecture (the table above puts `security` in the same crate as `rtps`
  and `mock`) — so the crate boundary is being drawn around code that's
  actually staying together, not split further later. The "interop-tested"
  half of this gate is now satisfied (see the "Interop testing" section's
  **Done** note below, rust-DDS#31); the "Module naming caveat" section's
  separate #59 gate below is still open, so this cutover still should not
  start yet.
- **`crates/dds-safety` created at Tier 2**, holding E2E protection
  (`safety`) first; `tsn` is added to it in Tier 3.
- **`crates/dds-tools` created at Tier 3** (`idl`, `cdr`, `xtypes`,
  plus a `dds-tools` codegen binary mirroring `cmd/ddstool`).
- **`crates/dds-bridges` created at Tier 4.**
- **`crates/dds-observability` created at Tier 5.**

Each cutover is its own PR: workspace-manifest change + `git mv`, no
behavior change, so it reviews independently of the feature work that
motivated it.

### Tier 1 — RTPS wire-protocol port

**Priority: highest. This is the tier that actually matters** — it turns
rust-DDS from an in-process mock into something that can interoperate on a
real network, which is the entire point of a DDS implementation. Reference:
go-DDS's `rtps` package (RTPS 2.3, pure Go / no CGo, 4,106 production LOC +
6,670 test LOC across 15 non-test files). It is the correctness oracle for
this port, not something to be redesigned from scratch — same wire format,
same submessage encoding, same port-assignment formula, so a rust-DDS
participant and a go-DDS participant can talk to each other, which is the
actual goal (not merely "implements the RTPS spec" in isolation).

Sub-phases, scoped against the go-DDS file breakdown:

1. **Wire framing & identifiers** — `Header` (20-byte fixed RTPS message
   header), `GuidPrefix`/`EntityId`/`GUID`, `SequenceNumber` (packed
   High:Low → `u64`, careful of wraparound aliasing — go-DDS's `snToU64`
   in `reliable.go` is the reference), `Locator`. Mirrors go-DDS
   `guid.go` (81 LOC), `locator.go` (136 LOC), the framing half of
   `message.go` (365 LOC total). Magic bytes `"RTPS"`, a vendor ID
   (go-DDS uses an unregistered `0x0127`; rust-DDS needs its own).
   **Done** — landed in [rust-DDS#22](https://github.com/SoundMatt/rust-DDS/pull/22)
   as `src/rtps/{guid,locator,message}.rs`, verified byte-for-byte against
   real go-DDS reference output (`REQ-RTPS-001`..`010`). Internal only —
   not yet wired into `Participant`/`Publisher`/`Subscriber`; that starts
   with sub-phase 3 (UDP transport).
2. **Minimal wire-level CDR** — just enough Common Data Representation to
   encode/decode RTPS submessage headers and inline QoS parameter lists
   (mirrors go-DDS's `rtps/cdr.go`, 193 LOC). **This is deliberately not**
   the general-purpose XCDR1/XCDR2 payload codec that Tier 3's `dds-tools`
   crate will provide for typed, IDL-generated payloads (go-DDS's
   top-level `cdr` package, 348 LOC, is a separate and larger thing) — Tier
   1 only needs enough CDR to get RTPS framing right, not to serialize
   application types.
   **Done** — landed in [rust-DDS#23](https://github.com/SoundMatt/rust-DDS/pull/23)
   as `src/rtps/cdr.rs`: the `PL_CDR_LE` parameter-list encoder/decoder
   (`PlCdrEncoder`/`PlCdrDecoder`) and PID table, plus the plain
   `CDR_LE`/`PL_CDR_LE` payload encapsulation wrap/unwrap helpers, verified
   byte-for-byte against real go-DDS reference output (`REQ-RTPS-011`..`015`,
   `REQ-RTPS-009`). Internal only — not yet wired into `Participant`/
   `Publisher`/`Subscriber`; consumed by SPDP/SEDP starting with sub-phase 4.
3. **UDP transport** — socket setup per the RTPS 2.3 §9.6.1 port formula
   (`metaMulticast(domain) = 7400 + 250*domain`,
   `metaUnicast(domain,i) = 7400 + 250*domain + 10 + 2*i`,
   `dataUnicast(domain,i) = 7400 + 250*domain + 11 + 2*i`), multicast group
   `239.255.0.1`, IPv4 primary with IPv6 as an option (go-DDS's own IPv6
   path is noted as having "limited interop testing" — rust-DDS should not
   claim more confidence than that either). OS-specific socket options
   (`SO_REUSEPORT`, TX timestamping) go through the `socket2` crate's safe
   API rather than raw libc calls — see the no-`unsafe` note below.
   **Done** — landed in [rust-DDS#24](https://github.com/SoundMatt/rust-DDS/pull/24)
   as `src/rtps/transport.rs`: async (tokio) `RtpsSocket` with
   `bind_unicast_v4`/`_v6` (16-port sequential retry, matching go-DDS's
   `newUnicastSocket`/`newUnicastSocketV6`) and `bind_multicast_v4`/`_v6`
   (SO_REUSEADDR/SO_REUSEPORT via `socket2`'s safe API, so multiple local
   participants can share the SPDP multicast port), plus
   `spawn_receive_loop` — one `tokio::task` per socket running
   `recv_from` in a loop and dispatching into an `mpsc` channel, replacing
   go-DDS's single `dataReceiveLoop` goroutine. Port-formula functions and
   the `239.255.0.1`/`FF03::1` multicast constants verified against real
   go-DDS reference values (`REQ-RTPS-016`..`020`). Zero `unsafe`
   (REQ-ASIL-002/REQ-MEM-001). Internal only — not yet wired into
   `Participant`/`Publisher`/`Subscriber`; consumed by SPDP/SEDP starting
   with sub-phase 4.
4. **SPDP** (Simple Participant Discovery) — multicast announce/listen
   at a periodic interval with jitter, known-participants table. Mirrors
   `spdp.go` (379 LOC).
   **Done** — landed in [rust-DDS#25](https://github.com/SoundMatt/rust-DDS/pull/25)
   as `src/rtps/spdp.rs`: `SpdpConfig`/`ParticipantProxy`,
   `build_participant_data`/`parse_participant_data` (the `PL_CDR_LE`
   ParticipantProxy payload codec, including the zero-address
   metatraffic/default-locator fill-in from the announcement's UDP sender
   address), and `SpdpService` — a `tokio::time::interval`-driven announce
   loop (immediate first send, then periodic with optional jitter), a
   receive loop consuming `transport::RtpsSocket::spawn_receive_loop`'s
   `mpsc::Receiver` and dispatching into the known-peers table (self-filtered
   by `GuidPrefix`), and a once-per-second lease-eviction loop — each
   independently stoppable via `.abort()` on its `JoinHandle`, matching
   `transport.rs`'s established idiom. Also adds the generic DATA-submessage
   encode/decode and submessage-iteration helpers (`encode_data_submessage`/
   `decode_data_submessage`/`SubmessageIter`/`wrap_in_rtps_message`) to
   `src/rtps/message.rs`, and the builtin-endpoint bitmask constants to
   `src/rtps/guid.rs` — both, like go-DDS's own file layout, shared
   framing/identifier pieces rather than SPDP-specific. Verified
   byte-for-byte against real go-DDS reference output (`REQ-RTPS-021`..`028`).
   Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001). Internal only — not yet wired
   into `Participant`/`Publisher`/`Subscriber`; consumed by SEDP starting
   with sub-phase 5. Not in scope here (later Tier 1/2 work): SEDP peer
   notification, the `DiscoveryPlugin` authentication hook, and the
   participant-liveliness callback.
5. **SEDP** (Simple Endpoint Discovery) — unicast endpoint announcement
   between participants once SPDP has found them. Mirrors `sedp.go`
   (343 LOC).
   **Done** — landed in [rust-DDS#26](https://github.com/SoundMatt/rust-DDS/pull/26)
   as `src/rtps/sedp.rs`: `SedpConfig`/`EndpointInfo`, `build_endpoint_data`
   (the `PL_CDR_LE` EndpointData payload codec: endpoint GUID, topic name,
   the hard-coded `"CDR_BLOB"` type name, and a zero-address default
   unicast locator filled in by the receiver, mirroring
   `build_participant_data`'s convention), and `SedpService` —
   `register_writer`/`register_reader` (local endpoint bookkeeping plus
   immediate broadcast to every peer known to `SpdpService`),
   `on_new_peer` (announces local endpoints to one newly-discovered peer),
   a receive loop consuming `transport::RtpsSocket::spawn_receive_loop`'s
   `mpsc::Receiver` and dispatching SEDP publication/subscription DATA
   submessages (self-filtered by `GuidPrefix`) into `on_remote_writer`/
   `on_remote_reader`, topic-based matching against local endpoints, and
   `on_peer_evicted` to drop a departed peer's endpoints — each piece
   independently usable, matching `transport.rs`/`spdp.rs`'s established
   idiom. Since no RTPS participant runtime type exists yet to hold
   `rtpsReader`/`rtpsWriter` objects (that composition lands with
   sub-phase 6), matching functions return the matched `EntityId`/`Guid`s
   for a future caller rather than notifying an object in-line — see the
   module's "No RTPS participant runtime yet" doc section. Also adds
   `Locator::udp_addr` (`src/rtps/locator.rs`) for resolving a peer's
   metatraffic locator to a `SocketAddr` send target. Verified byte-for-byte
   against real go-DDS reference output (`REQ-RTPS-029`..`035`). Zero
   `unsafe` (REQ-ASIL-002/REQ-MEM-001). Internal only — not yet wired into
   `Participant`/`Publisher`/`Subscriber`; consumed by sub-phase 6
   ("BestEffort data path"). Not in scope here (later Tier 1/2 work): actual
   sample data delivery, the `EndpointPlugin`/`DiscoveryPlugin`
   authentication hook, and the participant-liveliness callback.
6. **BestEffort data path** — DATA submessage encode/decode, dispatch to
   matched readers by topic + writer GUID. This is the bulk of go-DDS's
   `participant.go` (1,505 LOC total; roughly half of it is receive-loop
   dispatch and reader/writer bookkeeping).
   **Done** — landed in [rust-DDS#27](https://github.com/SoundMatt/rust-DDS/pull/27)
   as `src/rtps/participant.rs`: the first RTPS participant runtime type,
   `RtpsParticipant` — owns `rtpsReader`/`rtpsWriter`-shaped local endpoint
   bookkeeping (`RtpsWriter`/`RtpsReader` handles from `new_writer`/
   `new_reader`), reuses `crate::participant::SampleReceiver`/`SubInner` for
   reader delivery (per the roadmap's async design table, rather than
   inventing a second channel type), and performs real BestEffort DATA
   submessage encode/decode + dispatch to matched local readers by topic
   (local delivery) and by SEDP-matched writer GUID (remote/UDP delivery) —
   composing sub-phase 2's `wrap_payload`/`unwrap_payload` and sub-phase 4's
   `encode_data_submessage`/`decode_data_submessage`/`wrap_in_rtps_message`,
   all previously verified byte-for-byte against go-DDS, so no new wire
   format is introduced here. Also extends `sedp.rs` with
   `SedpService::set_match_listener`/`WriterMatch` and `spdp.rs` with
   `SpdpService::set_peer_listener`, the "future caller" hooks those two
   modules' own docs anticipated — `RtpsParticipant::spawn_sedp_match_listener`
   and `RtpsParticipant::spawn_spdp_peer_listener` consume them to keep a
   reader's accepted-writer-GUID set in sync with SEDP matching discovered
   after registration, and to bridge SPDP peer discovery into SEDP
   (`sedp.on_new_peer`) the way go-DDS's `spdpService.handlePacket` calls
   `s.p.sedp.onNewPeer` directly. Also adds `entity_id_for_writer`/
   `entity_id_for_reader` and `Guid::to_bytes` to `guid.rs`. Verified against
   real go-DDS reference output for the DATA submessage composition and the
   `entityIdForWriter`/`entityIdForReader` byte layout (`REQ-RTPS-036`,
   `REQ-RTPS-037`), plus a real two-participant round trip over loopback UDP
   (`REQ-RTPS-038`..`042`) exercising SEDP-matched BestEffort delivery
   end-to-end — not just discovery. Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001).
   Internal only — not yet wired into `Participant`/`Publisher`/`Subscriber`.
   Not in scope here (later Tier 1 work, per the roadmap's own scoping):
   `INFO_TS`-based timestamp propagation (every delivered `Sample`'s
   `timestamp` is the delivering side's `Utc::now()`, a documented deviation
   — see the module's "DATA submessage payload" doc section), HEARTBEAT/
   ACKNACK reliable-QoS retransmission (sub-phase 7), `DATA_FRAG`
   fragmentation (sub-phase 8), and TransientLocal/wildcard-topic matching
   (sub-phase 9's stretch items).
7. **Reliable QoS** — HEARTBEAT / ACKNACK retransmission, per-writer
   history cache (go-DDS retains 256 samples per writer), gap detection on
   the reader side. Mirrors `reliable.go` (231 LOC) plus the
   heartbeat/acknack handlers in `participant.go`.
   **Done** — landed in [rust-DDS#28](https://github.com/SoundMatt/rust-DDS/pull/28)
   as `src/rtps/reliable.rs` (the sender-side `SendHistory` ring buffer,
   retaining the last 256 sent wire messages per reliable writer, and the
   receiver-side `RecvTracker` contiguous-watermark gap tracker, bounded
   out-of-order buffering capped at 8192 SNs ahead of the watermark — direct
   ports of go-DDS's `sendHistory`/`recvTracker`), extends `src/rtps/message.rs`
   with the HEARTBEAT/ACKNACK/GAP submessage wire codec (mirroring go-DDS's
   own file layout — those codecs live in `message.go`, not `reliable.go`),
   and extends `src/rtps/participant.rs` with `RtpsParticipant::new_reliable_writer`/
   `new_reliable_reader` plus the heartbeat-send/acknack-handle/retransmit
   wiring (`send_heartbeat`, `notify_reliable_readers`, `handle_heartbeat`,
   `handle_acknack`, `advance_acked`) — matching go-DDS's
   `rtpsWriter.sendHeartbeatLocked`/`heartbeatLoop`/`notifyReliableReaders`/
   `handleHeartbeat`/`handleAckNack`/`advanceAcked` behaviourally. A reliable
   writer's periodic HEARTBEAT loop is its own `tokio::task`
   (`tokio::time::interval`-driven, 200ms period matching go-DDS's
   `heartbeatPeriod`), independently stoppable via `.abort()` on the
   `JoinHandle` `new_reliable_writer` returns alongside the writer handle —
   this sub-phase has no writer `Close` path yet to stop it automatically
   (a documented deviation from go-DDS's `rtpsWriter.Close`/`hbDone`, same
   category as sub-phase 6's "no Close path for writers yet" note); for the
   same reason, `waitDrain`/`CloseWithDrain` are not ported (nothing to
   drain into). GAP is encode-only, matching go-DDS's own behavior exactly
   (go-DDS sends GAP but never parses one back on receipt either — no
   `parseGAP`/`submsgGAP` case exists in its own `handleDataPacket` switch).
   Verified byte-for-byte against real go-DDS reference output for the
   HEARTBEAT/ACKNACK/GAP submessage codec (`REQ-RTPS-043`..`045`), plus a
   real two-participant round trip over loopback UDP exercising actual gap
   detection and ACKNACK-driven retransmission end-to-end — one DATA
   datagram is deliberately dropped mid-stream and recovered purely through
   the wire protocol, not local bookkeeping (`REQ-RTPS-046`..`051`). Zero
   `unsafe` (REQ-ASIL-002/REQ-MEM-001). Internal only — not yet wired into
   `Participant`/`Publisher`/`Subscriber`. Not in scope here (later Tier 1
   work, per the roadmap's own scoping): `DATA_FRAG` fragmentation
   (sub-phase 8) and TransientLocal/wildcard-topic matching (sub-phase 9's
   stretch items).
8. **Fragmentation** — `DATA_FRAG` for payloads exceeding one UDP
   datagram. Mirrors `fragment.go` (231 LOC).
   **Done** — landed in [rust-DDS#29](https://github.com/SoundMatt/rust-DDS/pull/29)
   as `src/rtps/fragment.rs`: the DATA_FRAG submessage wire codec
   (`DataFrag`/`encode_data_frag`/`decode_data_frag`, including go-DDS's own
   file-local `submsgDATAFRAG` constant, matching `fragment.go`'s layout
   rather than `message.go`'s), the sender-side splitter
   (`split_into_fragments`/`split_into_fragments_n`, direct ports of
   go-DDS's `splitIntoFragments`/`splitIntoFragmentsN`), and the
   receiver-side reassembly buffer (`FragmentAssembler`, a direct port of
   go-DDS's `fragmentAssembler` — stale-reassembly eviction, out-of-order
   tolerance, and the oversize-`DataSize` rejection guard all included).
   `src/rtps/participant.rs` extends `RtpsWriter::write` to fragment a
   CDR-wrapped payload larger than `MAX_FRAGMENT_PAYLOAD` into DATA_FRAG
   submessages instead of one DATA submessage (matching go-DDS's
   `rtpsWriter.Write`, including reliable writers storing only the first
   fragment's wire message for retransmission — go-DDS's own documented
   simplification, not new here), and adds a `SUBMSG_DATA_FRAG` case to
   `RtpsParticipant::handle_data_packet` that feeds a participant-owned
   `FragmentAssembler` and dispatches a completed reassembly exactly like a
   DATA submessage. The receive-side wiring is a deliberate addition beyond
   go-DDS: go-DDS defines and unit-tests `fragmentAssembler` but never
   calls it from `handleDataPacket` (no `submsgDATAFRAG` case exists there
   either — the same encode-only asymmetry sub-phase 7 already documented
   for GAP), so this sub-phase completes the round trip on the rust-DDS
   side using go-DDS's own (unwired) type as the byte/behavior template —
   see `fragment.rs`'s module docs ("Receive-side wiring") for the
   consequent caveat (its `FragKey` is scoped by writer `EntityId` +
   low-32-bits sequence number, matching go-DDS's own `fragKey` exactly,
   not by full remote `Guid`). Also documents and guards one no-panic edge
   case go-DDS's own (never-exercised) slicing logic does not: a DATA_FRAG
   whose declared fragment layout would slice past a too-short `Payload`
   (which would panic in Go too, just never reached since go-DDS never
   wires this receive path in) is skipped instead, and all
   attacker-controlled-field arithmetic uses wrapping (not panicking)
   operations, preserving REQ-RTPS-009. Verified byte-for-byte against real
   go-DDS reference output for the DATA_FRAG submessage codec and the
   splitter/assembler's exact fragment boundaries (`REQ-RTPS-052`..`054`),
   plus a real two-participant fragmented-payload round trip over loopback
   UDP — one `write()` call whose CDR-wrapped payload spans several
   DATA_FRAG datagrams, reassembled into exactly one delivered `Sample`
   (`REQ-RTPS-055`). Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001). Internal
   only — not yet wired into `Participant`/`Publisher`/`Subscriber`. Not in
   scope here (later Tier 1 work, per the roadmap's own scoping):
   TransientLocal/wildcard-topic matching (sub-phase 9's stretch items).
9. **Small supporting pieces, scoped as stretch items within Tier 1
   rather than deferred**: TransientLocal durability persistence hooks
   (`persist.go`, 87 LOC), topic wildcard matching (`wildcard.go`,
   41 LOC). Zero-copy loan API (`loan.go`, 66 LOC) can be deferred to the
   shared-memory transport tier since it's not meaningful without a
   zero-copy transport underneath it.
   **Done** — landed in [rust-DDS#30](https://github.com/SoundMatt/rust-DDS/pull/30)
   as `src/rtps/persist.rs` and `src/rtps/wildcard.rs`: `persist_load`/
   `persist_flush`/`persist_path` (the disk-backed last-sample cache, one
   file per topic — a 4-byte little-endian length prefix followed by the
   raw payload bytes, byte-exact against real go-DDS output), and
   `topic_matches` (MQTT-style `+`/`#` topic-pattern matching, a direct
   port of go-DDS's `TopicMatches`). `src/rtps/participant.rs` wires both
   in: `RtpsParticipant::new_with_persistent_history` (go-DDS's
   `WithPersistentHistory` functional option, as a second constructor
   alongside the existing `RtpsParticipant::new`) makes `RtpsWriter::write`
   flush the topic's last payload to disk on every write, and adds
   `RtpsParticipant::new_transient_local_reader`/
   `new_reliable_transient_local_reader` — late-joiner delivery of a
   topic's last sample from an in-memory cache first, falling back to disk
   via `persist_load`, matching go-DDS's `NewSubscriber` TransientLocal
   block exactly (including which failure exceeds the disk-fallback
   guard); `RtpsParticipant::dispatch_to_readers` matches a reader's
   (possibly wildcarded) registered topic against a writer's concrete
   topic with `topic_matches` as a fallback to exact equality, exactly
   where go-DDS's own `dispatchToReaders` calls `TopicMatches` — and
   nowhere else: go-DDS's `sedp.go` endpoint matching uses plain `==`
   throughout, no `TopicMatches` call anywhere in that file, so `sedp.rs`'s
   existing literal-equality endpoint matching is intentionally unchanged.
   Verified against real go-DDS reference output for the persisted-file
   byte layout and go-DDS's actual `TopicMatches` output for a fixed table
   of pattern/topic pairs (`REQ-RTPS-056`, `REQ-RTPS-057`). Zero `unsafe`
   (REQ-ASIL-002/REQ-MEM-001). Internal only — not yet wired into
   `Participant`/`Publisher`/`Subscriber`. This closes out Tier 1 (RTPS
   wire-protocol port); the zero-copy loan API (`loan.go`) remains
   deferred to the shared-memory transport tier (v0.4) per this
   sub-phase's own scoping above.

**Async vs. sync — the concrete call for this crate.** rust-DDS is already
committed to `tokio` (`Cargo.toml`: `tokio = { version = "1", features =
["full"] }`, `async-trait`, `tokio-test` as a dev-dependency), and every
existing public method on `Participant`/`Publisher`/`Subscriber` is already
`async fn` via `#[async_trait]`. RTPS I/O should be **async on tokio**, not a
parallel synchronous/thread-based transport underneath an async facade —
introducing a second concurrency model into one crate is its own source of
bugs and would fight the crate's existing idiom for no benefit. Concretely,
translating go-DDS's goroutine/mutex/channel design into tokio:

   | go-DDS (goroutines + channels + mutexes) | rust-DDS (tokio) |
   |---|---|
   | One `dataReceiveLoop` goroutine per participant, multiplexing all sockets, dispatching into `handleDataPacket`/`handleHeartbeat`/`handleAckNack` | One `tokio::task` per UDP socket running `UdpSocket::recv_from` in a loop, decoding and dispatching via an internal `mpsc` channel |
   | One `heartbeatLoop` goroutine per reliable writer, stopped by closing `hbDone chan struct{}` | One `tokio::task` per reliable writer driven by `tokio::time::interval`, cancelled via a `tokio::sync::watch` or `oneshot` on `Close` |
   | `participant.mu sync.Mutex`, `rtpsWriter.mu`, `rtpsReader.mu sync.RWMutex` guarding shared entity state | Prefer a plain (non-async) `Mutex`/`RwLock` (`std::sync` or `parking_lot`) over `tokio::sync::Mutex` for these — critical sections are short bookkeeping updates, and holding a `tokio::sync::Mutex` across an `.await` point is a documented footgun; `parking_lot` avoids poisoning semantics that don't help here (matches the crate's existing "no `.unwrap()` on user-visible paths" posture, REQ-ASIL-003) |
   | `ch chan dds.Sample` (buffered) per reader for delivery to subscribers | `tokio::sync::mpsc::Sender<Sample>` per reader — same shape as `mock::MockParticipant`'s existing `SampleReceiver`, so the RTPS reader can reuse that type rather than inventing a second one |

   **Carry-forward constraint, not a new one:** rust-DDS's existing safety
   requirements REQ-ASIL-002 and REQ-MEM-001 (no `unsafe` anywhere in the
   crate) hold for Tier 1 without exception. go-DDS needed no CGo or raw
   syscalls to implement RTPS either (it's pure Go); `tokio::net::UdpSocket`
   plus `socket2`'s safe API cover everything go-DDS's OS-specific
   `traffic_linux.go`/`traffic_other.go` (154 + 28 LOC) needed platform
   `libc` calls for. This should be flagged explicitly when Tier 1 work
   starts, not discovered partway through.

**Testing.** go-DDS's `rtps` package has ~6,670 LOC of tests against 4,106
LOC of production code (test:prod ≈ 1.6:1) across `rtps_test.go`,
`wire_test.go`, `packet_test.go`, `spdp_coverage_test.go`, `reliable_test.go`,
`persist_test.go`, `access_test.go`, `writectx_test.go`, `rtps_ctx_test.go`,
`rtps_v06_test.go`, `rtps_coverage_test.go`. rust-DDS's Tier 1 test budget
should be at least comparable, and per-phase (framing, SPDP, SEDP,
reliability, fragmentation each get their own test module) — but unit tests
alone don't prove interop; see the next section.

### Interop testing — a real gap beyond RELAY's `interop` command

RELAY's `relay interop` (spec §11.2.1) is **not** a wire-level test, and
using it as the bar for "Tier 1 done" would be a mistake. What it actually
does: for each golden vector, it runs `<binary> convert --protocol P
--format json` against every participating implementation, normalizes
timestamps, and checks that the resulting `relay.Message` JSON is
byte-identical across implementations (and against the in-process reference
computed by `relay convert`). That's a semantic/JSON-level equivalence check
on the RELAY-adapter boundary (`adapt.rs`, `to_message`/`from_message`) — it
never puts a packet on a wire and says nothing about whether rust-DDS's RTPS
framing, SPDP/SEDP handshake, or ACKNACK retransmission actually
interoperates with anything.

Actual RTPS interop testing needs new infrastructure that doesn't exist
anywhere in the ecosystem yet:

- **A live two-process test harness** — a rust-DDS RTPS participant and a
  go-DDS RTPS participant (or two rust-DDS processes) on real UDP
  loopback/multicast, asserting SPDP discovers both sides, SEDP matches
  writer/reader pairs, and samples flow end-to-end (including a
  reliable-QoS run that forces a retransmission). This is the minimum bar
  and should gate Tier 1 completion.
- **pcap-fixture conformance** — recorded known-good RTPS traffic (from
  go-DDS, or ideally a third independent stack) decoded and checked
  byte-for-byte against RTPS 2.3 §9 framing, so wire-format regressions are
  caught without needing a live peer process in every CI run.
- **A third, independent oracle beyond go-DDS self-interop** — go-DDS
  already has a CycloneDDS CGo bridge (`cyclone`, 413 LOC), making
  CycloneDDS the most readily available real independent DDS stack to test
  against; testing rust-DDS only against go-DDS risks both sides sharing
  the same misreading of the spec.

This is real testing-infrastructure work, separate from and in addition to
Tier 1 implementation — it should be scoped as its own workstream (a
`rtps-interop` CI job, analogous to but distinct from the existing
`relay-interop` job, since RELAY's spec-vectors set only covers
Message-level golden vectors today, not RTPS wire captures) and likely
needs a shared home (not duplicated ad hoc per-repo) once cpp-DDS reaches
the same point.

**Done — all 3 of 3 deliverables.** Deliverables 1 and 2 landed in
[rust-DDS#31](https://github.com/SoundMatt/rust-DDS/pull/31) as a new
`rtps-interop` CI job, separate from and in addition to the Tier 1
sub-phase work above, exactly as scoped:

- **Live two-process test harness** (the minimum bar) — `rtps-interop-peer`
  (`src/bin/rtps_interop_peer.rs`, a `[[bin]]` target, not part of the
  public library API), a standalone RTPS participant process driven
  entirely by the real, production `rust_dds::rtps` machinery (real SPDP
  multicast announce/receive/evict, real SEDP unicast announce/receive/
  match, real BestEffort/Reliable data path — no test-only shortcuts).
  `tests/rtps_two_process_interop.rs` spawns two of these as separate OS
  processes on real UDP loopback/multicast and asserts SPDP discovers both
  sides, SEDP matches the writer/reader pair, and samples flow end-to-end —
  including a reliable-QoS run where the reader process deliberately
  discards its own first real receipt of one datagram (a real UDP
  datagram sent by the writer's OS process, already delivered by the
  kernel to the reader's socket, discarded before RTPS dispatch — see
  `RtpsParticipant::handle_data_packet`'s doc comment) and the test
  asserts every sample, including the dropped one, still arrives via
  ACKNACK-driven retransmission and lands in original sequence order —
  the case sub-phase 7's own `reliable_qos_detects_gap_and_retransmits_over_real_udp`
  explicitly does not prove (two live *processes*, not one process's own
  test suite). `#[ignore]`d in the default `cargo test` sweep (unsuited to
  the cross-platform OS/Rust test matrix); runs in the new `rtps-interop`
  CI job (ubuntu-only) via `cargo test --release --test
  rtps_two_process_interop -- --ignored --test-threads=1`.
- **pcap-fixture conformance** — `src/rtps/pcap.rs`: a pure, `unsafe`-free
  encoder/decoder for the standard libpcap file format (global header +
  IPv4/UDP-framed records, `LINKTYPE_RAW`) wrapping RTPS messages, real
  enough to open in Wireshark/`tcpdump -r`. `tests/fixtures/rtps_go_dds_reference.pcap`
  (regenerated via `cargo run --example generate_rtps_pcap_fixture`)
  records seven RTPS 2.3 §9 messages — SPDP announcement, SEDP
  publication + subscription announcements, plain DATA, HEARTBEAT,
  ACKNACK, GAP — built from bytes this crate's own Tier 1 sub-phases
  already independently verified byte-for-byte against go-DDS's real
  encoder (never reimplemented); `tests/rtps_pcap_conformance.rs` decodes
  the checked-in fixture and asserts every message byte-for-byte and via
  this crate's own `Header`/`SubmessageIter`/`decode_*` functions, with no
  live peer process and no network I/O (runs in the default `cargo test`
  sweep as well as the `rtps-interop` job). REQ-RTPS-058.

- **A third, independent oracle beyond go-DDS self-interop** — landed in
  [rust-DDS#33](https://github.com/SoundMatt/rust-DDS/pull/33),
  mirroring go-DDS's own `interop/` package (a live CycloneDDS peer, gated
  behind a build flag, driven by a `docker-compose.yml`) as closely as Rust
  idiom allows. `tests/cyclone_interop.rs` reuses `rtps-interop-peer`
  (unmodified — same production `rust_dds::rtps` code path already proven
  against go-DDS in deliverable 1) as a real, separate OS process talking
  real RTPS/UDP to a live, independent `ddsperf`-driven CycloneDDS
  container (`docker-compose.yml`, repo root), asserting SPDP discovers
  the peer, SEDP matches the writer/reader endpoint announcements, and
  samples flow end-to-end — including a Reliable-QoS run, both publisher-
  and subscriber-side. Gated behind the `cyclone-interop` Cargo feature
  (`#![cfg(feature = "cyclone-interop")]` — the Rust equivalent of go-DDS's
  `interop` Go build tag: without it the test file does not even compile)
  *and* `#[ignore]`, matching this crate's own established posture for
  live-network tests, so it is absent from the normal `cargo test` sweep
  and default CI, same as deliverable 1. Runs in a new `cyclone-interop` CI
  job (`.github/workflows/ci.yml`), analogous to but distinct from
  `rtps-interop`: it probes CycloneDDS Docker image availability first and
  skips cleanly (green, not red) rather than failing when the image cannot
  be pulled — the same graceful-skip posture go-DDS's own `test-interop`
  job uses for the identical reason (a native, environment-dependent image
  is not something ordinary CI should be blocked on; see
  `docker-compose.yml`'s note on the current lack of a published reference
  image, a caveat that applies equally to go-DDS's own compose file, which
  references the same image name). This completes the "Interop testing"
  section's full scope: rust-DDS is now tested against both another
  instance of itself (deliverable 1) and a genuinely independent RTPS
  implementation (deliverable 3), closing the "both sides sharing the same
  misreading of the spec" risk this section opened with.

### Tier 2 — Safety (E2E) + Security

Two independent pieces of work that both slot into the target
architecture's `dds-safety` and `dds-core` crates respectively:

- **`dds-safety::safety`** — E2E protection header (CRC-16, sequence
  counter, freshness check). go-DDS's `safety` package is 658 LOC. This is
  already scoped in this roadmap's existing "Planned — v0.8" list below;
  this tier plan pulls it forward in priority relative to bridges/tooling.
- **`dds-core::security`** — pluggable payload security
  (`SecurityPlugin` trait), HMAC-SHA-256 integrity, AES-256-GCM encryption,
  topic ACL, anti-replay guard, HMAC-SHA-256 **discovery** authentication.
  go-DDS's `security` package is 639 LOC. Matches this roadmap's existing
  "Planned — v0.5" list closely.

Note the dependency edge back into Tier 1: discovery authentication plugs
into SPDP (go-DDS's `participant.go` has a `DiscoveryPlugin` interface
threaded through participant construction) — Tier 2 security work is not
fully decoupled from Tier 1's RTPS internals, so it cannot start completely
independently of Tier 1 landing.

### Tier 3 — xtypes, tsn, idl/cdr

All land in `dds-tools` (idl/cdr/xtypes) except `tsn`, which extends the
`dds-safety` crate created in Tier 2:

- **`dds-tools::cdr`** — general-purpose XCDR1 (and eventually XCDR2)
  codec for typed payload (de)serialization, used by IDL-generated code.
  go-DDS: 348 LOC. Distinct from Tier 1's minimal wire-framing CDR (see
  Tier 1, sub-phase 2). **Already landed** as `rtps::xcdr` under the "v0.2
  — RTPS Transport (Tier 1)" milestone's "CDR/XCDR1 serialization for RTPS
  wire format" item (in-crate, ahead of `dds-tools` existing) — this
  bullet is left here as the pointer to where an eventual XCDR2 extension,
  and/or a Tier-3-time extraction of `rtps::xcdr` into this crate, would
  land; it is not unstarted work.
- **`dds-tools::idl`** — IDL parsing and code generation, plus a
  `dds-tools` CLI binary mirroring go-DDS's `cmd/ddstool`. go-DDS: 1,382
  LOC — the largest single item in this tier.
- **`dds-tools::xtypes`** — DDS-XTypes extensible/evolvable type support,
  depends on `idl` + `cdr` being in place first. go-DDS: 460 LOC.
- **`dds-safety::tsn`** — TSN (802.1) QoS integration, depends on Tier 1's
  transport layer for socket-level priority/DSCP/PCP tagging (go-DDS's
  `tsnSocketForPCP` in `participant.go` is the reference). go-DDS: 824 LOC.

### Tier 4 — bridges

All land in `dds-bridges`: mqtt (proposed name `mqttbr`), wan (`wanbr`),
rest (`restbr`), grpc (`grpcbridge`, a name proposed to be shared with RCP's
existing bridge for the same concern), domain (`domainbr`). go-DDS today has
`bridge/{grpc,rest,wan}` (582 + 275 + 378 = 1,235 LOC) but **no dedicated
mqtt or domain bridge package** — those are gaps in the reference
implementation too, not just in rust-DDS, so Tier 4 for rust-DDS may end up
informing or racing go-DDS's own mqtt/domain bridge work rather than purely
following it. This tier supersedes the ad hoc placement of "Domain bridge"
and "WAN bridge" under this roadmap's existing "Planned — v0.9" list below —
group them under one deliberate `dds-bridges` crate instead of scattering
them across a grab-bag "Enterprise" milestone.

### Tier 5 — observability

Lands in `dds-observability`: otel/admin/monitor/record/services
equivalents (go-DDS: 64 + 197 + 504 + 395 + 231 = 1,391 LOC). Smallest LOC
footprint of the five groups but broad surface area. RELAY#59 leaves
`admin`/`monitor`/`otel`/`record`/`services` **unconstrained** in the
proposed module-name registry (same as most cross-cutting concerns not in
the table) — so, unlike Tiers 1–4, there's no naming ratification blocking
this tier at all.

### Module naming caveat

Every crate/module name above (`dds-core`, `dds-safety`, `dds-tools`,
`dds-bridges`, `dds-observability`, and the bridge names `mqttbr`/`wanbr`/
`restbr`/`grpcbridge`/`domainbr`) is a **proposed** name pending review and
ratification of RELAY spec §13.7.2's DDS registry entry, tracked at
[RELAY#59](https://github.com/SoundMatt/RELAY/issues/59). The spec issue
itself flags open questions (are `mqttbr`/`wanbr`/`restbr`/`domainbr` the
right shape vs. a more generic bridge-grouping name; should `grpcbridge`
really be shared between DDS and RCP) that could change these names before
they land. This does not block starting Tier 1 — RTPS work happens inside
the existing single-crate `rust_dds` and doesn't need a crate name yet. It
does mean the Cargo workspace cutover proposed above (at the Tier 1 → Tier 2
boundary) should not be scheduled to start before #59 has at least a
provisional resolution, since that cutover is exactly the point where these
names get written into `Cargo.toml` `[package] name` fields and become
harder to change.

---

## Per-version milestones

### Released — v0.1 — Foundation

- [x] `Participant`, `Publisher`, `Subscriber` traits per RELAY spec §8.2
- [x] `Domain` type with validation (0–232)
- [x] `Guid`, `Sample`, `QoS`, `ReliabilityKind`, `DurabilityKind` types per §15.7.2
- [x] `DEFAULT_QOS` (BestEffort + Volatile) and `RELIABLE_QOS` (Reliable + TransientLocal)
- [x] `mock::MockParticipant` — in-process broker, zero dependencies
- [x] TransientLocal last-value cache for late-joining subscribers
- [x] Back-pressure policies: DropNewest, DropOldest, Block
- [x] `SampleReceiver` with async `recv()` and non-blocking `try_recv()`
- [x] Monotonic per-writer sequence numbers and writer GUID on all samples
- [x] `Subscriber::unsubscribe()` — stops delivery without closing the channel
- [x] `Error` enum with all four mandatory RELAY sentinels and DDS-specific variants
- [x] `adapt()` — wraps any `Participant` as a `relay::Node` per RELAY §10.3
- [x] `Sample::to_message()` / `Sample::from_message()` round-trip per §15.7.2
- [x] `relay::Node::subscribe()` requires topic via `relay::with_topic()`
- [x] `RELAY_SPEC_VERSION` — tracks the crate's current RELAY spec conformance (source of truth: `rust_dds::RELAY_SPEC_VERSION` / `rust-dds version --format json`)
- [x] CLI binary: `version`, `capabilities`, `status`
- [x] 37 passing tests; CI on ubuntu/macos/windows × Rust 1.75/stable
- [x] DCO enforced in CI

### Planned — v0.2 — RTPS Transport (Tier 1)

- [x] Pure-Rust RTPS/UDP transport (`rtps::RtpsParticipant`) — the RTPS
  engine itself (`rtps::participant::RtpsParticipant` and its
  `RtpsWriter`/`RtpsReader` handles) landed across Tier 1 sub-phases 1–9
  (`rust-DDS#22`–`#30`); this item's own remaining scope — wiring that
  engine into a public-facing implementation of
  `Participant`/`Publisher`/`Subscriber` so application code can use it the
  same way it uses `mock::MockParticipant` — is done:
  `rtps::dds_participant::RtpsUdpParticipant`. `RtpsUdpParticipant::new`
  binds the meta/data unicast sockets and the SPDP multicast socket at the
  RTPS 2.3 §9.6.1 formula ports and starts every background task a live
  participant needs (SPDP announce/evict/receive, SEDP receive, the
  SPDP→SEDP and SEDP→`RtpsParticipant` discovery bridges, the data-socket
  receive/dispatch loop) — the same bootstrap sequence
  `src/bin/rtps_interop_peer.rs` already exercised as a standalone test/dev
  binary, now behind a library constructor. `QoS::reliability`/
  `QoS::durability` select among the four reader constructors sub-phase 9
  built (BestEffort/Reliable × Volatile/TransientLocal). `adapt()`/
  `relay::Node` need no change: they already work with any
  `Arc<dyn Participant>`. Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001).
- [x] CDR/XCDR1 serialization for RTPS wire format — the general-purpose
  primitive-type CDR/XCDR1 codec for typed, non-opaque DATA/DATA_FRAG
  payloads, deliberately distinct from Tier 1 sub-phase 2's `cdr` module
  (`PL_CDR_LE` parameter-list codec + `wrap_payload`/`unwrap_payload`
  plain-payload encapsulation helpers, `rust-DDS#23`) — that sub-phase's
  own "Done" note flagged this as future work. Landed as
  `rtps::xcdr::{XcdrEncoder, XcdrDecoder}`: encode/decode of bool, octet
  (signed/unsigned), char, 16/32/64-bit signed/unsigned integers, 32/64-bit
  IEEE 754 floats, CDR strings, and byte sequences, little-endian, each
  primitive aligned to its own size (1/2/4/8 bytes) counted from the start
  of the 4-byte `CDR_LE` encapsulation header exactly like go-DDS's own
  alignment origin — ported 1:1 from go-DDS's top-level `cdr` package
  (`tools/cdr/cdr.go`, 348 LOC, matching this item's original scope note).
  Structs and typed sequences are composed by callers from these primitive
  writes/reads in sequence (the same convention go-DDS's own `cdr` package
  uses — it has no dedicated struct or typed-sequence type either), which
  is what IDL-generated (de)serialization code will eventually do; this
  item is the primitive codec those callers compose, not a code generator.
  Every encode case is verified byte-for-byte against real go-DDS `cdr`
  package reference output (`REQ-RTPS-063`–`066`), and no `unsafe`
  anywhere (REQ-ASIL-002/REQ-MEM-001). Scoped inside the existing
  single `rust_dds` crate per this roadmap's own crate-cutover sequencing
  (see "Module naming caveat" above) — not a new `dds-tools` crate, which
  remains gated to Tier 3 pending RELAY#59 naming ratification; see the
  Tier 3 "xtypes, tsn, idl/cdr" section's `dds-tools::cdr` bullet for the
  note on a possible later extraction into that crate once it exists.
- [x] SPDP participant discovery (multicast + unicast) — the multicast half
  landed with sub-phase 4 (`rust-DDS#25`) and has been wired into
  `RtpsUdpParticipant` since v0.13; this item's own remaining scope — a
  static/configured peer-unicast-address mode, for environments where
  multicast routing is unavailable or undesirable (Docker/cloud networks,
  TSN segments) — is done, landed in
  [rust-DDS#34](https://github.com/SoundMatt/rust-DDS/pull/34):
  `SpdpConfig::peer_locators`/`SpdpConfig::with_peer_locators` (a list of
  static peer unicast `SocketAddr`s) and `SpdpConfig::no_multicast`/
  `SpdpConfig::with_no_multicast` (independently disables the multicast
  send), `src/rtps/spdp.rs`. `SpdpService::send_announcement` sends the
  same already-verified `ParticipantData` announcement directly (unicast,
  via the existing `send_socket`) to every configured peer address, in
  addition to (or, with `no_multicast`, instead of) the multicast group —
  no new wire format, only the destination address of an already-correct
  encode. Wired into the public API as
  `RtpsUdpParticipant::new_with_config`/`RtpsUdpParticipantConfig`
  (`src/rtps/dds_participant.rs`), which also fans the metatraffic unicast
  socket's receive loop out to both SPDP and SEDP (a peer's unicast SPDP
  announcement arrives on the same socket SEDP unicast traffic already
  uses) and, when multicast is disabled, skips binding/joining the SPDP
  multicast socket entirely. Mirrors go-DDS's `WithPeerLocators`/
  `WithNoMulticast` `Option`s (`rtps/participant.go`) in shape, translated
  to this crate's own builder-style config idiom rather than go-DDS's
  functional-options-string signature — with one documented deviation
  found by inspecting a fresh go-DDS clone rather than assumed: go-DDS's
  own `peerLocators` field is stored by `WithPeerLocators` but never read
  by `sendAnnouncement` (no unicast send is actually wired there), and
  `noMulticast` only gates the unrelated user-data multicast socket, not
  SPDP multicast (`rtps/packet_test.go`'s own
  `TestWithNoMulticast_ParticipantStarts` comment says as much) — so this
  sub-feature has no working byte/behavioural go-DDS oracle to verify
  against; rust-DDS's implementation follows go-DDS's own doc comments (the
  stated intent of those two options) as the design reference instead, and
  ends up wiring the send-time behaviour go-DDS's own API surface still
  only promises. Verified with unit tests in `src/rtps/spdp.rs` proving
  unicast-sent announcements reach a peer over real loopback UDP without
  any multicast socket involved (single- and multi-peer), plus an
  in-process two-participant `RtpsUdpParticipant` test
  (`src/rtps/dds_participant.rs`) and a real two-OS-process extension of
  the existing interop harness
  (`tests/rtps_two_process_interop.rs::unicast_only_discovery_and_besteffort_delivery_between_two_live_processes_with_no_multicast`,
  via new `--no-multicast`/`--peer`/`--meta-port` flags on
  `src/bin/rtps_interop_peer.rs`) — SPDP discovery, SEDP matching, and
  BestEffort delivery all working end-to-end with no multicast socket bound
  on either side. Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001). REQ-RTPS-059.
- [x] SEDP endpoint announcement
- [x] BestEffort delivery over UDP multicast and unicast — a second remote
  delivery path alongside the existing per-locator unicast one, landed in
  [rust-DDS#35](https://github.com/SoundMatt/rust-DDS/pull/35):
  `transport::USER_DATA_MULTICAST_ADDR` (`239.255.0.2`) and
  `transport::user_multicast_port` (the RTPS 2.3 §9.6.1 domain-scoped
  formula, `portBase + domainGain*domain + 1` — one port shared by every
  participant on the domain, no per-participant term, unlike the meta/data
  unicast ports), matching go-DDS's `rtps.userDataMulticastAddr`/
  `userMulticastPort` byte-for-byte/value-for-value. Unlike SEDP's
  per-topic unicast locator (`PID_DEFAULT_UNICAST_LOCATOR`), no new SEDP
  wire field was needed: go-DDS's own reference implementation
  (`rtps/participant.go`) does not advertise a per-topic multicast locator
  either — a single well-known, domain-scoped group is used whenever any
  reader is matched, resolved from `SedpService::matched_reader_locators`'s
  existing non-empty check alone. `RtpsParticipant::set_user_data_multicast_addr`
  (a post-construction setter, mirroring `SedpService::set_match_listener`'s
  established idiom, since the caller only knows the address once it has
  attempted — and possibly failed — to bind the multicast receive socket)
  configures the destination; `RtpsWriter::write` then sends each wire
  message once to that destination instead of once per matched reader's
  unicast locator, whenever at least one remote reader is matched — for
  both BestEffort and Reliable writers, since go-DDS's own condition
  (`len(locs) > 0 && w.p.dataMcastSock != nil`) does not distinguish them
  either. `RtpsUdpParticipant::new`/`new_with_config` bind and join the
  multicast group at construction — soft-fail (never a construction error)
  matching go-DDS's own `dataMcastSock` bind convention ("failure is soft:
  fall back to unicast-only delivery") — and feed its receive loop into the
  same `RtpsParticipant::spawn_receive_loop` dispatch path the unicast data
  socket already uses, so a matched reader receives a multicast-delivered
  sample identically to a unicast-delivered one, no new decode/dispatch
  logic required. `RtpsUdpParticipantConfig::with_no_multicast` now gates
  *both* multicast sockets (SPDP and user-data) with the one flag — a
  deliberate, documented improvement on go-DDS's own `WithNoMulticast`,
  whose doc comment claims to disable "SPDP multicast discovery" but, per a
  fresh go-DDS clone's actual `participant.go`, only ever gates the
  unrelated user-data multicast socket (the same go-DDS inconsistency this
  same milestone's "SPDP participant discovery" entry above already found
  and documented). Verified against real go-DDS reference values for the
  multicast address/port formula (`REQ-RTPS-060`), a real two-participant
  round trip over loopback UDP proving delivery arrives via the multicast
  socket specifically — not the per-reader unicast fallback —
  (`REQ-RTPS-061`), and a `RtpsUdpParticipant`-level two-process-equivalent
  pub/sub round trip with multicast left on by default (`REQ-RTPS-062`).
  Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001).
- [x] IPv4 and IPv6 multicast support — wires sub-phase 3's already-landed
  IPv6 transport primitives (`transport::bind_unicast_v6`/`bind_multicast_v6`,
  `SPDP_MULTICAST_ADDR_V6`) into the public `RtpsUdpParticipant` API, landed
  in [rust-DDS#36](https://github.com/SoundMatt/rust-DDS/pull/36):
  `RtpsUdpParticipantConfig::with_ipv6` (builder style, matching
  `with_peer_locators`/`with_no_multicast`) switches every socket this
  participant binds — meta/data unicast, SPDP multicast, user-data
  multicast — from IPv4 to IPv6 together, plus the new
  `transport::USER_DATA_MULTICAST_ADDR_V6` (`FF03::2`, one site-local group
  past `SPDP_MULTICAST_ADDR_V6`) for the user-data half. This is a
  deliberate **address-family switch, not a dual-stack add-on** — the one
  documented deviation from go-DDS's own `WithIPv6` `Option`, which *adds* a
  second, parallel set of IPv6 sockets alongside the IPv4 ones. Inspecting a
  fresh go-DDS clone found that go-DDS's own IPv6 sockets are, today, only
  ever wired into the user-data receive path — `mcastSockV6`/`metaSockV6`
  are bound but never threaded into any SPDP/SEDP receive loop, so go-DDS's
  `WithIPv6` cannot actually *discover* a peer over IPv6 at all. A
  single-family switch avoids reproducing that gap: `SpdpConfig::ipv6`/
  `SedpConfig::ipv6` (new fields, same builder idiom) make
  `build_participant_data`/`build_endpoint_data` advertise
  `LOCATOR_KIND_UDPV6` zero-address locators instead of `LOCATOR_KIND_UDPV4`
  ones, `SpdpService::send_announcement` sends to `SPDP_MULTICAST_ADDR_V6`
  instead of `SPDP_MULTICAST_ADDR`, and both modules' zero-address fill-in
  logic (previously IPv4-only, silently dropping an IPv6 sender's address)
  now dispatches on the decoded locator's own kind against the datagram's
  real source-address family — so every code path this participant already
  has (SPDP announce/receive, SEDP announce/receive, BestEffort/Reliable
  data, both multicast groups) works identically under `with_ipv6()`, over
  real IPv6 end to end. No go-DDS byte oracle for the IPv6-specific pieces
  (go-DDS's own `buildParticipantData`/`buildEndpointData` never emit an
  IPv6 locator, and `USER_DATA_MULTICAST_ADDR_V6` has no go-DDS counterpart
  at all — go-DDS has no IPv6 user-data multicast socket) — the wire
  encoding itself is unchanged from what `locator.rs`'s existing
  `Locator::udp_v6` tests already verify byte-for-byte; what's new here is
  purely which family gets selected and Rust-side internal-consistency
  tests cover that. Verified with unit tests in `spdp.rs`/`sedp.rs`
  (locator-family selection, zero-address fill-in, multicast-destination
  selection — all deterministic, no real sockets needed) and `transport.rs`
  (the new constant), an in-process two-`RtpsUdpParticipant`
  SPDP+SEDP+BestEffort round trip entirely over real IPv6 multicast
  (`dds_participant.rs`), and a `--ipv6` extension of the live two-process
  interop harness (`tests/rtps_two_process_interop.rs`,
  `src/bin/rtps_interop_peer.rs`) mirroring the existing IPv4 case. Per
  go-DDS's own `WithIPv6` doc comment and this crate's sub-phase 3 IPv6
  primitives, this carries forward — not upgrades — the **limited interop
  testing** caveat: proven against this crate's own two independently
  started participants/processes talking IPv6 to each other, not against a
  third-party DDS implementation's IPv6 path; every real-IPv6-multicast
  test soft-skips (not fails) in an environment without a usable
  IPv6-multicast-capable interface, the same posture every IPv4-multicast
  test in this crate already has. Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001).

### Planned — v0.3 — Reliable QoS (Tier 1)

- [x] Reliable delivery with HEARTBEAT / ACKNACK retransmission
- [x] TransientLocal durability over RTPS (SEDP history cache)
- [x] Fragment support for large payloads (DATA_FRAG)
- [x] Deadline QoS subscriber enforcement with callback (`SubscriberOptions::deadline_missed` /
  `relay::with_deadline_callback`; a per-reader `tokio` watcher task, independently
  stoppable, following the SPDP-announce-loop/reliable-writer-HEARTBEAT-loop idiom;
  uniform across `mock::MockParticipant` and `RtpsUdpParticipant`, both
  BestEffort/Reliable and Volatile/TransientLocal — API shape follows go-DDS's own
  `SubscriberConfig.DeadlineMissedCallback`/`WithDeadlineMissed` reference behavior)

### Planned — v0.4 — Shared-Memory Transport

- [x] `shmem::ShmemParticipant` — POSIX shared-memory zero-copy transport —
  landed as `src/shmem/{pool,broker,ipc,participant,loan}.rs`, mirroring
  this crate's established `src/rtps/` file-per-concern layout inside the
  existing single `rust_dds` crate per the "Interim structure vs. full
  cutover" sequencing above (the Cargo workspace split remains gated on
  RELAY#59). `shmem::ShmemParticipant` implements
  `Participant`/`Publisher`/`Subscriber` the same way
  `mock::MockParticipant` and `rtps::dds_participant::RtpsUdpParticipant`
  do, so `adapt()`/`relay::Node` work with it via `Arc<dyn Participant>`
  with no changes needed there. Same-process participants on one `Domain`
  share an in-process `broker::Broker` (structural port of go-DDS's
  `shmem.go` broker section — zero file I/O for same-process delivery);
  cross-process delivery (`ipc.rs`) uses a per-(domain, topic) rendezvous
  file, written atomically (write-then-rename) on every publish and
  polled by each subscriber, in place of go-DDS's Unix-domain-socket
  notification — documented and justified in `ipc.rs`'s own module docs:
  this crate's CI matrix includes `windows-latest`
  (`cargo test --all-features`), where `AF_UNIX SOCK_DGRAM` is not a
  portable option, and inspecting a fresh go-DDS clone found its own
  `shmem` package does not use POSIX `mmap`/`shm_open` either despite its
  package doc comment's claim — `shmPublish`/`readData` are plain
  `os.Create`/`os.Open`/`io.ReadFull`, the same category of
  implementation this port uses. **The "POSIX shared-memory" vs.
  "zero-`unsafe`" tension flagged before this work started**: real POSIX
  shared memory (`mmap`/`shm_open`, or a wrapping crate like
  `memmap2`/`shared_memory`) requires treating a region another process
  can concurrently mutate as a Rust reference — exactly the aliasing the
  borrow checker cannot verify, so every such crate's actual byte-access
  API is an `unsafe fn` one level down. This port does not reach for it:
  the "shared-memory" transport's data channel is a plain file, preserving
  REQ-ASIL-002/REQ-MEM-001's zero-`unsafe` bar without exception (grep
  confirms zero `unsafe` blocks/fns/impls in the whole crate, including
  this module tree) — the same choice go-DDS's own reference already made
  in practice, not a new compromise. Also fixes two gaps found in go-DDS's
  own reference by inspecting a fresh clone rather than assuming: (1)
  go-DDS's `shmTopicDir` ignores `Domain` entirely for the cross-process
  rendezvous path (only its in-process `sharedBrokers` map is
  domain-keyed) — this port's rendezvous path includes the domain; (2)
  go-DDS's own `shmListener` only reacts to a notification arriving after
  it starts, so a go-DDS shmem subscriber started after a remote
  process's last TransientLocal write never receives it cross-process —
  this port's poller seeds from the rendezvous file's current content on
  first poll for `DurabilityKind::TransientLocal`, closing that gap; and
  (3) go-DDS's own reference has a real, its-own-tests-documented
  same-process double-delivery behavior (`shmem_test.go`'s
  `TestSequenceNumber_Shmem`/`TestWriterGUID_Shmem` filter it out rather
  than prevent it) — this port prevents it instead, via a per-process
  random `origin_id` embedded in every rendezvous-file write that the
  writing process's own poller skips (see `ipc.rs`'s module docs, "Same-
  process double-delivery"). `QoS::durability`/`max_sample_size`/
  `deadline_ns` (the last via the same `participant::spawn_deadline_watcher`
  every other transport in this crate uses) are enforced the same way
  `mock::MockParticipant` enforces them; `QoS::reliability` has no
  shmem-specific meaning (no retransmission concept for a local file
  write), matching go-DDS. REQ-SHMEM-001..008. Zero `unsafe`
  (REQ-ASIL-002/REQ-MEM-001). Tested with unit tests per concern
  (`pool`/`broker`/`ipc`/`participant`/`loan`, including in-process
  domain/topic isolation, TransientLocal, back-pressure, and an explicit
  same-process-exactly-once-not-twice regression test) plus a real
  two-process round-trip test analogous to `rtps_two_process_interop.rs`
  (`tests/shmem_two_process_interop.rs` + `src/bin/shmem_interop_peer.rs`,
  a new `shmem-interop` CI job): two independent OS processes exchanging
  five samples with strictly increasing sequence numbers over the real
  rendezvous file (no shared `Broker`, no socket), plus a late-joining
  reader started only *after* the writer process has already published
  and fully exited, receiving the writer's last TransientLocal value
  purely from disk — proving the cross-process path is real IPC, not an
  in-process shortcut.
- [x] `LoaningPublisher` trait with pool-backed zero-copy writes — the
  go-DDS `loan.go` zero-copy loan API Tier 1 sub-phase 9 (`rust-DDS#30`)
  deliberately deferred to this milestone "since it's not meaningful
  without a zero-copy transport underneath it"; `shmem::ShmemParticipant`
  (above) is that transport. `LoaningPublisher` (extending `Publisher`
  with `loan(size)`/`commit(buf)`) is declared in `src/participant.rs`
  alongside `Publisher`, mirroring go-DDS's own placement of
  `dds.LoaningPublisher` next to `dds.Publisher` in `dds.go` — so a future
  transport can implement it too — with `shmem::ShmemLoaningPublisher`
  (`src/shmem/loan.rs`) as its first implementation, backed by
  `shmem::pool::BytePool` (a port of go-DDS's `pool.BytePool`, capped at a
  bounded free-list size rather than go-DDS's GC-reclaimed `sync.Pool`,
  since Rust has no GC to fall back on for that reclamation).
  `ShmemParticipant::new_loaning_publisher` is an inherent method on the
  concrete participant type rather than, as go-DDS's
  `shmem.NewLoaningPublisher` does, a free function taking `dds.Participant`
  and type-asserting the concrete publisher it just created — a small,
  deliberate Rust-idiomatic simplification that turns a go-DDS runtime
  `ErrLoanBuffer` failure mode (passing the wrong transport's participant
  in) into a compile error instead, so there is no such failure mode left
  to test for here. `loan`'s zero-fill of newly-visible buffer bytes (via
  safe `Vec::resize`, not an `unsafe { set_len }` shortcut) is the one
  documented, functionally-immaterial difference from go-DDS's raw
  reused-memory `buf[:size]` re-slice — the caller overwrites the loaned
  range before `commit` in both implementations regardless. REQ-LOAN-001..
  003. Zero `unsafe` (REQ-ASIL-002/REQ-MEM-001). Unit-tested: loan/commit
  round trip delivering through a live subscriber, oversized-loan
  `Error::LoanBuffer`, loan-after-close `Error::Closed`, pool reuse across
  repeated loan/commit cycles, and `QoS::max_sample_size` enforcement
  flowing through `commit`.

### Planned — v0.5 — Security (Tier 2)

- [ ] Pluggable payload security trait (`SecurityPlugin`)
- [ ] HMAC-SHA-256 integrity plugin
- [ ] AES-256-GCM encryption plugin
- [ ] Topic ACL (`AccessPolicy`)
- [ ] Anti-replay guard (`ReplayGuard`)
- [ ] HMAC-SHA-256 discovery authentication

### Planned — v0.6 — Observability (Tier 5)

- [ ] `HealthProvider` trait
- [ ] `MetricsProvider` trait (per-topic write/deliver/drop counters)
- [ ] `Drainer` / close-with-drain
- [ ] Structured logging via `tracing` crate

### Planned — v0.7 — Developer Experience

- [ ] `testutil` — `NewParticipant`, `assert_sample`, `TopicRecorder`, `burst_publish`
- [ ] CLI `pub`, `sub`, `discover` subcommands
- [ ] `WaitSet` — multiplex over multiple subscribers

### Planned — v0.8 — Advanced Features (E2E protection item is Tier 2)

- [ ] Typed generics `TypedPublisher<T>` / `TypedSubscriber<T>` with `JsonCodec<T>` and `ProtoCodec<T>`
- [ ] Topic recording (JSONL) and deterministic replay
- [ ] Fault injection wrapper
- [ ] E2E protection header (CRC-16, sequence counter, freshness)

### Planned — v0.9 — Enterprise (bridge items are Tier 4)

- [ ] X.509/ECDSA CertPlugin
- [ ] Domain bridge (in-process participant-to-participant forwarding)
- [ ] WAN bridge (TCP, length-framed JSON)
- [ ] HTTP admin API
- [ ] Managed service lifecycle wrappers
