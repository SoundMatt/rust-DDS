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
  actually staying together, not split further later.
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
4. **SPDP** (Simple Participant Discovery) — multicast announce/listen
   at a periodic interval with jitter, known-participants table. Mirrors
   `spdp.go` (379 LOC).
5. **SEDP** (Simple Endpoint Discovery) — unicast endpoint announcement
   between participants once SPDP has found them. Mirrors `sedp.go`
   (343 LOC).
6. **BestEffort data path** — DATA submessage encode/decode, dispatch to
   matched readers by topic + writer GUID. This is the bulk of go-DDS's
   `participant.go` (1,505 LOC total; roughly half of it is receive-loop
   dispatch and reader/writer bookkeeping).
7. **Reliable QoS** — HEARTBEAT / ACKNACK retransmission, per-writer
   history cache (go-DDS retains 256 samples per writer), gap detection on
   the reader side. Mirrors `reliable.go` (231 LOC) plus the
   heartbeat/acknack handlers in `participant.go`.
8. **Fragmentation** — `DATA_FRAG` for payloads exceeding one UDP
   datagram. Mirrors `fragment.go` (231 LOC).
9. **Small supporting pieces, scoped as stretch items within Tier 1
   rather than deferred**: TransientLocal durability persistence hooks
   (`persist.go`, 87 LOC), topic wildcard matching (`wildcard.go`,
   41 LOC). Zero-copy loan API (`loan.go`, 66 LOC) can be deferred to the
   shared-memory transport tier since it's not meaningful without a
   zero-copy transport underneath it.

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
  Tier 1, sub-phase 2).
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

- [ ] Pure-Rust RTPS/UDP transport (`rtps::RtpsParticipant`)
- [ ] CDR/XCDR1 serialization for RTPS wire format
- [ ] SPDP participant discovery (multicast + unicast)
- [ ] SEDP endpoint announcement
- [ ] BestEffort delivery over UDP multicast and unicast
- [ ] IPv4 and IPv6 multicast support

### Planned — v0.3 — Reliable QoS (Tier 1)

- [ ] Reliable delivery with HEARTBEAT / ACKNACK retransmission
- [ ] TransientLocal durability over RTPS (SEDP history cache)
- [ ] Fragment support for large payloads (DATA_FRAG)
- [ ] Deadline QoS subscriber enforcement with callback

### Planned — v0.4 — Shared-Memory Transport

- [ ] `shmem::ShmemParticipant` — POSIX shared-memory zero-copy transport
- [ ] `LoaningPublisher` trait with pool-backed zero-copy writes

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
