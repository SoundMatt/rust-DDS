# Roadmap

## Released — v0.1 — Foundation

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
- [x] `RELAY_SPEC_VERSION = "1.7"`
- [x] CLI binary: `version`, `capabilities`, `status`
- [x] 37 passing tests; CI on ubuntu/macos/windows × Rust 1.75/stable
- [x] DCO enforced in CI

## Planned — v0.2 — RTPS Transport

- [ ] Pure-Rust RTPS/UDP transport (`rtps::RtpsParticipant`)
- [ ] CDR/XCDR1 serialization for RTPS wire format
- [ ] SPDP participant discovery (multicast + unicast)
- [ ] SEDP endpoint announcement
- [ ] BestEffort delivery over UDP multicast and unicast
- [ ] IPv4 and IPv6 multicast support

## Planned — v0.3 — Reliable QoS

- [ ] Reliable delivery with HEARTBEAT / ACKNACK retransmission
- [ ] TransientLocal durability over RTPS (SEDP history cache)
- [ ] Fragment support for large payloads (DATA_FRAG)
- [ ] Deadline QoS subscriber enforcement with callback

## Planned — v0.4 — Shared-Memory Transport

- [ ] `shmem::ShmemParticipant` — POSIX shared-memory zero-copy transport
- [ ] `LoaningPublisher` trait with pool-backed zero-copy writes

## Planned — v0.5 — Security

- [ ] Pluggable payload security trait (`SecurityPlugin`)
- [ ] HMAC-SHA-256 integrity plugin
- [ ] AES-256-GCM encryption plugin
- [ ] Topic ACL (`AccessPolicy`)
- [ ] Anti-replay guard (`ReplayGuard`)
- [ ] HMAC-SHA-256 discovery authentication

## Planned — v0.6 — Observability

- [ ] `HealthProvider` trait
- [ ] `MetricsProvider` trait (per-topic write/deliver/drop counters)
- [ ] `Drainer` / close-with-drain
- [ ] Structured logging via `tracing` crate

## Planned — v0.7 — Developer Experience

- [ ] `testutil` — `NewParticipant`, `assert_sample`, `TopicRecorder`, `burst_publish`
- [ ] CLI `pub`, `sub`, `discover` subcommands
- [ ] `WaitSet` — multiplex over multiple subscribers

## Planned — v0.8 — Advanced Features

- [ ] Typed generics `TypedPublisher<T>` / `TypedSubscriber<T>` with `JsonCodec<T>` and `ProtoCodec<T>`
- [ ] Topic recording (JSONL) and deterministic replay
- [ ] Fault injection wrapper
- [ ] E2E protection header (CRC-16, sequence counter, freshness)

## Planned — v0.9 — Enterprise

- [ ] X.509/ECDSA CertPlugin
- [ ] Domain bridge (in-process participant-to-participant forwarding)
- [ ] WAN bridge (TCP, length-framed JSON)
- [ ] HTTP admin API
- [ ] Managed service lifecycle wrappers
