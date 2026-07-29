# Changelog

All notable changes to `rust-dds` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow Semantic Versioning strictly — pre-1.0
`0.x` releases may include breaking changes in a minor version bump, per
[Cargo's SemVer compatibility rules for `0.x`](https://doc.rust-lang.org/cargo/reference/semver.html).
Each entry below was backfilled from the repository's tag and PR history;
going forward, add an entry here as part of the PR that lands each release.

## [Unreleased]

## [0.28.0] — 2026-07-27

- `MetricsProvider` trait (`observability::metrics`).

## [0.27.0] — 2026-07-27

- `HealthProvider` trait (`observability::health`).

## [0.26.0] — 2026-07-27

- HMAC-SHA-256 discovery authentication (`security::discovery`).

## [0.25.0] — 2026-07-27

- Anti-replay guard (`security::replay::ReplayGuard`).

## [0.24.0] — 2026-07-27

- Topic ACL (`security::acl::AccessPolicy`).

## [0.23.0] — 2026-07-27

- AES-256-GCM encryption plugin (`security::aes_gcm::AesGcmPlugin`).

## [0.22.0] — 2026-07-27

- HMAC-SHA-256 integrity plugin (`security::hmac::HmacPlugin`).

## [0.21.0] — 2026-07-27

- Pluggable payload security trait (`SecurityPlugin`).

## [0.20.0] — 2026-07-27

- Shared-memory transport (`shmem::ShmemParticipant` + `LoaningPublisher`).

## [0.19.0] — 2026-07-27

- Deadline QoS subscriber enforcement with callback.

## [0.18.0] — 2026-07-27

- CDR/XCDR1 general-purpose payload codec.

## [0.17.0] — 2026-07-27

- IPv4 and IPv6 multicast support for `RtpsUdpParticipant`.

## [0.16.0] — 2026-07-27

- BestEffort delivery over UDP multicast and unicast.

## [0.15.0] — 2026-07-27

- SPDP static unicast peer discovery.

## [0.14.0] — 2026-07-27

- Live CycloneDDS-peer wire interop harness (RTPS interop testing, deliverable 3/3).

## [0.13.0] — 2026-07-27

- Wired `RtpsParticipant` into the public `Participant` API.

## [0.12.0] — 2026-07-27

- RTPS interop testing infrastructure (live two-process harness + pcap fixtures).

## [0.11.0] — 2026-07-27

- RTPS Tier-1 sub-phase 9 — TransientLocal persistence + topic wildcard matching.

## [0.10.0] — 2026-07-27

- RTPS Tier-1 sub-phase 8 — Fragmentation (DATA_FRAG).

## [0.9.0] — 2026-07-27

- RTPS Tier-1 sub-phase 7 — Reliable QoS (HEARTBEAT/ACKNACK).

## [0.8.0] — 2026-07-27

- RTPS Tier-1 sub-phase 6 — BestEffort data path.

## [0.7.0] — 2026-07-27

- RTPS Tier-1 sub-phase 5 — SEDP endpoint discovery.

## [0.6.0] — 2026-07-27

- RTPS Tier-1 sub-phase 4 — SPDP participant discovery.

## [0.5.0] — 2026-07-27

- RTPS Tier-1 sub-phase 3 — UDP transport.

## [0.4.0] — 2026-07-27

- RTPS Tier-1 sub-phase 2 — minimal wire-level CDR.

## [0.3.0] — 2026-07-27

- RTPS Tier-1 sub-phase 1 — wire framing & identifiers.

## [0.2.0] — 2026-07-27

- §8.2/§14/§15.2 QoS conformance, `capabilities.interfaces` fix, doc version drift fix.

## [0.1.5] — 2026-06-19

- Version bump only.

## [0.1.4] — 2026-06-19

- Version bump only.

## [0.1.3] — 2026-06-19

- Completed §20 full-lifecycle CI — `qualify`, `vuln`, `interop` gates + §20.4 evidence.

## [0.1.2] — 2026-06-19

- Resolved two RELAY v1.10 spec failures (§6.4, §10.5 r3) and `meta` key ordering.

## [0.1.1] — 2026-06-19

- RELAY v1.10 §12 conformance and §20 CI gates.

## [0.1.0] — 2026-06-19

- Initial release: ASIL/IEC/DO-178C/cybersecurity FuSa evidence — 88 requirements
  with 100% bidirectional traceability.
- `Participant`, `Publisher`, `Subscriber` traits; `MockParticipant` in-process
  broker; TransientLocal, back-pressure, sequence numbers, writer GUID;
  `adapt()` RELAY Node adapter; CLI binary.

[Unreleased]: https://github.com/SoundMatt/rust-DDS/compare/v0.28.0...HEAD
[0.28.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SoundMatt/rust-DDS/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/SoundMatt/rust-DDS/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/SoundMatt/rust-DDS/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/SoundMatt/rust-DDS/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/SoundMatt/rust-DDS/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/SoundMatt/rust-DDS/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/SoundMatt/rust-DDS/releases/tag/v0.1.0
