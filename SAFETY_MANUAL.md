# Safety Manual — rust-DDS SEooC

**Document:** rust-DDS Safety Manual  
**Version:** 0.1.3  
**Standard:** ISO 26262 Part 8 (SEooC), IEC 61508-3, DO-178C DAL-A  
**Date:** 2026-06-19  
**Status:** Released  

---

## 1 Purpose and Scope

This safety manual describes how rust-DDS v0.1.x shall be integrated into a
safety-relevant system. rust-DDS is a **Safety Element out of Context (SEooC)**:
it has been developed to ISO 26262 ASIL-D, IEC 61508 SIL-3, and DO-178C DAL-A
objectives, but the actual ASIL/SIL/DAL achieved in a product depends on the
system-level integration and the assumptions listed in Section 3.

**Scope**: In-process mock transport (v0.1). The RTPS/UDP transport and
cryptographic authentication layers are not part of this scope and require
additional safety analysis before use in safety-critical products.

---

## 2 Applicable Standards and Levels

| Standard    | Level  | Scope                                |
|-------------|--------|--------------------------------------|
| ISO 26262   | ASIL-D | Automotive E/E; target for core APIs |
| IEC 61508   | SIL-3  | Industrial safety systems            |
| DO-178C     | DAL-A  | Airborne software                    |
| ISO/SAE 21434 | CAL-3 | Cybersecurity assurance level       |
| IEC 62443-4-1 | ML-3 | Software development security level |

Achieved integrity level depends on the system integrator's safety case and the
correct satisfaction of all Assumptions of Use (Section 3).

---

## 3 Assumptions of Use (AoU)

The following assumptions **must** be satisfied by the system integrator.
Failure to satisfy any AoU invalidates the safety claims of this element.

### AoU-001 — Trusted execution environment (ASIL-D, SIL-3)
rust-DDS v0.1 does not provide authentication or cryptographic protection.
**The host process must run in a trusted environment where access to the process
address space is restricted to authorised software only.**

### AoU-002 — Deadlines enforced by the application (ASIL-C)
The `QoS.deadline_ns` field carries a deadline value but rust-DDS does not
enforce it against a hardware watchdog. **The application must poll
`SampleReceiver::try_recv` or set an external timer to detect deadline misses
and react appropriately.**

### AoU-003 — Single tokio runtime (SIL-3)
rust-DDS assumes all async operations run within a single `tokio::Runtime`. Do
not share `MockParticipant` across multiple runtimes.

### AoU-004 — Payload validation is the caller's responsibility (ASIL-D)
rust-DDS transports payloads as opaque `Vec<u8>`. **The application is
responsible for validating the content, length, and encoding of payloads before
acting on them.** Using unvalidated payloads from untrusted sources violates
REQ-SEC-004 and REQ-SEC-011.

### AoU-005 — Topic names must not exceed 256 bytes (SIL-3)
Topic names are validated non-empty but not bounded by length in v0.1.
**The system integrator must enforce a maximum topic length of 256 bytes at the
application boundary** until REQ-MEM-006 is fully implemented in a future release.

### AoU-006 — No concurrent runtime shutdown (ASIL-D)
Calling `Participant::close` concurrently from multiple tasks is safe (idempotent),
but the `tokio::Runtime` must not be shut down while any outstanding `recv()` call
is awaited. **Ensure all receivers are dropped before shutting down the runtime.**

### AoU-007 — Block policy in v0.1 does not bound memory (SIL-2)
The `Block` back-pressure policy in v0.1 appends without capacity enforcement (see
REQ-MEM-003 Known Limitation). **Do not use `Block` policy in memory-constrained
environments; use `DropNewest` or `DropOldest` instead.**

### AoU-008 — Compiler and toolchain version (DO-178C DAL-A)
This element was qualified with `rustc 1.85+`. Using an older or non-qualified
toolchain removes the DO-178C DAL-A claim. **Use rustc ≥ 1.85 (stable) or the
exact nightly recorded in the CI matrix.**

---

## 4 Safety Goals Derived from HARA

The following safety goals are derived from the Hazard Analysis and Risk
Assessment (`.fusa-hara.json`). Each goal is mapped to requirements and is
monitored by CI.

| Goal ID | Description                                     | ASIL  | Requirements          |
|---------|-------------------------------------------------|-------|-----------------------|
| SG-001  | Prevent late/missing delivery under back-pressure | ASIL-B | REQ-HAZ-001, REQ-ASIL-008 |
| SG-002  | Prevent corrupt payload delivery                | ASIL-C | REQ-HAZ-002, REQ-SEC-011 |
| SG-003  | Prevent topic isolation failure                 | ASIL-B | REQ-HAZ-003, REQ-IEC-005 |
| SG-004  | Prevent cross-domain leakage                    | ASIL-B | REQ-HAZ-004, REQ-PART-001 |
| SG-005  | Prevent subscriber block after unsubscribe      | ASIL-B | REQ-HAZ-005, REQ-SUB-004 |
| SG-006  | Prevent write-after-close success               | ASIL-B | REQ-HAZ-007, REQ-PUB-004 |

---

## 5 Interface Catalog

See `BOUNDARY.md` for the graphical system boundary diagram.

### 5.1 Public API (Entry Points)

| Function / Trait Method          | Module              | Inputs Validated | ASIL |
|----------------------------------|---------------------|-----------------|------|
| `MockParticipant::new(Domain)`   | `mock/mod.rs`       | Domain [0,232]  | D    |
| `Participant::new_publisher(topic, QoS)` | `mock/mod.rs` | topic non-empty | D  |
| `Participant::new_subscriber(topic, QoS)` | `mock/mod.rs` | topic non-empty | D |
| `Publisher::write(Vec<u8>)`      | `mock/mod.rs`       | closed check    | D    |
| `Publisher::write_ctx(Context, Vec<u8>)` | `mock/mod.rs` | deadline check | D  |
| `Publisher::close()`             | `mock/mod.rs`       | idempotent      | D    |
| `Subscriber::unsubscribe()`      | `mock/mod.rs`       | —               | D    |
| `Subscriber::close()`            | `mock/mod.rs`       | idempotent      | D    |
| `SampleReceiver::recv()`         | `participant.rs`    | closed check    | D    |
| `SampleReceiver::try_recv()`     | `participant.rs`    | —               | D    |
| `Participant::close()`           | `mock/mod.rs`       | idempotent      | D    |
| `adapt(Arc<dyn Participant>)`    | `adapt.rs`          | —               | B    |

### 5.2 Output Types

| Type            | Module           | Safety-relevant Fields                     |
|-----------------|------------------|-------------------------------------------|
| `Sample`        | `types.rs`       | `topic`, `payload`, `sequence_number`, `writer_guid`, `timestamp` |
| `relay::Message`| `relay.rs`       | `topic`, `payload`, `meta` (BTreeMap, deterministic) |
| `Error`         | `error.rs`       | All variants; maps to RELAY sentinels via `as_relay()` |

### 5.3 Configuration Inputs

| Field              | Type                   | Validation         | Default        |
|--------------------|------------------------|--------------------|----------------|
| `QoS.reliability`  | `ReliabilityKind`      | enum               | BestEffort     |
| `QoS.durability`   | `DurabilityKind`       | enum               | Volatile       |
| `QoS.channel_depth`| `usize`                | clamped to 256 max | 1              |
| `QoS.back_pressure`| `BackPressurePolicy`   | enum               | DropNewest     |
| `Domain`           | `i32`                  | [0, 232]           | caller-supplied |

---

## 6 Integration Constraints

### 6.1 Memory

- Subscriber queues are bounded to `QoS.channel_depth` samples (≤ 256 in v0.1).
- Each `Sample` allocates one `Vec<u8>` for the payload. At `channel_depth = 256`
  and maximum payload size (64 KiB), worst-case allocation per subscriber is 16 MiB.
- Use `DropNewest` or `DropOldest` in memory-constrained environments.

### 6.2 Timing

- `SubInner::push` is O(1) under `DropNewest` and `DropOldest` (HAZ-001 mitigated).
- `try_recv` is non-blocking O(1).
- `recv` blocks asynchronously with no busy-wait (REQ-ASIL-010).
- `write` / `write_ctx` complete synchronously under DropNewest/DropOldest.

### 6.3 Threading

- All types implement `Send + Sync` (REQ-CONC-001).
- Internal state is protected by `std::sync::Mutex` and `AtomicBool`.
- Deadlock freedom guaranteed by single-lock protocol: no two locks held simultaneously
  on any code path (REQ-CONC-003).

### 6.4 Platform Requirements

- **OS**: Any OS supporting the Rust standard library.
- **Rust**: `rustc ≥ 1.85` (stable channel).
- **Async runtime**: `tokio` (async-ready; multi-threaded or current-thread runtime).
- **Build**: Standard `cargo build`; no external C/C++ dependencies.

---

## 7 Known Limitations (v0.1)

| Ref     | Description                                                   | Planned Fix |
|---------|---------------------------------------------------------------|-------------|
| LIM-001 | No network transport — in-process mock only                   | v0.2 RTPS/UDP |
| LIM-002 | No cryptographic authentication                               | v0.5 DDS-Security |
| LIM-003 | Block policy appends without capacity enforcement (REQ-MEM-003) | v0.2 |
| LIM-004 | Payload size not checked in mock transport (REQ-SEC-002)      | v0.2 RTPS |
| LIM-005 | No hardware watchdog integration for deadline monitoring      | v0.3 |
| LIM-006 | `convert` CLI command not implemented                         | v0.2 |
| LIM-007 | QoS missing 5 canonical fields (max_sample_size, transport_priority, latency_budget, lifespan, publish_period) | v0.2 |

---

## 8 Traceability Summary

| Standard    | Requirement Count | Coverage |
|-------------|-------------------|----------|
| ISO 26262 (ASIL) | 10 + 6 HAZ | 100% //fusa:req + //fusa:test |
| IEC 61508 (IEC)  | 15           | 100% //fusa:req + //fusa:test |
| DO-178C (DO)     | 14           | 100% //fusa:req + //fusa:test |
| Cybersecurity (SEC) | 15         | 100% //fusa:req + //fusa:test |
| Concurrency (CONC) | 4          | 100% //fusa:req + //fusa:test |
| Integrity (INT) | 3             | 100% //fusa:req + //fusa:test |
| Memory Safety (MEM) | 6         | 100% //fusa:req + //fusa:test |
| Real-time (RT) | 5              | 100% //fusa:req + //fusa:test |
| Config Mgmt (CM) | 3            | 100% //fusa:req + //fusa:test |
| **Total** | **115**          | **100%** |

All requirements traced bidirectionally: req → implementation (//fusa:req) →
test (//fusa:test). Enforced by the `fusa-trace` CI job on every PR.

---

## 9 Evidence Package

| Artifact                  | Description                                        |
|---------------------------|----------------------------------------------------|
| `requirements.json`       | 115 requirements, bidirectionally traced           |
| `.fusa-hara.json`         | HARA: 10 DDS-specific hazards (HAZ-001..010)       |
| `fmea.json` / `fmea.csv`  | Design FMEA: 40 failure modes across all modules   |
| `tara.json` / `tara.md`   | TARA: 8 DDS-specific STRIDE threats (ISO/SAE 21434)|
| `sbom.json`               | Software Bill of Materials (CycloneDX format)      |
| `provenance.json`         | Build provenance and toolchain record              |
| `qualify-report.json`     | Tool qualification report (16+ cases, all PASS)   |
| `vuln.json`               | Vulnerability scan results                         |
| `artifact-manifest.json`  | Manifest of all evidence artifacts with SHA-256    |
| `SAFETY_PLAN.md`          | Development safety plan and process description    |
| `SECURITY.md`             | Security policy and vulnerability reporting        |
| `BOUNDARY.md`             | System boundary diagram and trust zone map         |

---

## 10 Change Control

All changes to safety-relevant code must follow the process in `SAFETY_PLAN.md`
Section "Change Control". Key steps:

1. Create feature branch `feat/<name>` from `main`
2. Add new requirements to `requirements.json` (IDs never reused)
3. Add `//fusa:req` and `//fusa:test` annotations for every new requirement
4. Update FMEA for any new failure modes
5. Pass all 19 CI jobs including `fusa-trace`, `relay-conform`, `relay-interop`
6. Commit with DCO sign-off (`Signed-off-by: Name <email>`)
7. Merge via pull request to `main`
8. Tag as semantic version
