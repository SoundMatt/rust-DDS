# Safety Plan — rust-DDS

## Scope

This document covers functional safety for `rust-dds` v0.1 (in-process mock
transport). It applies to use cases where rust-DDS is a **SEooC** (Safety Element
out of Context) integrated into a safety-relevant system.

## Applicable Standards

| Standard | Level | Scope |
|----------|-------|-------|
| ISO 26262 | ASIL-D (target) | Automotive E/E systems |
| IEC 61508 | SIL-3 (target) | Industrial safety systems |
| DO-178C | DAL-A (target) | Airborne software |

## Safety Requirements

All functional safety requirements are recorded in `requirements.json` with the
following categories and IDs (115 total):

| Category | IDs | Standard |
|----------|-----|----------|
| ASIL requirements | REQ-ASIL-001 – REQ-ASIL-010 | ISO 26262 |
| HAZ-derived safety goals | REQ-HAZ-001, 002, 003, 004, 005, 007 | ISO 26262 (HARA-derived) |
| IEC requirements | REQ-IEC-001 – REQ-IEC-015 | IEC 61508 SIL-3 |
| DO-178C requirements | REQ-DO-001 – REQ-DO-014 | DO-178C DAL-A |
| Cybersecurity | REQ-SEC-001 – REQ-SEC-015 | ISO/SAE 21434 CAL-3 |
| Memory safety | REQ-MEM-001 – REQ-MEM-006 | |
| Real-time | REQ-RT-001 – REQ-RT-005 | |
| Integrity | REQ-INT-001 – REQ-INT-003 | |
| Concurrency | REQ-CONC-001 – REQ-CONC-004 | |
| Configuration management | REQ-CM-001 – REQ-CM-003 | |

## Traceability

Requirements traceability is enforced bidirectionally:

- **Implementation → Requirement**: every safety-relevant code block carries a
  `//fusa:req REQ-XXX-NNN` annotation.
- **Test → Requirement**: every test covering a safety requirement carries a
  `//fusa:test REQ-XXX-NNN` annotation.
- **CI gate**: the `fusa-trace` CI job verifies that every requirement ID in
  `requirements.json` appears in at least one `//fusa:req` and at least one
  `//fusa:test` annotation. Orphan tags (referencing non-existent IDs) are also
  caught (REQ-IEC-003, REQ-IEC-004, REQ-DO-001).

## Key Safety Properties

### Fault Detection and Propagation (REQ-ASIL-001, REQ-IEC-002)

All errors are returned via `Result<T, Error>`. No safety-relevant path panics or
silently discards errors. The `Error::as_relay()` method maps DDS-specific errors
to mandatory RELAY sentinels.

### No Undefined Behavior (REQ-ASIL-002, REQ-MEM-001)

No `unsafe` blocks exist. All memory operations use safe Rust abstractions. The
Rust type system and borrow checker enforce memory and thread safety statically.

### Atomic State Machine (REQ-ASIL-007, REQ-IEC-010)

Participant and Publisher closed state is tracked with `AtomicBool::compare_exchange`,
ensuring at-most-once close semantics without data races.

### Bounded Memory (REQ-MEM-002, REQ-SEC-009)

Subscriber queues are bounded to `channel_depth` entries. Back-pressure policies
(DropNewest, DropOldest, Block) prevent unbounded growth.

### Input Validation (REQ-ASIL-006, REQ-PART-001)

- Domain values validated to [0, 232] before participant creation
- Topic names validated non-empty before publisher/subscriber creation
- GUID hex encoding validated on deserialization

### Concurrent Safety (REQ-CONC-001, REQ-IEC-006)

All shared state is protected by `std::sync::Mutex` or `tokio::sync::Mutex`.
`AtomicBool` is used for closed flags. All trait implementations are `Send + Sync`.

### Real-time Constraints (REQ-RT-001, REQ-RT-002)

- `push()` is O(1) under DropNewest and DropOldest policies
- `try_recv()` is non-blocking
- No `thread::sleep` or spin-loops in any operation path

## Testing Strategy

### Unit Tests

All 14 mock participant tests and tests across all modules carry `//fusa:test`
annotations tracing to specific requirements.

### Boundary Tests (REQ-DO-006)

Boundary values tested explicitly:
- `Domain(0)` and `Domain(232)` (valid boundary)
- `Domain(-1)` and `Domain(233)` (invalid boundary)
- Empty topic string

### Golden Vector Tests (REQ-DO-007)

`sample_to_message_golden_vector` verifies the Sample-to-Message conversion with
hardcoded expected hex bytes for the writer_guid.

### Concurrent Tests (REQ-DO-008)

`multiple_subscribers_receive_same_sample` verifies broadcast delivery to concurrent
subscribers.

## Safety Documentation

| Document | Description |
|----------|-------------|
| `SAFETY_PLAN.md` | This file — development safety plan and process |
| `SAFETY_MANUAL.md` | Integrator-facing safety manual (SEooC, AoU, interface catalog) |
| `BOUNDARY.md` | System boundary diagram, trust zones, data flows, partitioning |
| `SECURITY.md` | Security policy and vulnerability reporting |

## CI Quality Gates

| Job | Purpose |
|-----|---------|
| `test` | Multi-platform × multi-toolchain test suite (6× matrix) |
| `release-build` | Catch release-mode issues (optimizer, overflow) |
| `lint` | `cargo fmt`, `cargo clippy -D warnings`, dead code |
| `security-audit` | `cargo audit` + `cargo deny` — blocks on RUSTSEC advisories |
| `coverage` | `cargo tarpaulin` structural coverage report (REQ-DO-013) |
| `relay-conform` | `relay conform --strict` §12.1/12.2/12.3 schema gates |
| `relay-interop` | `relay interop` behavioural conformance gate |
| `rsfusa-check` | `rsfusa check` — 0 ERROR findings required |
| `rsfusa-qualify` | `rsfusa qualify` — 16/16 qualification cases PASS |
| `rsfusa-vuln` | `rsfusa vuln` — vulnerability scan |
| `rsfusa-cyber` | `rsfusa cyber` — cybersecurity analysis |
| `fusa-trace` | Bidirectional traceability gate (all 115 reqs → code → tests) |
| `safety-artifacts` | Verifies 17 evidence files present + valid JSON + content checks |
| `dco` | Developer Certificate of Origin on all commits |

## Known Limitations (v0.1)

1. **No network transport** — v0.1 is in-process mock only. RTPS/UDP transport
   (v0.2) will require additional safety analysis for network-facing attack surfaces.
2. **No cryptographic authentication** — planned for v0.5. Until then, the library
   assumes a trusted execution environment.
3. **No watchdog integration** — real-time deadline monitoring (REQ-ASIL-010) is
   available via `QoS.deadline_ns` but does not automatically notify a system watchdog.
4. **Block back-pressure** — the Block policy currently appends without waiting for
   capacity; true async backpressure is planned (REQ-MEM-003).

## Change Control

All changes must:
1. Create a `feat/<name>` branch
2. Update `requirements.json` for any new requirements (IDs never reused)
3. Add `//fusa:req` and `//fusa:test` annotations for new requirements
4. Pass all CI quality gates including `fusa-trace`
5. Be committed with DCO sign-off (`Signed-off-by:`)
6. Be merged via pull request to `main`
