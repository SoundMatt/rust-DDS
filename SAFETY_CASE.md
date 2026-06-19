# Safety Case — rust-DDS SEooC

**Document:** rust-DDS Safety Case  
**Version:** 0.1.3  
**Date:** 2026-06-19  
**Format:** Structured prose argument (text-based GSN)  

---

## G1 — Top-Level Safety Claim

> **rust-DDS v0.1.x is acceptably safe for use as a contributing SEooC element in systems up to ASIL-B (decomposed), SIL-2, or DAL-C, provided all Assumptions of Use in SAFETY_MANUAL.md §3 are satisfied by the system integrator.**

### Context C1 — Scope

This claim applies to:
- The in-process mock transport only (`MockParticipant`)
- Library code in `src/` (types, participant, mock, relay, adapt, error)
- The CLI binary in `src/bin/main.rs` for conformance reporting
- rustc ≥ 1.85 stable toolchain on Linux, macOS, or Windows

This claim does **not** cover:
- Network transport (RTPS/UDP — planned v0.2)
- Cryptographic authentication (planned v0.5)
- The calling application's use of delivered payloads

### Context C2 — Claimed vs Target Level

| Metric | Claimed (achieved) | Target (aspirational) | Gap |
|--------|-------------------|-----------------------|-----|
| ISO 26262 | ASIL-B (decomposed) | ASIL-D | Independent V&V, tool qual |
| IEC 61508 | SIL-2 | SIL-3 | Independent V&V |
| DO-178C | DAL-C | DAL-A | Tool qual, multi-level reqs, MC/DC tool |
| ISO/SAE 21434 | CAL-3 (process) | CAL-4 | Independent penetration test |

---

## S1 — Argument Strategy

The claim G1 is supported by four parallel sub-arguments:

1. **S1a — Design correctness**: the design prevents the identified hazards
2. **S1b — Implementation correctness**: the code faithfully realises the design
3. **S1c — Verification completeness**: the test suite detects deviations
4. **S1d — Process integrity**: the development process was followed correctly

---

## S1a — Design Correctness

### G1a — The design prevents the identified safety hazards

**Strategy:** Show that every hazard in `.fusa-hara.json` has a corresponding design mitigation traced to a requirement.

| Hazard | ASIL | Mitigation in Design | Requirement |
|--------|------|---------------------|-------------|
| HAZ-001: Late delivery under back-pressure | B | DropNewest/DropOldest/Block policy applied at push() | REQ-HAZ-001, REQ-ASIL-008 |
| HAZ-002: Corrupt payload delivery | C | Payloads are opaque `Vec<u8>`; safe Rust clone is byte-identical | REQ-HAZ-002, REQ-SEC-011 |
| HAZ-003: Topic isolation failure | B | Broker HashMap uses exact string match; no wildcard routing | REQ-HAZ-003, REQ-IEC-005 |
| HAZ-004: Cross-domain leakage | B | Each `MockParticipant` owns its `Arc<Broker>`; no shared state | REQ-HAZ-004, REQ-PART-001 |
| HAZ-005: Subscriber block after unsubscribe | B | `unsubscribe()` calls `close()` per §6.4; Notify wakes recv() | REQ-HAZ-005, REQ-SUB-004 |
| HAZ-006: Sequence number wraparound | QM | u64 counter; wraparound at 1.8×10¹⁹ writes; accepted | REQ-ASIL-005 |
| HAZ-007: Write-after-close success | B | `AtomicBool` closed flag checked at top of every write path | REQ-HAZ-007, REQ-PUB-004 |
| HAZ-008: GUID collision | B | AtomicU64 fetch_add per participant; domain in byte 0 | REQ-SEC-007, REQ-SEC-008 |
| HAZ-009: Topic name injection | A | Empty topic rejected; `TopicEmpty` returned | REQ-SEC-001, REQ-SEC-013 |
| HAZ-010: Payload size flooding | C | Back-pressure bounds queue; mock has no size limit (AoU-007) | REQ-MEM-002 |

**Evidence:** `.fusa-hara.json`, `requirements.json`, `BOUNDARY.md §4`

**Assumption A1:** The system integrator enforces AoU-007 (Block policy not used in memory-constrained environments) and AoU-004 (payload validation at application boundary).

---

## S1b — Implementation Correctness

### G1b — The implementation faithfully realises the design

**Strategy:** Compiler guarantees + code review evidence + no unsafe.

#### G1b.1 — Memory safety
Rust's type system and borrow checker enforce memory safety statically. No `unsafe` blocks exist (REQ-ASIL-002, REQ-MEM-001). Verified by compiler on every build and by `cargo clippy -D warnings` in CI.

**Evidence:** Absence of `unsafe` keyword in `src/`; confirmed by `grep -r unsafe src/` returning empty.

#### G1b.2 — No undefined behaviour
All integer arithmetic uses `fetch_add` (wrapping by definition for u64), checked domain validation, and safe slice operations. No transmutes, raw pointers, or union access.

**Evidence:** `cargo clippy`, `rsfusa check` (0 errors), lint CI job.

#### G1b.3 — Concurrent correctness
All shared state is protected by `std::sync::Mutex` or `AtomicBool` with `SeqCst` ordering. The single-lock protocol (REQ-CONC-003) prevents deadlock. `AtomicBool::compare_exchange` ensures at-most-once close semantics (REQ-ASIL-007, REQ-IEC-010).

**Evidence:** `src/participant.rs` SubInner; `concurrent_publish_subscribe_no_deadlock` test; `traits_are_send_sync` test.

#### G1b.4 — Lifecycle correctness
Closed state is irreversible (REQ-INT-003). write-after-close, new-publisher-after-close, and new-subscriber-after-close all return `Error::Closed` (REQ-PUB-004, REQ-PART-006). Idempotent close verified by test.

**Residual concern:** Publisher closed flag uses `store(true)` not `compare_exchange` — concurrent close from two tasks is safe (both set true) but not strictly at-most-once. Acceptable at ASIL-B; ASIL-D would require `compare_exchange`.

---

## S1c — Verification Completeness

### G1c — The test suite detects deviations from the design

**Strategy:** Show coverage across four dimensions.

#### G1c.1 — Requirement traceability
All 115 requirements have at least one `//fusa:req` implementation annotation and at least one `//fusa:test` test annotation. Enforced by `fusa-trace` CI gate on every PR. Orphan tags (referencing non-existent requirement IDs) are also blocked.

**Evidence:** `fusa-trace` CI job; `requirements.json`.

#### G1c.2 — FMEA failure mode coverage
All 40 failure modes in `fmea.json` are linked to requirements, and every linked requirement has at least one test. No FMEA entry has RPN > 100 (see `fmea.json` `rpn` field); all high-severity items are caught by dedicated tests.

**Evidence:** `fmea.json`; `//fusa:test` annotations on relevant tests.

#### G1c.3 — Structural coverage
Statement and branch coverage is measured by `cargo-tarpaulin` in CI (coverage job). Branch coverage is reported but **MC/DC (Modified Condition/Decision Coverage) is not measured** — tarpaulin reports branch pairs, not independent condition influence. This is the primary gap between claimed DAL-C and target DAL-A.

**Evidence:** Coverage CI job, `coverage/cobertura.xml` artifact.

**Residual concern (GAP-001):** True MC/DC measurement requires a dedicated tool (LDRA, VectorCAST, or LLVM-based MC/DC). Current coverage satisfies DAL-C / ASIL-B but not DAL-A / ASIL-D.

#### G1c.4 — Robustness and boundary coverage
All external entry points are exercised with abnormal inputs by `robustness_all_boundary_inputs` (REQ-DO-011) and dedicated boundary tests (domain 0, 232, -1, 233; empty topic; write/recv after close).

**Evidence:** `robustness_all_boundary_inputs`, `domain_out_of_range`, `empty_topic_rejected`, `write_after_close_returns_closed`, `closed_state_is_irreversible` tests.

---

## S1d — Process Integrity

### G1d — The development process was followed correctly

#### G1d.1 — Configuration management
Every commit to `main` carries a DCO `Signed-off-by` enforced by the `dco` CI job (REQ-CM-001). Releases are tagged with semantic versions (REQ-CM-002). SBOM generated per release (REQ-CM-003).

**Evidence:** `dco` CI job; git tag history; `sbom.json`.

#### G1d.2 — Coding standard
`cargo fmt` and `cargo clippy -D warnings` are enforced on every PR by the `lint` CI job (REQ-IEC-011). No deviations recorded.

**Evidence:** `lint` CI job pass history.

#### G1d.3 — Tool qualification
`rsfusa qualify` runs 16 qualification test cases (FUSA001–LINT004) and all pass (see `qualify-report.json`). This is **self-qualification by the tool vendor**, not independent third-party qualification per DO-330 or ISO 26262 Part 8 §11.

**Residual concern (GAP-002):** Independent tool qualification is required for ASIL-D / DAL-A claims. The rustc toolchain is not formally qualified under DO-330. See FuSaOps issue for recommended action.

#### G1d.4 — Independence
**GAP-003 (critical for ASIL-D):** The developer who wrote the implementation also wrote the tests and the safety evidence. ISO 26262 ASIL-D and DO-178C DAL-A require independent V&V — a separate individual or organisation reviewing and testing the software without access to the implementation author's reasoning. This independence does not currently exist.

**Impact:** The absence of independent V&V is the single largest gap between the claimed ASIL-B and the target ASIL-D.

---

## Residual Gaps Summary

| Gap ID | Description | Impact | Needed for |
|--------|------------|--------|-----------|
| GAP-001 | MC/DC not measured (tarpaulin = branch only) | Cannot claim DO-178C DAL-A structural coverage | DAL-A, ASIL-D |
| GAP-002 | Tool qualification not independent (rustc, tarpaulin, rsfusa) | Cannot claim tool-qualified development environment | DAL-A, ASIL-D, SIL-3 |
| GAP-003 | No independent V&V | Cannot claim ASIL-D or DAL-A verification | ASIL-D, DAL-A |
| GAP-004 | Block back-pressure not capacity-bounded (REQ-MEM-003) | Potential memory exhaustion if Block policy used | ASIL-C+ |
| GAP-005 | Publisher close uses `store` not `compare_exchange` | At-most-once close not strictly enforced under concurrent access | ASIL-D |
| GAP-006 | HARA not produced by independent multi-engineer workshop | ISO 26262 §7.4 requires team review of hazard completeness | ASIL-D |
| GAP-007 | Single-level requirements (no HLR/LLR decomposition) | DO-178C requires hierarchical req breakdown | DAL-A |

---

## Conclusion

rust-DDS v0.1.x satisfies claim **G1** at ASIL-B / SIL-2 / DAL-C levels.

To advance to ASIL-D / SIL-3 / DAL-A, the gaps above must be closed. The three highest-priority actions are:

1. **Engage an independent V&V body** to review the safety case and re-execute the test suite (closes GAP-003)
2. **Add true MC/DC coverage measurement** using a DO-178C-qualified coverage tool (closes GAP-001)
3. **Qualify the development toolchain** under DO-330 / ISO 26262 Part 8 §11 (closes GAP-002)

These actions are tracked in SoundMatt/FuSaOps for cross-repo coordination.
