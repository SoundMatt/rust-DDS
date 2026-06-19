# Threat Analysis and Risk Assessment (TARA) — rust-DDS

Standard: ISO/SAE 21434 | Generated: 2026-06-19 | Tool: rust-FuSa 0.2.8

## Summary

| Rating | Count |
|--------|-------|
| HIGH   | 3     |
| MEDIUM | 4     |
| LOW    | 1     |
| **Total** | **8** |

## Threats

### TARA-DDS-001 — Spoofed Publisher GUID (HIGH)

**STRIDE:** Spoofing | **CWE:** CWE-346  
**Threat:** Attacker constructs a sample with a `writer_guid` matching a trusted publisher, causing the subscriber to accept data from an untrusted source.  
**Mitigation:** `writer_guid` is a 16-byte token derived from domain prefix + AtomicU64 counter (REQ-SEC-007, REQ-SEC-008). Future RTPS transport must authenticate GUID origin via DDS-Security. Replay protection deferred to RTPS milestone.

---

### TARA-DDS-002 — Topic Name Injection (MEDIUM)

**STRIDE:** Tampering | **CWE:** CWE-20  
**Threat:** Caller passes a crafted topic string containing path separators or control characters, causing broker misrouting or log injection.  
**Mitigation:** Topic validated non-empty (REQ-SEC-001, REQ-SEC-013); exact `HashMap` key match prevents glob/wildcard expansion. Future transport should add character allowlist validation.

---

### TARA-DDS-003 — Payload Flooding DoS (HIGH)

**STRIDE:** Denial of Service | **CWE:** CWE-400  
**Threat:** High-rate publisher writes arbitrarily large payloads, exhausting subscriber queue memory and degrading real-time performance.  
**Mitigation:** Back-pressure policy (DropNewest/DropOldest/Block) bounds queue depth (REQ-ASIL-008). Payload size limit (REQ-SEC-002 `PayloadTooLarge`) deferred to RTPS transport milestone.

---

### TARA-DDS-004 — Sample Replay Attack (MEDIUM)

**STRIDE:** Spoofing | **CWE:** CWE-294  
**Threat:** Attacker captures a valid `relay::Message` and replays it to inject stale or duplicate data into a safety-critical subscriber.  
**Mitigation:** Monotonic sequence numbers (REQ-ASIL-005, REQ-SEC-007) enable duplicate detection; timestamp present in every `Message`. Application layer must enforce freshness window. DDS-Security replay protection deferred to RTPS milestone.

---

### TARA-DDS-005 — Cross-Domain Data Exfiltration (HIGH)

**STRIDE:** Elevation of Privilege | **CWE:** CWE-284  
**Threat:** Participant on domain D subscribes to topics intended for domain D+1 due to missing access control between domains.  
**Mitigation:** Each `MockParticipant` holds an isolated `Broker`; domains are fully partitioned (REQ-PART-001, HAZ-004). Future RTPS must enforce domain ID in UDP multicast group selection.

---

### TARA-DDS-006 — Race on Subscriber Close (LOW)

**STRIDE:** Tampering | **CWE:** CWE-362  
**Threat:** Concurrent `close()` and `recv()` calls could read from a partially-freed `SubInner`, producing undefined output.  
**Mitigation:** `SubInner` uses `AtomicBool` + `Notify` for lock-free close signalling (REQ-CONC-001, REQ-IEC-006); `Mutex` protects the sample queue. No unsafe code (REQ-ASIL-002). Formally verified by `cargo test` concurrency tests (REQ-DO-008).

---

### TARA-DDS-007 — Deserialisation of External Payload (MEDIUM)

**STRIDE:** Tampering | **CWE:** CWE-502  
**Threat:** Deserialisation of external DDS payload causes memory safety violation or logic error in application layer.  
**Mitigation:** rust-DDS treats payloads as opaque `Vec<u8>`; no in-library deserialisation of application-level content. Application owns decoding and must validate (REQ-SEC-004, REQ-SEC-011).

---

### TARA-DDS-008 — Unbounded Publisher Creation (MEDIUM)

**STRIDE:** Denial of Service | **CWE:** CWE-770  
**Threat:** Caller creates thousands of publishers without closing them, filling the Mutex-protected `HashMap` and exhausting memory.  
**Mitigation:** Publisher lifecycle managed by caller; `close()` removes publisher state. Future implementation should add per-participant publisher limit. Tracked as resource exhaustion risk.
