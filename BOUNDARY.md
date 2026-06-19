# System Boundary Diagram — rust-DDS

**Document:** rust-DDS System Boundary  
**Version:** 0.1.3  
**Standard:** ISO 26262 (SEooC boundary), IEC 61508, DO-178C  
**Date:** 2026-06-19  

---

## 1 System Context (C4 Level 1)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HOST PROCESS (trusted)                            │
│                                                                             │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                        Application Layer                             │  │
│   │   (caller is responsible for payload validation, deadline tracking,  │  │
│   │    replay detection, and access control — see SAFETY_MANUAL §3)      │  │
│   └────────────┬──────────────────────────────────────────┬─────────────┘  │
│                │ Participant trait API (AoU-004)           │ relay::Node API │
│                ▼                                           ▼                │
│   ┌────────────────────────────────┐   ┌─────────────────────────────────┐ │
│   │        rust-DDS v0.1           │   │        RELAY adapter            │ │
│   │  ┌────────────────────────┐   │   │        (adapt.rs)               │ │
│   │  │   MockParticipant      │   │   │                                 │ │
│   │  │   (mock/mod.rs)        │   │   │  relay::Node::send()            │ │
│   │  │                        │   │   │  relay::Node::subscribe()       │ │
│   │  │  Broker (in-process)   │   │   └─────────────┬───────────────────┘ │
│   │  │  ┌──────────────────┐  │   │                 │                     │
│   │  │  │ topic→[SubInner] │  │   │                 │ (wraps Participant)  │
│   │  │  │ HashMap          │  │   └─────────────────┘                     │
│   │  │  │ (Mutex-protected)│  │                                           │
│   │  │  └──────────────────┘  │                                           │
│   │  │  publish counter       │                                           │
│   │  │  (AtomicU64)           │                                           │
│   │  └────────────────────────┘                                           │
│   │                                                                        │
│   │  ┌────────────────────────┐   ┌────────────────────────┐              │
│   │  │  SubInner              │   │  SampleReceiver         │              │
│   │  │  (participant.rs)      │──▶│  (participant.rs)       │──▶ App       │
│   │  │  Mutex<VecDeque>       │   │  recv() / try_recv()   │              │
│   │  │  AtomicBool (closed)   │   └────────────────────────┘              │
│   │  │  AtomicBool (unsub)    │                                           │
│   │  │  Notify                │                                           │
│   │  └────────────────────────┘                                           │
│   └────────────────────────────────────────────────────────────────────────┘
│                                                                             │
│   PLATFORM DEPENDENCIES (all trusted within process boundary):              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐ │
│   │ tokio runtime│  │ std::sync    │  │ serde_json   │  │ rustc 1.85+   │ │
│   │ (async I/O)  │  │ (Mutex,Atomic│  │ (JSON encode)│  │ (safe Rust)   │ │
│   └──────────────┘  └──────────────┘  └──────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
        │
        │  (v0.1 mock only — no network I/O crosses this boundary)
        ▼
 ╔═══════════════════════════════════════════════════════╗
 ║          EXTERNAL (OUT OF SCOPE, v0.1)                ║
 ║  Network / RTPS / UDP / Shared Memory / DDS-Security  ║
 ║  (planned v0.2+ — requires new safety analysis)       ║
 ╚═══════════════════════════════════════════════════════╝
```

---

## 2 Trust Zone Map

| Zone | Name | Trust Level | Description |
|------|------|-------------|-------------|
| Z1 | Application | TRUSTED | The calling application; must satisfy AoU-001..008 |
| Z2 | rust-DDS core | TRUSTED | This library; all safety claims apply within Z2 |
| Z3 | Tokio / std | TRUSTED | Rust standard library and async runtime |
| Z4 | Build toolchain | TRUSTED | rustc ≥ 1.85; must be from a qualified installation |
| Z5 | Network/external | UNTRUSTED | Not in scope for v0.1; future RTPS transport |

Data entering rust-DDS from Z1 (application) is validated at the API boundary
(topic name, domain value, payload origin). Data from Z5 is not processed in v0.1.

---

## 3 Data Flows

### 3.1 Publish Flow

```
Application
  │ write(payload: Vec<u8>)
  ▼
MockPublisher::write()          ← closed-flag check (REQ-PUB-004)
  │
  ▼
Broker::publish(topic, sample)  ← lock Broker Mutex
  │
  ├──▶ SubInner[0]::push()     ← back-pressure policy (REQ-QOS-006/007)
  ├──▶ SubInner[1]::push()     ← back-pressure policy
  └──▶ SubInner[N]::push()     ← notify all waiters
```

### 3.2 Subscribe Flow

```
Application
  │ recv() / try_recv()
  ▼
SampleReceiver::recv()          ← async wait on Notify (no busy-spin)
  │
  ▼
SubInner::pop()                 ← lock queue Mutex
  │
  ▼
Sample { topic, payload, sequence_number, writer_guid, timestamp }
  │
  ▼
Application                     ← caller validates payload (AoU-004)
```

### 3.3 Unsubscribe / Close Flow

```
Subscriber::unsubscribe()
  │
  ├──▶ SubInner::unsubscribed.store(true)
  └──▶ SubInner::close()        ← signals Notify; recv() drains then returns None (§6.4)

Participant::close()
  │
  ├──▶ AtomicBool::compare_exchange(closed = true)  ← idempotent (REQ-ASIL-007)
  └──▶ all SubInner::close()   ← all receivers drain and return None
```

### 3.4 RELAY Adapter Flow

```
Application
  │ relay::Node::send(ctx, Message)
  ▼
DdsNode::send()
  │ from_message() → Sample
  ▼
Publisher::write(payload)       ← same as §3.1 above

relay::Node::subscribe(opts)
  │ topic from SubscriberOptions
  ▼
MockParticipant::new_subscriber()
  │ spawn forwarding task
  ▼
tokio::mpsc channel → relay::Receiver
```

---

## 4 Interface Boundary Conditions

| Interface Point | Input Constraint | Error Returned | Standard Ref |
|----------------|-----------------|----------------|--------------|
| Domain creation | `i32` in [0, 232] | `DomainOutOfRange` | REQ-PART-001 / HAZ-004 |
| Publisher creation | topic non-empty | `TopicEmpty` | REQ-PART-003 / HAZ-009 |
| Subscriber creation | topic non-empty | `TopicEmpty` | REQ-PART-004 / HAZ-009 |
| write after close | closed flag true | `Closed` | REQ-PUB-004 / HAZ-007 |
| write_ctx with expired ctx | ctx.done() == true | `Timeout` | REQ-PUB-003 |
| GUID deserialization | 32 hex chars = 16 bytes | `InvalidMessage` | REQ-SEC-004 |
| relay::subscribe with no topic | opts.topic is None | `NotConnected` | REQ-RELAY-003 |

---

## 5 Module Responsibility Map

| Module | Single Responsibility | ASIL |
|--------|-----------------------|------|
| `src/types.rs` | Domain, GUID, QoS, Sample types; Sample ↔ Message conversion | D |
| `src/error.rs` | Error enum; RELAY sentinel mapping via `as_relay()` | D |
| `src/participant.rs` | SubInner queue; SampleReceiver; Participant/Publisher/Subscriber traits | D |
| `src/mock/mod.rs` | In-process MockParticipant and Broker | B |
| `src/relay.rs` | RELAY protocol types (Message, Context, Node trait) | B |
| `src/adapt.rs` | RELAY Node adapter wrapping Participant | B |
| `src/lib.rs` | Public re-exports; module-level traceability anchors | D |
| `src/bin/main.rs` | CLI binary; §12 JSON output (version/capabilities/status) | B |
| `build.rs` | Captures rustc version at build time for §12.1 runtime field | A |

---

## 6 Partitioning Analysis (DO-178C §2.5, REQ-DO-012)

Each module above has a single documented responsibility. Failure modes are
contained within module boundaries:

- A fault in `mock/mod.rs` (e.g. wrong routing) cannot corrupt `types.rs` data
  structures (they are immutable once constructed).
- A fault in `adapt.rs` (e.g. wrong topic extraction) affects the relay adapter
  path only; the core DDS pub/sub path is independent.
- `SubInner` state is encapsulated behind `Arc`; no other module can directly
  write to a subscriber queue except through `push()`.
- The CLI binary (`src/bin/main.rs`) is a separate binary target and cannot
  affect library behaviour at runtime.

---

## 7 External Dependencies (Supply Chain)

See `sbom.json` for the full Software Bill of Materials. Key runtime dependencies:

| Crate | Version | Purpose | CVE Check |
|-------|---------|---------|-----------|
| `tokio` | 1.x | Async runtime | cargo audit (CI) |
| `serde` | 1.x | Serialization | cargo audit (CI) |
| `serde_json` | 1.x | JSON encode/decode | cargo audit (CI) |
| `async-trait` | 0.x | Async trait support | cargo audit (CI) |
| `chrono` | 0.4.x | Timestamps | cargo audit (CI) |
| `thiserror` | 1.x | Error derive | cargo audit (CI) |

All dependencies are scanned by `cargo audit` and `rsfusa vuln` on every CI run
(REQ-SEC-006). No dependency carries a known CVE (see `vuln.json`).
