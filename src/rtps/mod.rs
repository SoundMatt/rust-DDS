// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RTPS (Real-Time Publish-Subscribe Protocol) wire types and transport —
//! RTPS 2.3. Tracks the parity build-out plan in `ROADMAP.md` ("Tier 1 —
//! RTPS wire-protocol port"): `guid`/`locator`/`message` (sub-phase 1,
//! "Wire framing & identifiers") and `cdr` (sub-phase 2, "Minimal
//! wire-level CDR") are pure, synchronous `encode`/`decode` for wire types,
//! no I/O. `transport` (sub-phase 3, "UDP transport") is the first module
//! in this tree with actual I/O — async on tokio, per `transport`'s own
//! module docs. `spdp` (sub-phase 4, "SPDP") is the first module with
//! participant/discovery dispatch logic — periodic multicast announce,
//! decode-and-store of peer announcements, lease-based eviction — built on
//! top of `cdr`'s `PL_CDR_LE` codec and `transport`'s sockets. `sedp`
//! (sub-phase 5, "SEDP") is the unicast counterpart: once `spdp` has found a
//! remote participant, `sedp` exchanges publication/subscription
//! announcements with it and matches local/remote endpoints by topic name.
//! `participant` (sub-phase 6, "BestEffort data path") is the first module
//! with an actual RTPS participant runtime type: it owns
//! `rtpsReader`/`rtpsWriter`-shaped local endpoint bookkeeping, wires
//! `sedp`'s endpoint-matching output into it, and performs real BestEffort
//! DATA submessage encode/decode/dispatch over `transport`'s sockets — real
//! end-to-end sample delivery, not just discovery. `reliable` (sub-phase 7,
//! "Reliable QoS") adds HEARTBEAT/ACKNACK retransmission on top of
//! `participant`'s BestEffort path: a per-writer send-history ring buffer
//! and per-remote-writer receive-side gap tracker (both pure bookkeeping,
//! no I/O), while `message` gains the HEARTBEAT/ACKNACK/GAP submessage wire
//! codec and `participant` gains the heartbeat-send/acknack-handle/
//! retransmit wiring — mirroring go-DDS's own split across `reliable.go`,
//! `message.go`, and `participant.go`. `fragment` (sub-phase 8,
//! "Fragmentation") adds the DATA_FRAG submessage codec and reassembly
//! buffer, mirroring go-DDS's `rtps/fragment.go` — `participant` gains
//! send-side fragmentation in `RtpsWriter::write` (large payloads split
//! into DATA_FRAG submessages instead of one DATA) and receive-side
//! reassembly (a `FragmentAssembler` fed from `RtpsParticipant`'s existing
//! receive loop, dispatching a completed reassembly exactly like a DATA
//! submessage — see `fragment.rs`'s module docs for why this exceeds
//! go-DDS's own unwired `fragmentAssembler`). `persist` (sub-phase 9,
//! "TransientLocal durability persistence hooks") and `wildcard`
//! (sub-phase 9, "topic wildcard matching") are the last two small,
//! self-contained pieces of Tier 1: `persist` is a disk-backed last-sample
//! cache (`persist_load`/`persist_flush`) that `participant` wires into
//! `RtpsWriter::write` (flush-on-write) and a new
//! `RtpsParticipant::new_transient_local_reader`/`new_reliable_transient_local_reader`
//! (load-on-subscribe fallback), and `wildcard` is pure MQTT-style
//! `+`/`#` topic-pattern matching that `participant`'s
//! `dispatch_to_readers` calls exactly where go-DDS's own
//! `dispatchToReaders` calls `TopicMatches` — see each module's own docs.
//! Later sub-phases follow the same layering. This module tree is internal: it is **not**
//! re-exported from the crate root and is **not** wired into the public
//! `Participant`/`Publisher`/`Subscriber` API yet.
//!
//! Byte layout for every type here is derived from go-DDS's `rtps` package
//! (`github.com/SoundMatt/go-DDS`, RTPS 2.3), which the roadmap designates
//! as the correctness oracle for this port — same wire format, same
//! submessage encoding, so a rust-DDS participant and a go-DDS participant
//! can eventually talk to each other. See each submodule's `tests` for
//! byte-for-byte comparisons against real go-DDS output (hex literals with
//! the exact Go reproduction snippet in a comment).
//!
//! No `unsafe` anywhere in this module tree (REQ-ASIL-002 / REQ-MEM-001,
//! carried forward from the crate-wide constraint) and no `.unwrap()` on
//! decode paths that accept untrusted/external bytes (REQ-ASIL-003):
//! malformed or truncated input returns `Err(RtpsDecodeError)`, never panics.
//!
//! All nine Tier 1 sub-phases above are internal-only and unit/in-process-
//! integration-tested; none of that proves two independent OS processes
//! actually interoperate over a real wire, which is a distinct gap
//! `ROADMAP.md`'s "Interop testing" section calls out explicitly. `pcap`
//! (this module tree's tenth module, not a Tier 1 sub-phase — it is the
//! "pcap-fixture conformance" deliverable of that section) is a pure pcap
//! container encoder/decoder used to check recorded, known-good go-DDS
//! RTPS traffic byte-for-byte without needing a live peer; the "live
//! two-process harness" deliverable itself lives outside this module tree,
//! in the crate's `rtps-interop-peer` binary (`src/bin/`) and
//! `tests/rtps_two_process_interop.rs`, since it is a standalone process,
//! not a wire type.

pub mod cdr;
pub mod fragment;
pub mod guid;
pub mod locator;
pub mod message;
pub mod participant;
pub mod pcap;
pub mod persist;
pub mod reliable;
pub mod sedp;
pub mod spdp;
pub mod transport;
pub mod wildcard;

use thiserror::Error;

/// Decode error for RTPS wire types.
///
/// Decoding untrusted bytes (from a future UDP transport) must never panic;
/// every `decode` function in this module tree returns this type instead of
/// unwrapping or indexing out of bounds.
//fusa:req REQ-RTPS-009
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RtpsDecodeError {
    /// Input shorter than the fixed wire size for this type.
    #[error("rtps: truncated input: expected at least {expected} bytes, got {got}")]
    Truncated { expected: usize, got: usize },
    /// RTPS message did not start with the `"RTPS"` magic bytes.
    #[error("rtps: bad magic bytes: expected \"RTPS\"")]
    BadMagic,
    /// CDR/PL_CDR payload did not start with a recognised encapsulation
    /// scheme identifier.
    //fusa:req REQ-RTPS-014
    #[error("rtps: unrecognised CDR encapsulation scheme: 0x{got:04x}")]
    InvalidCdrScheme { got: u16 },
}
