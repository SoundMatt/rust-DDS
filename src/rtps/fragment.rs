// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DATA_FRAG submessage codec and reassembly (RTPS 2.3 §8.3.7.3, §9.4.5.13).
//!
//! This is Tier 1 sub-phase 8 of the parity build-out plan in `ROADMAP.md`
//! ("Tier 1 — RTPS wire-protocol port" → "Fragmentation"). It mirrors
//! go-DDS's `rtps/fragment.go` (231 LOC) as a single self-contained file —
//! matching go-DDS's own layout, which (unlike HEARTBEAT/ACKNACK/GAP,
//! defined in `message.go`) keeps `submsgDATAFRAG`, `marshalDataFrag`/
//! `parseDataFrag`, `fragmentAssembler`, and `splitIntoFragments`/
//! `splitIntoFragmentsN` all together in `fragment.go`. [`DataFrag`] carries
//! the parsed submessage fields; [`encode_data_frag`]/[`decode_data_frag`]
//! are the wire codec; [`FragmentAssembler`] is the receiver-side
//! reassembly buffer (go-DDS's `fragmentAssembler`); [`split_into_fragments`]/
//! [`split_into_fragments_n`] are the sender-side splitter (go-DDS's
//! `splitIntoFragments`/`splitIntoFragmentsN`).
//!
//! # Send-side wiring
//!
//! [`super::participant::RtpsWriter::write`] fragments a payload into
//! DATA_FRAG submessages (via [`split_into_fragments`]) whenever its
//! CDR-wrapped size exceeds [`MAX_FRAGMENT_PAYLOAD`], instead of a single
//! DATA submessage — matching go-DDS's `rtpsWriter.Write`. rust-DDS has no
//! TSN writer class yet, so the per-writer `fragmentSize()` override
//! (`TSNParams.MaxFragPayload`) has no counterpart here; every writer uses
//! the same [`MAX_FRAGMENT_PAYLOAD`] default go-DDS falls back to.
//!
//! # Receive-side wiring
//!
//! [`super::participant::RtpsParticipant`] owns one [`FragmentAssembler`]
//! (`RtpsParticipant::frag_assembler`) and feeds it every DATA_FRAG
//! submessage it decodes, dispatching the reassembled payload exactly like
//! a completed DATA submessage once [`FragmentAssembler::receive`] returns
//! `Some`. **This is a deliberate addition beyond go-DDS**: go-DDS defines
//! `fragmentAssembler` and unit-tests it directly (`packet_test.go`), but
//! its own `participant.go` `handleDataPacket` switch has no `submsgDATAFRAG`
//! case — go-DDS sends DATA_FRAG but never reassembles one back on receipt,
//! the same asymmetry already documented for GAP in `reliable.rs` (an
//! encode-only submessage on the go-DDS side). Since a working two-way
//! fragmented-payload round trip needs *some* receive-side reassembly, and
//! go-DDS's own (unused, unwired) `fragmentAssembler` type is the obvious
//! byte/behavior template, this sub-phase wires it in on the rust-DDS side.
//! [`FragKey`] is still keyed the same way go-DDS defines it — writer
//! `EntityId` + low 32 bits of the sequence number, *not* the full remote
//! `Guid` — so, exactly as in go-DDS's own (never-instantiated) design, two
//! different remote participants that happen to assign the same writer
//! `EntityId` and low sequence number could interleave fragments in a
//! single participant-wide assembler. Scoping by full `Guid` would close
//! this gap but would no longer be a faithful port of go-DDS's `fragKey`;
//! documented here rather than silently fixed.
//!
//! # Defensive deviation: no panic on adversarial fragment layout
//!
//! Go's `copy(dst[a:b], src[c:d])` and slice expressions do not panic when
//! a slice's length is `0` (e.g. `c == d`), but `parseDataFrag` places no
//! upper bound relating `FragmentsInSubmsg`/`FragmentStartingNum` to
//! `len(Payload)` — a crafted DATA_FRAG with `FragmentsInSubmsg > 1` and a
//! `Payload` shorter than `FragmentsInSubmsg * FragmentSize` bytes can drive
//! go-DDS's own `fragmentAssembler.receive` to slice `f.Payload[fragStart:fragEnd]`
//! with `fragEnd < fragStart`, which *would* panic in Go too (not exercised
//! by go-DDS's own tests, which never emit `FragmentsInSubmsg > 1`, and
//! moot in practice since go-DDS never wires `fragmentAssembler` into a
//! receive path at all). Since this sub-phase *does* wire reassembly into a
//! live receive path fed by untrusted UDP input, [`FragmentAssembler::receive`]
//! adds one guard `parseDataFrag`/`fragmentAssembler.receive` has no
//! counterpart for: a fragment index whose payload slice would end before
//! it starts is skipped (treated as no bytes contributed) rather than
//! indexed, preserving REQ-RTPS-009's "malformed input never panics"
//! invariant. All arithmetic that combines attacker-controlled fields
//! (`FragmentStartingNum`, `FragmentsInSubmsg`, `FragmentSize`) uses
//! wrapping (not panicking) operations for the same reason, mirroring Go's
//! silent unsigned-integer wraparound semantics exactly rather than
//! introducing a new panic surface Go's own semantics don't have.
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001, carried forward).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::guid::{EntityId, ENTITYID_UNKNOWN};
use super::message::{SequenceNumber, SubmessageHeader, FLAG_ENDIANNESS};
use super::RtpsDecodeError;

/// Maximum bytes placed in a single DATA_FRAG body. Chosen (matching
/// go-DDS's own comment) to keep the full RTPS packet under 1400 bytes on a
/// typical Ethernet MTU of 1500 bytes (headers ≈ 100 bytes).
//fusa:req REQ-RTPS-054
pub const MAX_FRAGMENT_PAYLOAD: usize = 1200;

/// Maximum `DataSize` accepted from an incoming DATA_FRAG submessage.
/// Frames claiming a larger size are discarded before any allocation, to
/// prevent memory exhaustion from malformed or malicious peers. Matches
/// go-DDS's `maxReassemblyBytes`.
//fusa:req REQ-RTPS-053
pub const MAX_REASSEMBLY_BYTES: u32 = 16 * 1024 * 1024;

/// How long an incomplete fragment reassembly is held before being
/// discarded, bounding memory use when fragments are permanently lost.
/// Matches go-DDS's `staleFragAge`.
//fusa:req REQ-RTPS-053
pub const STALE_FRAG_AGE: Duration = Duration::from_secs(5);

/// Submessage ID for DATA_FRAG (RTPS 2.3 §8.3.7.3). Matches go-DDS's
/// `submsgDATAFRAG`, defined in `fragment.go` itself rather than
/// `message.go` — this module mirrors that same file-local placement.
//fusa:req REQ-RTPS-052
pub const SUBMSG_DATA_FRAG: u8 = 0x16;

// ---------------------------------------------------------------------------
// DataFrag
// ---------------------------------------------------------------------------

/// Parsed fields of a DATA_FRAG submessage. Matches go-DDS's `DataFrag`
/// struct.
//fusa:req REQ-RTPS-052
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataFrag {
    pub writer_entity_id: EntityId,
    pub reader_entity_id: EntityId,
    pub writer_seq_num: SequenceNumber,
    /// 1-based index of the first fragment carried by this submessage.
    pub fragment_starting_num: u32,
    /// Number of fragments carried by this submessage.
    pub fragments_in_submsg: u16,
    /// Size of each fragment in bytes (the last fragment of a stream may be
    /// smaller than this, in `payload`, but `fragment_size` still names the
    /// nominal per-fragment stride used to compute byte offsets).
    pub fragment_size: u16,
    /// Total (unfragmented) data size in bytes.
    pub data_size: u32,
    /// Raw bytes of the fragment(s) carried by this submessage.
    pub payload: Vec<u8>,
}

/// Serialises `f` into a complete RTPS submessage (4-byte
/// [`SubmessageHeader`] + body), ready to pass to
/// [`super::message::wrap_in_rtps_message`]. Matches go-DDS's
/// `marshalDataFrag` byte-for-byte.
///
/// Body layout (32 fixed bytes + payload): `extraFlags`(2, always zero) +
/// `octetsToInlineQos`(2, always zero — unlike DATA's fixed `16`, DATA_FRAG
/// carries no inline-QoS-relative fields between these and `readerId`,
/// matching go-DDS's `marshalDataFrag` exactly) + `readerEntityId`(4) +
/// `writerEntityId`(4) + `writerSeqNum`(8, high then low, matching
/// [`SequenceNumber::encode`]) + `fragmentStartingNum`(4) +
/// `fragmentsInSubmsg`(2) + `fragmentSize`(2) + `dataSize`(4) +
/// `payload`(variable). Sets only the `E` (little-endian) flag — unlike
/// DATA, DATA_FRAG has no `D`/`Q` flag bits go-DDS's own encoder sets
/// either.
//fusa:req REQ-RTPS-052
pub fn encode_data_frag(f: &DataFrag) -> Vec<u8> {
    let fixed_len = 32;
    let mut body = Vec::with_capacity(fixed_len + f.payload.len());
    body.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    body.extend_from_slice(&0u16.to_le_bytes()); // octetsToInlineQos
    f.reader_entity_id.encode(&mut body);
    f.writer_entity_id.encode(&mut body);
    f.writer_seq_num.encode(&mut body);
    body.extend_from_slice(&f.fragment_starting_num.to_le_bytes());
    body.extend_from_slice(&f.fragments_in_submsg.to_le_bytes());
    body.extend_from_slice(&f.fragment_size.to_le_bytes());
    body.extend_from_slice(&f.data_size.to_le_bytes());
    body.extend_from_slice(&f.payload);

    let mut out = Vec::with_capacity(SubmessageHeader::LEN + body.len());
    let header = SubmessageHeader {
        submessage_id: SUBMSG_DATA_FRAG,
        flags: FLAG_ENDIANNESS,
        octets_to_next_header: body.len() as u16,
    };
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// Decodes a [`DataFrag`] from a DATA_FRAG submessage *body* (the bytes
/// after the 4-byte [`SubmessageHeader`]). Matches go-DDS's
/// `parseDataFrag`.
///
/// Returns `Err(RtpsDecodeError::Truncated)` — never panics — if `body` is
/// shorter than the fixed 32-byte prefix.
//fusa:req REQ-RTPS-052
//fusa:req REQ-RTPS-009
pub fn decode_data_frag(body: &[u8]) -> Result<DataFrag, RtpsDecodeError> {
    if body.len() < 32 {
        return Err(RtpsDecodeError::Truncated {
            expected: 32,
            got: body.len(),
        });
    }
    let reader_entity_id = EntityId::decode(&body[4..8])?;
    let writer_entity_id = EntityId::decode(&body[8..12])?;
    let writer_seq_num = SequenceNumber::decode(&body[12..20])?;
    let fragment_starting_num = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
    let fragments_in_submsg = u16::from_le_bytes([body[24], body[25]]);
    let fragment_size = u16::from_le_bytes([body[26], body[27]]);
    let data_size = u32::from_le_bytes([body[28], body[29], body[30], body[31]]);
    let payload = body[32..].to_vec();
    Ok(DataFrag {
        writer_entity_id,
        reader_entity_id,
        writer_seq_num,
        fragment_starting_num,
        fragments_in_submsg,
        fragment_size,
        data_size,
        payload,
    })
}

// ---------------------------------------------------------------------------
// FragmentAssembler — receiver-side reassembly
// ---------------------------------------------------------------------------

/// Key identifying one in-progress reassembly: the fragmenting writer's
/// `EntityId` plus the low 32 bits of its sequence number. Matches go-DDS's
/// `fragKey` exactly — see this module's doc comment ("Receive-side
/// wiring") for the cross-participant-collision caveat that follows from
/// not including a `GuidPrefix`.
//fusa:req REQ-RTPS-053
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FragKey {
    writer: EntityId,
    seq_lo: u32,
}

/// One in-progress reassembly buffer. Matches go-DDS's `fragBuffer`.
struct FragBuffer {
    data: Vec<u8>,
    /// Count of *distinct* fragment indices received so far — see
    /// `received_indices` below. Not incremented again for a duplicate
    /// delivery of an already-seen index.
    received: u32,
    /// Set of fragment indices (0-based, `fragment_starting_num - 1`, plus
    /// offset within a multi-fragment submessage) already contributed to
    /// `data`. Required because completion is decided by `received >=
    /// total`: without tracking *which* indices were actually seen,
    /// redelivery (duplication) of a single index under a lossy/reordering
    /// transport like UDP could satisfy the count while other indices were
    /// never delivered, falsely completing reassembly with the
    /// corresponding regions of `data` left at their zero-fill initial
    /// value instead of real payload.
    received_indices: HashSet<u32>,
    /// Total number of fragments expected.
    total: u32,
    /// When the first fragment for this key was received (monotonic clock
    /// — go-DDS uses wall-clock `time.Time`/`time.Now()`, but only ever
    /// compares two same-process readings via `Sub`, so a monotonic
    /// [`Instant`] is behaviourally equivalent here and avoids any
    /// wall-clock-adjustment hazard).
    created: Instant,
}

/// Reassembles DATA_FRAG submessages for any number of concurrent
/// (writer, sequence-number) reassembly streams. Matches go-DDS's
/// `fragmentAssembler`.
///
/// # Concurrency
///
/// Guarded by a plain [`std::sync::Mutex`], matching go-DDS's own
/// `fragmentAssembler.mu` (`sync.Mutex`) and this module tree's async/tokio
/// design convention (short bookkeeping updates, never held across an
/// `.await`) — see `reliable.rs`'s module docs for the same rationale.
//fusa:req REQ-RTPS-053
#[derive(Default)]
pub struct FragmentAssembler {
    buffers: Mutex<HashMap<FragKey, FragBuffer>>,
}

impl FragmentAssembler {
    /// Creates an empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one DATA_FRAG's fragment(s) to the matching in-progress
    /// reassembly (creating it on first contact) and returns the complete
    /// reassembled payload once every fragment has arrived, or `None`
    /// while reassembly is still incomplete or `f` is rejected outright
    /// (zero `fragment_size`/`data_size`/`fragments_in_submsg`, or
    /// `data_size` over [`MAX_REASSEMBLY_BYTES`] — rejected before any
    /// allocation). Matches go-DDS's `fragmentAssembler.receive`
    /// (including its stale-reassembly sweep, run on every call, and its
    /// out-of-order/duplicate-fragment tolerance), plus the one additional
    /// no-panic guard documented in this module's "Defensive deviation"
    /// doc section.
    //fusa:req REQ-RTPS-053
    //fusa:req REQ-RTPS-009
    pub fn receive(&self, f: &DataFrag) -> Option<Vec<u8>> {
        if f.fragment_size == 0 || f.data_size == 0 || f.fragments_in_submsg == 0 {
            return None;
        }
        if f.data_size > MAX_REASSEMBLY_BYTES {
            return None;
        }
        let total = f.data_size.div_ceil(u32::from(f.fragment_size));

        let key = FragKey {
            writer: f.writer_entity_id,
            seq_lo: f.writer_seq_num.low,
        };
        let now = Instant::now();
        // Poisoned-mutex recovery matches this module tree's convention
        // elsewhere (never propagate a panic from one caller into every
        // other caller of a shared bookkeeping type): fall back to the
        // poisoned guard's data rather than panicking here too.
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());

        // Evict incomplete reassemblies older than STALE_FRAG_AGE, on every
        // call — matches go-DDS's sweep-on-every-receive.
        buffers.retain(|_, b| now.duration_since(b.created) <= STALE_FRAG_AGE);

        let fb = buffers.entry(key).or_insert_with(|| FragBuffer {
            data: vec![0u8; f.data_size as usize],
            received: 0,
            received_indices: HashSet::new(),
            total,
            created: now,
        });

        // fragIdx/offset combine attacker-controlled fields; use wrapping
        // arithmetic (mirrors Go's silent unsigned wraparound) rather than
        // risking an overflow panic — see the module doc's "Defensive
        // deviation" section.
        let frag_idx = f.fragment_starting_num.wrapping_sub(1);
        for i in 0..f.fragments_in_submsg {
            let idx = frag_idx.wrapping_add(u32::from(i));
            let offset = idx.wrapping_mul(u32::from(f.fragment_size));
            if offset >= f.data_size {
                break;
            }
            // A fragment index already contributed to `data` — redelivery
            // (duplication) of it must not double-count towards
            // `received`, or a lossy/reordering transport delivering one
            // index repeatedly while others are lost could falsely
            // complete reassembly (see `received_indices`'s doc comment).
            // Checked (not yet recorded) here; only actually recorded once
            // this fragment is confirmed well-formed below, so a malformed
            // delivery never permanently "consumes" an index that a later,
            // well-formed redelivery could still legitimately complete.
            if fb.received_indices.contains(&idx) {
                continue;
            }
            // offset < f.data_size <= MAX_REASSEMBLY_BYTES here, so the
            // remaining arithmetic in this iteration cannot overflow u32.
            let frag_start = u32::from(i) * u32::from(f.fragment_size);
            let payload_len = f.payload.len() as u32;
            let frag_end = (frag_start + u32::from(f.fragment_size)).min(payload_len);
            if frag_end < frag_start {
                // Malformed: this fragment's declared payload is shorter
                // than its position implies. Go's equivalent slice
                // expression would panic here; skip instead (REQ-RTPS-009).
                continue;
            }
            let end = (offset + (frag_end - frag_start)).min(f.data_size);
            fb.data[offset as usize..end as usize]
                .copy_from_slice(&f.payload[frag_start as usize..frag_end as usize]);
            fb.received_indices.insert(idx);
            fb.received += 1;
        }

        if fb.received >= fb.total {
            buffers.remove(&key).map(|b| b.data)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Splitting — sender-side
// ---------------------------------------------------------------------------

/// Splits `payload` into [`DataFrag`]s using the default
/// [`MAX_FRAGMENT_PAYLOAD`] size. `writer_eid`/`seq_num` identify the
/// writer and the sample being fragmented. Matches go-DDS's
/// `splitIntoFragments`.
//fusa:req REQ-RTPS-054
pub fn split_into_fragments(
    writer_eid: EntityId,
    seq_num: SequenceNumber,
    payload: &[u8],
) -> Vec<DataFrag> {
    split_into_fragments_n(writer_eid, seq_num, payload, MAX_FRAGMENT_PAYLOAD)
}

/// Splits `payload` into [`DataFrag`]s with at most `max_payload_size`
/// bytes of payload per fragment (each fragment its own submessage —
/// `fragments_in_submsg` is always `1`, matching go-DDS's own
/// `splitIntoFragmentsN`, which never packs more than one fragment per
/// submessage). `max_payload_size <= 0` (i.e. `0`, since this parameter is
/// unsigned) falls back to [`MAX_FRAGMENT_PAYLOAD`], matching go-DDS's
/// `maxPayloadSize <= 0` fallback. Matches go-DDS's `splitIntoFragmentsN`
/// byte-for-byte, including its truncating `uint16(maxPayloadSize)` cast
/// for any `max_payload_size` above `u16::MAX`.
//fusa:req REQ-RTPS-054
pub fn split_into_fragments_n(
    writer_eid: EntityId,
    seq_num: SequenceNumber,
    payload: &[u8],
    max_payload_size: usize,
) -> Vec<DataFrag> {
    let max_payload_size = if max_payload_size == 0 {
        MAX_FRAGMENT_PAYLOAD
    } else {
        max_payload_size
    };
    let size = max_payload_size as u16;
    let total = payload.len();
    let mut frags = Vec::new();
    let mut offset = 0usize;
    let mut frag_num = 1u32; // 1-based
    while offset < total {
        let end = (offset + usize::from(size)).min(total);
        let chunk = &payload[offset..end];
        frags.push(DataFrag {
            writer_entity_id: writer_eid,
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_seq_num: seq_num,
            fragment_starting_num: frag_num,
            fragments_in_submsg: 1,
            fragment_size: size,
            data_size: total as u32,
            payload: chunk.to_vec(),
        });
        offset = end;
        frag_num += 1;
    }
    frags
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtps::guid::{entity_id_for_writer, GuidPrefix};
    use crate::rtps::message::{wrap_in_rtps_message, Header, VendorId};

    fn ascending_prefix() -> GuidPrefix {
        let mut b = [0u8; 12];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i + 1) as u8;
        }
        GuidPrefix(b)
    }

    // Reference bytes reproduced from go-DDS's actual `rtps` package (real
    // `marshalDataFrag`/`parseDataFrag`/`splitIntoFragments`/
    // `splitIntoFragmentsN`/`fragmentAssembler`/`wrapInRTPSMessage`, not
    // reimplemented). Go reproduction (package-local scratch test file,
    // `rtps/zzrepro_fragment_test.go`, never committed to go-DDS, deleted
    // after use):
    //
    //   writerEID := entityIdForWriter(1)
    //   f := DataFrag{
    //       WriterEntityId: writerEID, ReaderEntityId: EntityIdUnknown,
    //       WriterSeqNum: SequenceNumber{High: 0, Low: 7},
    //       FragmentStartingNum: 1, FragmentsInSubmsg: 1,
    //       FragmentSize: 6, DataSize: 6,
    //       Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02},
    //   }
    //   buf := marshalDataFrag(f)
    //   fmt.Printf("%x\n", buf)
    //   // -> 160126000000000000000000000001030000000007000000010000000100
    //   //    060006000000deadbeef0102
    //   fmt.Printf("%d\n", len(buf)) // -> 42
    //
    //   var prefix GuidPrefix
    //   for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    //   msg := wrapInRTPSMessage(prefix, buf)
    //   fmt.Printf("%x\n", msg)
    //   // -> 52545053020301270102030405060708090a0b0c1601260000000000000000
    //   //    00000001030000000007000000010000000100060006000000deadbeef0102
    //   fmt.Printf("%d\n", len(msg)) // -> 62
    //
    //   payload := make([]byte, maxFragmentPayload*2+50) // 2450 bytes
    //   for i := range payload { payload[i] = byte(i % 251) }
    //   frags := splitIntoFragments(writerEID, SequenceNumber{Low: 2}, payload)
    //   // len(frags) == 3; frags[0].FragmentSize==1200, len(Payload)==1200;
    //   // frags[2].len(Payload)==50, DataSize==2450 on every fragment.
    //
    //   small := make([]byte, 25)
    //   for i := range small { small[i] = byte(i) }
    //   fragsN := splitIntoFragmentsN(writerEID, SequenceNumber{Low: 3}, small, 10)
    //   // len(fragsN) == 3: payload lengths 10, 10, 5.
    //
    //   var fa fragmentAssembler
    //   var result []byte
    //   for _, idx := range []int{2, 0, 1} { result = fa.receive(fragsN[idx]) }
    //   fmt.Printf("%x\n", result) // -> 000102030405060708090a0b0c0d0e0f101112131415161718
    //
    // Full run: `go test ./rtps/... -run TestZZReproFragmentBytes -v`
    // (go-DDS commit 3b548f2 / rust-DDS branch feat/rtps-fragmentation).

    //fusa:test REQ-RTPS-052
    #[test]
    fn encode_data_frag_matches_go_dds_reference() {
        let writer_eid = entity_id_for_writer(1);
        let f = DataFrag {
            writer_entity_id: writer_eid,
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_seq_num: SequenceNumber { high: 0, low: 7 },
            fragment_starting_num: 1,
            fragments_in_submsg: 1,
            fragment_size: 6,
            data_size: 6,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
        };
        let buf = encode_data_frag(&f);
        assert_eq!(buf.len(), 42);
        assert_eq!(
            hex::encode(&buf),
            "160126000000000000000000000001030000000007000000010000000100\
             060006000000deadbeef0102"
                .replace(['\n', ' '], "")
        );

        let header = Header {
            protocol_version: crate::rtps::message::PROTOCOL_VERSION_2_3,
            vendor_id: VendorId([0x01, 0x27]), // go-DDS's own vendor id, for byte-exact parity
            guid_prefix: ascending_prefix(),
        };
        let msg = wrap_in_rtps_message(header, &buf);
        assert_eq!(msg.len(), 62);
        assert_eq!(
            hex::encode(&msg),
            "52545053020301270102030405060708090a0b0c16012600000000000000\
             0000000001030000000007000000010000000100060006000000deadbeef0102"
                .replace(['\n', ' '], "")
        );
    }

    //fusa:test REQ-RTPS-052
    #[test]
    fn decode_data_frag_round_trips_encode_data_frag() {
        let f = DataFrag {
            writer_entity_id: entity_id_for_writer(1),
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_seq_num: SequenceNumber { high: 0, low: 7 },
            fragment_starting_num: 1,
            fragments_in_submsg: 1,
            fragment_size: 6,
            data_size: 6,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
        };
        let buf = encode_data_frag(&f);
        let decoded = decode_data_frag(&buf[SubmessageHeader::LEN..]).unwrap();
        assert_eq!(decoded, f);
    }

    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_data_frag_rejects_truncated_input_without_panicking() {
        assert_eq!(
            decode_data_frag(&[0u8; 31]),
            Err(RtpsDecodeError::Truncated {
                expected: 32,
                got: 31
            })
        );
    }

    //fusa:test REQ-RTPS-054
    #[test]
    fn split_into_fragments_matches_go_dds_reference() {
        let writer_eid = entity_id_for_writer(1);
        let payload: Vec<u8> = (0..(MAX_FRAGMENT_PAYLOAD * 2 + 50))
            .map(|i| (i % 251) as u8)
            .collect();
        let frags = split_into_fragments(writer_eid, SequenceNumber { high: 0, low: 2 }, &payload);
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].fragment_starting_num, 1);
        assert_eq!(frags[0].fragment_size, MAX_FRAGMENT_PAYLOAD as u16);
        assert_eq!(frags[0].payload.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(frags[2].fragment_starting_num, 3);
        assert_eq!(frags[2].payload.len(), 50);
        for f in &frags {
            assert_eq!(f.data_size, payload.len() as u32);
            assert_eq!(f.fragments_in_submsg, 1);
            assert_eq!(f.reader_entity_id, ENTITYID_UNKNOWN);
        }
    }

    //fusa:test REQ-RTPS-054
    #[test]
    fn split_into_fragments_n_matches_go_dds_reference() {
        let writer_eid = entity_id_for_writer(1);
        let small: Vec<u8> = (0..25u8).collect();
        let frags =
            split_into_fragments_n(writer_eid, SequenceNumber { high: 0, low: 3 }, &small, 10);
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].payload, small[0..10]);
        assert_eq!(frags[1].payload, small[10..20]);
        assert_eq!(frags[2].payload, small[20..25]);
        for f in &frags {
            assert_eq!(f.fragment_size, 10);
            assert_eq!(f.data_size, 25);
        }
    }

    //fusa:test REQ-RTPS-054
    #[test]
    fn split_into_fragments_n_empty_payload_yields_no_fragments() {
        let frags =
            split_into_fragments_n(entity_id_for_writer(1), SequenceNumber::default(), &[], 10);
        assert!(frags.is_empty());
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_reassembles_out_of_order_matches_go_dds_reference() {
        let writer_eid = entity_id_for_writer(1);
        let small: Vec<u8> = (0..25u8).collect();
        let frags =
            split_into_fragments_n(writer_eid, SequenceNumber { high: 0, low: 3 }, &small, 10);

        let fa = FragmentAssembler::new();
        let mut result = None;
        for idx in [2usize, 0, 1] {
            result = fa.receive(&frags[idx]);
        }
        assert_eq!(result, Some(small));
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_duplicate_fragment_does_not_falsely_complete() {
        let writer_eid = entity_id_for_writer(1);
        let payload: Vec<u8> = (0..30u8).collect();
        let frags =
            split_into_fragments_n(writer_eid, SequenceNumber { high: 0, low: 4 }, &payload, 10);
        assert_eq!(frags.len(), 3);

        let fa = FragmentAssembler::new();
        // Redeliver fragment index 0 three times; fragments 1 and 2 never
        // arrive. Before the fix, `received` was a plain per-submessage
        // counter, so this alone would satisfy `received >= total` and
        // falsely report reassembly complete with bytes [10..30] left at
        // their zero-fill initial value instead of real payload.
        assert_eq!(fa.receive(&frags[0]), None);
        assert_eq!(fa.receive(&frags[0]), None);
        assert_eq!(fa.receive(&frags[0]), None);

        // Delivering the two genuinely-missing fragments now completes it,
        // with the correct payload.
        assert_eq!(fa.receive(&frags[1]), None);
        assert_eq!(fa.receive(&frags[2]), Some(payload));
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_partial_delivery_returns_none() {
        let writer_eid = entity_id_for_writer(1);
        let payload = vec![0u8; MAX_FRAGMENT_PAYLOAD * 2];
        let frags = split_into_fragments(writer_eid, SequenceNumber { high: 0, low: 1 }, &payload);

        let fa = FragmentAssembler::new();
        assert_eq!(fa.receive(&frags[0]), None);
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_oversize_data_size_rejected_without_allocating() {
        let f = DataFrag {
            writer_entity_id: entity_id_for_writer(99),
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_seq_num: SequenceNumber { high: 0, low: 1 },
            fragment_starting_num: 1,
            fragments_in_submsg: 1,
            fragment_size: 1200,
            data_size: MAX_REASSEMBLY_BYTES + 1,
            payload: vec![0u8; 1200],
        };
        let fa = FragmentAssembler::new();
        assert_eq!(fa.receive(&f), None);
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_zero_data_size_rejected() {
        let f = DataFrag {
            fragment_size: 100,
            data_size: 0,
            fragments_in_submsg: 1,
            ..Default::default()
        };
        assert_eq!(FragmentAssembler::new().receive(&f), None);
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_zero_fragment_size_rejected() {
        let f = DataFrag {
            fragment_size: 0,
            data_size: 100,
            fragments_in_submsg: 1,
            ..Default::default()
        };
        assert_eq!(FragmentAssembler::new().receive(&f), None);
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_zero_fragments_in_submsg_rejected() {
        let f = DataFrag {
            fragment_size: 100,
            data_size: 100,
            fragments_in_submsg: 0,
            ..Default::default()
        };
        assert_eq!(FragmentAssembler::new().receive(&f), None);
    }

    //fusa:test REQ-RTPS-053
    #[test]
    fn fragment_assembler_stale_reassembly_is_evicted() {
        let writer_eid = entity_id_for_writer(55);
        let payload1 = vec![0u8; MAX_FRAGMENT_PAYLOAD * 2];
        let frags1 =
            split_into_fragments(writer_eid, SequenceNumber { high: 0, low: 1 }, &payload1);

        let fa = FragmentAssembler::new();
        fa.receive(&frags1[0]);
        assert_eq!(fa.buffers.lock().unwrap().len(), 1);

        // Back-date the buffer's `created` time past STALE_FRAG_AGE.
        {
            let mut buffers = fa.buffers.lock().unwrap();
            for b in buffers.values_mut() {
                b.created -= STALE_FRAG_AGE + Duration::from_secs(1);
            }
        }

        // Any subsequent receive() triggers the sweep.
        let payload2 = b"trigger".to_vec();
        let frags2 =
            split_into_fragments(writer_eid, SequenceNumber { high: 0, low: 2 }, &payload2);
        fa.receive(&frags2[0]);

        let buffers = fa.buffers.lock().unwrap();
        assert!(!buffers.contains_key(&FragKey {
            writer: writer_eid,
            seq_lo: 1
        }));
    }

    //fusa:test REQ-RTPS-009
    #[test]
    fn fragment_assembler_offset_past_data_size_breaks_without_panicking() {
        let eid = entity_id_for_writer(77);
        let fa = FragmentAssembler::new();

        let f1 = DataFrag {
            writer_entity_id: eid,
            writer_seq_num: SequenceNumber { high: 0, low: 7 },
            fragment_starting_num: 1,
            fragments_in_submsg: 1,
            fragment_size: 100,
            data_size: 200,
            payload: vec![0u8; 100],
            ..Default::default()
        };
        assert_eq!(fa.receive(&f1), None);

        // offset = (3-1)*100 = 200 >= DataSize(200) -> must break, not panic.
        let f3 = DataFrag {
            fragment_starting_num: 3,
            ..f1.clone()
        };
        assert_eq!(fa.receive(&f3), None);
    }

    //fusa:test REQ-RTPS-009
    #[test]
    fn fragment_assembler_end_clamp_matches_go_dds_reference() {
        // DataSize=250, FragmentSize=100: fragment 3 offset=200, nominal
        // end=300 > 250 -> clamped to 250.
        let eid = entity_id_for_writer(78);
        let fa = FragmentAssembler::new();
        for start in [1u32, 2, 3] {
            let len = if start == 3 { 50 } else { 100 };
            let f = DataFrag {
                writer_entity_id: eid,
                writer_seq_num: SequenceNumber { high: 0, low: 8 },
                fragment_starting_num: start,
                fragments_in_submsg: 1,
                fragment_size: 100,
                data_size: 250,
                payload: vec![start as u8; len],
                ..Default::default()
            };
            let result = fa.receive(&f);
            if start == 3 {
                let data = result.expect("reassembly should complete on the last fragment");
                assert_eq!(data.len(), 250);
                assert_eq!(&data[200..250], &vec![3u8; 50][..]);
            }
        }
    }

    //fusa:test REQ-RTPS-009
    #[test]
    fn fragment_assembler_short_payload_for_position_is_skipped_without_panicking() {
        // Defensive-only case (see module docs): FragmentsInSubmsg=2 but
        // Payload is too short to cover fragment index 1's declared
        // position at all (frag_start=100 > payload.len()=50, so
        // frag_end < frag_start). Go's equivalent slice expression would
        // panic here; this must not.
        let f = DataFrag {
            writer_entity_id: entity_id_for_writer(1),
            writer_seq_num: SequenceNumber { high: 0, low: 1 },
            fragment_starting_num: 1,
            fragments_in_submsg: 2,
            fragment_size: 100,
            data_size: 200,
            payload: vec![0xAB; 50], // too short for fragment index 1's position
            ..Default::default()
        };
        let fa = FragmentAssembler::new();
        // Must not panic; the short second fragment contributes nothing so
        // reassembly (2 fragments expected, only 1 counted) stays
        // incomplete.
        assert_eq!(fa.receive(&f), None);
    }

    //fusa:test REQ-RTPS-054
    #[test]
    fn split_into_fragments_n_zero_falls_back_to_default() {
        let payload = vec![0u8; MAX_FRAGMENT_PAYLOAD + 1];
        let frags = split_into_fragments_n(
            entity_id_for_writer(1),
            SequenceNumber::default(),
            &payload,
            0,
        );
        assert_eq!(frags[0].fragment_size, MAX_FRAGMENT_PAYLOAD as u16);
    }
}
