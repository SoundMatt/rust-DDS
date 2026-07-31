// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RTPS message framing: `ProtocolVersion`, `VendorId`, `SequenceNumber`,
//! the fixed 20-byte `Header`, and the 4-byte `SubmessageHeader`
//! (RTPS 2.3 §9.3.2, §9.4.1, §9.4.2).
//!
//! Wire layout ported 1:1 from go-DDS's `rtps/message.go` (the framing
//! half — DATA/HEARTBEAT/ACKNACK/GAP/INFO_TS submessage *bodies* are later
//! Tier 1 sub-phases, not this one).

use super::guid::{EntityId, GuidPrefix};
use super::RtpsDecodeError;

// ---------------------------------------------------------------------------
// ProtocolVersion
// ---------------------------------------------------------------------------

/// RTPS protocol version: `{major, minor}` (RTPS 2.3 §9.3.2).
//fusa:req REQ-RTPS-004
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

/// RTPS 2.3 — the version this crate implements.
//fusa:req REQ-RTPS-004
pub const PROTOCOL_VERSION_2_3: ProtocolVersion = ProtocolVersion { major: 2, minor: 3 };

impl ProtocolVersion {
    /// Wire size in bytes.
    pub const LEN: usize = 2;

    /// Append the 2-byte wire encoding (`{major, minor}`, raw bytes, no
    /// endian conversion — matches go-DDS's `[2]byte{major, minor}`) to
    /// `buf`.
    //fusa:req REQ-RTPS-004
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.major);
        buf.push(self.minor);
    }

    /// Decode a `ProtocolVersion` from the first 2 bytes of `buf`.
    //fusa:req REQ-RTPS-004
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        Ok(ProtocolVersion {
            major: buf[0],
            minor: buf[1],
        })
    }
}

// ---------------------------------------------------------------------------
// VendorId
// ---------------------------------------------------------------------------

/// 2-byte RTPS vendor identifier (RTPS 2.3 §9.3.2, assigned by the OMG
/// vendor registry).
//fusa:req REQ-RTPS-005
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct VendorId(pub [u8; 2]);

/// rust-DDS's own vendor ID. Unregistered (not assigned by the OMG vendor
/// registry), chosen distinct from go-DDS's own unregistered `0x0127`
/// (see go-DDS `rtps/message.go`'s `goVendorId`).
//fusa:req REQ-RTPS-005
pub const VENDOR_ID_RUST_DDS: VendorId = VendorId([0x01, 0x28]);

impl VendorId {
    /// Wire size in bytes.
    pub const LEN: usize = 2;

    /// Append the 2 raw wire bytes of this `VendorId` to `buf`.
    //fusa:req REQ-RTPS-005
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    /// Decode a `VendorId` from the first 2 bytes of `buf`.
    //fusa:req REQ-RTPS-005
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        let mut b = [0u8; 2];
        b.copy_from_slice(&buf[..Self::LEN]);
        Ok(VendorId(b))
    }
}

// ---------------------------------------------------------------------------
// SequenceNumber
// ---------------------------------------------------------------------------

/// 8-byte writer sequence number, packed as `High:Low` (RTPS 2.3 §9.3.2).
///
/// `High` is signed per the RTPS spec and go-DDS's own `SequenceNumber`
/// struct; in practice it is always `0` until the low 32 bits wrap.
//fusa:req REQ-RTPS-006
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SequenceNumber {
    pub high: i32,
    pub low: u32,
}

impl SequenceNumber {
    /// Wire size in bytes.
    pub const LEN: usize = 8;

    /// Append the 8-byte little-endian wire encoding (`high` then `low`,
    /// each 4-byte LE — matches go-DDS's `marshalDataSubmessage`/
    /// `marshalHeartbeat` field layout) to `buf`.
    //fusa:req REQ-RTPS-006
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.high.to_le_bytes());
        buf.extend_from_slice(&self.low.to_le_bytes());
    }

    /// Decode a `SequenceNumber` from the first 8 bytes of `buf`.
    //fusa:req REQ-RTPS-006
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        let high = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let low = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok(SequenceNumber { high, low })
    }

    /// Pack `{high, low}` into a single `u64` so reliability bookkeeping
    /// never aliases after the low 32 bits wrap (RTPS 2.3 §8.3.5).
    ///
    /// Direct port of go-DDS's `snToU64` (`rtps/reliable.go`):
    /// `uint64(uint32(sn.High))<<32 | uint64(sn.Low)`.
    //fusa:req REQ-RTPS-007
    pub fn to_u64(self) -> u64 {
        (u64::from(self.high as u32)) << 32 | u64::from(self.low)
    }

    /// Inverse of [`SequenceNumber::to_u64`]. Direct port of go-DDS's
    /// `u64ToSN`.
    //fusa:req REQ-RTPS-007
    pub fn from_u64(v: u64) -> Self {
        SequenceNumber {
            high: (v >> 32) as i32,
            low: v as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// Header (fixed 20-byte RTPS message header)
// ---------------------------------------------------------------------------

/// Magic bytes at the start of every RTPS message (RTPS 2.3 §9.4.1).
//fusa:req REQ-RTPS-008
pub const RTPS_MAGIC: [u8; 4] = *b"RTPS";

/// Fixed 20-byte RTPS message header (RTPS 2.3 §9.4.1): 4-byte magic +
/// 2-byte `ProtocolVersion` + 2-byte `VendorId` + 12-byte `GuidPrefix`.
//fusa:req REQ-RTPS-008
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Header {
    pub protocol_version: ProtocolVersion,
    pub vendor_id: VendorId,
    pub guid_prefix: GuidPrefix,
}

impl Header {
    /// Wire size in bytes.
    pub const LEN: usize = 20;

    /// Append the 20-byte wire encoding of this `Header` to `buf`:
    /// `"RTPS"` + `protocol_version` + `vendor_id` + `guid_prefix`.
    //fusa:req REQ-RTPS-008
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&RTPS_MAGIC);
        self.protocol_version.encode(buf);
        self.vendor_id.encode(buf);
        self.guid_prefix.encode(buf);
    }

    /// Decode a `Header` from the first 20 bytes of `buf`.
    ///
    /// Returns `Err(RtpsDecodeError::BadMagic)` if the first 4 bytes are
    /// not `"RTPS"`, or `Err(RtpsDecodeError::Truncated)` if `buf` is
    /// shorter than [`Header::LEN`]. Never panics.
    //fusa:req REQ-RTPS-008
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        if buf[0..4] != RTPS_MAGIC {
            return Err(RtpsDecodeError::BadMagic);
        }
        let protocol_version = ProtocolVersion::decode(&buf[4..6])?;
        let vendor_id = VendorId::decode(&buf[6..8])?;
        let guid_prefix = GuidPrefix::decode(&buf[8..20])?;
        Ok(Header {
            protocol_version,
            vendor_id,
            guid_prefix,
        })
    }
}

// ---------------------------------------------------------------------------
// SubmessageHeader
// ---------------------------------------------------------------------------

/// Submessage ID for DATA (RTPS 2.3 §9.4.5.3).
//fusa:req REQ-RTPS-010
pub const SUBMSG_DATA: u8 = 0x15;
/// Submessage ID for GAP (§9.4.5.4).
//fusa:req REQ-RTPS-010
pub const SUBMSG_GAP: u8 = 0x08;
/// Submessage ID for HEARTBEAT (§9.4.5.5).
//fusa:req REQ-RTPS-010
pub const SUBMSG_HEARTBEAT: u8 = 0x07;
/// Submessage ID for ACKNACK (§9.4.5.1).
//fusa:req REQ-RTPS-010
pub const SUBMSG_ACKNACK: u8 = 0x06;
/// Submessage ID for INFO_TS (§9.4.5.8).
//fusa:req REQ-RTPS-010
pub const SUBMSG_INFO_TS: u8 = 0x09;
/// Submessage ID for PAD (§9.4.5.9).
//fusa:req REQ-RTPS-010
pub const SUBMSG_PAD: u8 = 0x01;

/// Flag bit E: 1 = little-endian (present on every submessage we emit).
//fusa:req REQ-RTPS-010
pub const FLAG_ENDIANNESS: u8 = 0x01;
/// Flag bit Q: inline QoS present (DATA submessage, §9.4.5.3).
//fusa:req REQ-RTPS-010
pub const FLAG_INLINE_QOS: u8 = 0x02;
/// Flag bit D: serialised payload present (DATA submessage, §9.4.5.3).
//fusa:req REQ-RTPS-010
pub const FLAG_DATA: u8 = 0x04;

/// 4-byte submessage header prefixing every RTPS submessage (RTPS 2.3
/// §9.4.2): `submessageId` (1 byte) + `flags` (1 byte) +
/// `octetsToNextHeader` (2-byte little-endian length of the body that
/// follows).
//fusa:req REQ-RTPS-010
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SubmessageHeader {
    pub submessage_id: u8,
    pub flags: u8,
    pub octets_to_next_header: u16,
}

impl SubmessageHeader {
    /// Wire size in bytes.
    pub const LEN: usize = 4;

    /// Append the 4-byte wire encoding of this `SubmessageHeader` to `buf`.
    //fusa:req REQ-RTPS-010
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.submessage_id);
        buf.push(self.flags);
        buf.extend_from_slice(&self.octets_to_next_header.to_le_bytes());
    }

    /// Decode a `SubmessageHeader` from the first 4 bytes of `buf`.
    //fusa:req REQ-RTPS-010
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        Ok(SubmessageHeader {
            submessage_id: buf[0],
            flags: buf[1],
            octets_to_next_header: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }
}

// ---------------------------------------------------------------------------
// DataSubmessage (RTPS 2.3 §9.4.5.3)
// ---------------------------------------------------------------------------

/// Parsed fields of a DATA submessage.
//fusa:req REQ-RTPS-021
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataSubmessage {
    pub reader_entity_id: EntityId,
    pub writer_entity_id: EntityId,
    pub seq_num: SequenceNumber,
    /// `None` when the `D` (data) flag is not set, or the submessage body
    /// carries no bytes past the fixed 20-byte prefix.
    pub payload: Option<Vec<u8>>,
}

/// Builds a full DATA submessage (4-byte `SubmessageHeader` + body) carrying
/// `serialised_payload`. `serialised_payload` should already include its CDR
/// encapsulation header (see [`super::cdr::wrap_payload`]/
/// [`super::cdr::PlCdrEncoder::finish`]).
///
/// Body layout (RTPS 2.3 §9.4.5.3): `extraFlags`(2, always zero) +
/// `octetsToInlineQos`(2, always 16 — the fixed distance from the end of
/// that field to the start of `payload`) + `readerId`(4) + `writerId`(4) +
/// `seqNum`(8) + `payload`(variable). Matches go-DDS's
/// `marshalDataSubmessage` byte-for-byte; always sets the `E` (little-endian)
/// and `D` (data present) flags, matching go-DDS's own emission (this crate
/// never emits inline QoS or a keyed-only DATA, so those flags never need to
/// be set here).
//fusa:req REQ-RTPS-021
pub fn encode_data_submessage(
    writer_entity_id: EntityId,
    reader_entity_id: EntityId,
    seq_num: SequenceNumber,
    serialised_payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(20 + serialised_payload.len());
    body.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    reader_entity_id.encode(&mut body);
    writer_entity_id.encode(&mut body);
    seq_num.encode(&mut body);
    body.extend_from_slice(serialised_payload);

    let mut out = Vec::with_capacity(SubmessageHeader::LEN + body.len());
    let header = SubmessageHeader {
        submessage_id: SUBMSG_DATA,
        flags: FLAG_ENDIANNESS | FLAG_DATA,
        octets_to_next_header: body.len() as u16,
    };
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// Decodes a `DataSubmessage` from a DATA submessage *body* (the bytes after
/// the 4-byte `SubmessageHeader` — pass `flags` from that header
/// separately). Matches go-DDS's `parseDataSubmessage`.
///
/// Returns `Err(RtpsDecodeError::Truncated)` — never panics — if `body` is
/// shorter than the fixed 20-byte prefix.
//fusa:req REQ-RTPS-021
//fusa:req REQ-RTPS-009
pub fn decode_data_submessage(flags: u8, body: &[u8]) -> Result<DataSubmessage, RtpsDecodeError> {
    if body.len() < 20 {
        return Err(RtpsDecodeError::Truncated {
            expected: 20,
            got: body.len(),
        });
    }
    let reader_entity_id = EntityId::decode(&body[4..8])?;
    let writer_entity_id = EntityId::decode(&body[8..12])?;
    let seq_num = SequenceNumber::decode(&body[12..20])?;
    let payload = if flags & FLAG_DATA != 0 && body.len() > 20 {
        Some(body[20..].to_vec())
    } else {
        None
    };
    Ok(DataSubmessage {
        reader_entity_id,
        writer_entity_id,
        seq_num,
        payload,
    })
}

// ---------------------------------------------------------------------------
// HEARTBEAT submessage (RTPS 2.3 §9.4.5.5)
// ---------------------------------------------------------------------------

/// Parsed fields of a HEARTBEAT submessage. A reliable writer sends this
/// after every write and periodically, advertising the sequence-number
/// window currently retained in its send history. Matches go-DDS's
/// `Heartbeat` struct.
//fusa:req REQ-RTPS-043
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Heartbeat {
    pub reader_entity_id: EntityId,
    pub writer_entity_id: EntityId,
    /// Lowest sequence number still in the writer's history.
    pub first_sn: SequenceNumber,
    /// Highest sequence number sent so far.
    pub last_sn: SequenceNumber,
    /// Monotonically increasing per writer.
    pub count: i32,
}

/// Builds a full HEARTBEAT submessage (4-byte `SubmessageHeader` + 28-byte
/// body). Body layout (RTPS 2.3 §9.4.5.5): `readerId`(4) + `writerId`(4) +
/// `firstSN`(8) + `lastSN`(8) + `count`(4) = 28 bytes. Matches go-DDS's
/// `marshalHeartbeat` byte-for-byte.
//fusa:req REQ-RTPS-043
pub fn encode_heartbeat_submessage(hb: Heartbeat) -> Vec<u8> {
    let mut body = Vec::with_capacity(28);
    hb.reader_entity_id.encode(&mut body);
    hb.writer_entity_id.encode(&mut body);
    hb.first_sn.encode(&mut body);
    hb.last_sn.encode(&mut body);
    body.extend_from_slice(&hb.count.to_le_bytes());

    let mut out = Vec::with_capacity(SubmessageHeader::LEN + body.len());
    let header = SubmessageHeader {
        submessage_id: SUBMSG_HEARTBEAT,
        flags: FLAG_ENDIANNESS,
        octets_to_next_header: body.len() as u16,
    };
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// Decodes a `Heartbeat` from a HEARTBEAT submessage *body* (the bytes
/// after the 4-byte `SubmessageHeader`). Matches go-DDS's `parseHeartbeat`.
/// Never panics on truncated input (REQ-RTPS-009).
//fusa:req REQ-RTPS-043
//fusa:req REQ-RTPS-009
pub fn decode_heartbeat_submessage(body: &[u8]) -> Result<Heartbeat, RtpsDecodeError> {
    if body.len() < 28 {
        return Err(RtpsDecodeError::Truncated {
            expected: 28,
            got: body.len(),
        });
    }
    let reader_entity_id = EntityId::decode(&body[0..4])?;
    let writer_entity_id = EntityId::decode(&body[4..8])?;
    let first_sn = SequenceNumber::decode(&body[8..16])?;
    let last_sn = SequenceNumber::decode(&body[16..24])?;
    let count = i32::from_le_bytes([body[24], body[25], body[26], body[27]]);
    Ok(Heartbeat {
        reader_entity_id,
        writer_entity_id,
        first_sn,
        last_sn,
        count,
    })
}

// ---------------------------------------------------------------------------
// ACKNACK submessage (RTPS 2.3 §9.4.5.1)
// ---------------------------------------------------------------------------

/// Parsed fields of an ACKNACK submessage. A reliable reader sends this to
/// request retransmission of missing sequence numbers. Uses a fixed 32-bit
/// bitmap (`numBits` is always emitted as 32, one bitmap word), matching
/// go-DDS's `AckNack` struct.
//fusa:req REQ-RTPS-044
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckNack {
    pub reader_entity_id: EntityId,
    pub writer_entity_id: EntityId,
    /// First missing sequence number (the cumulative-ACK watermark).
    pub base: SequenceNumber,
    /// Bit N set means `base + N` is missing.
    pub bitmap: u32,
    pub count: i32,
}

/// Builds a full ACKNACK submessage (4-byte `SubmessageHeader` + 28-byte
/// body). Body layout (RTPS 2.3 §9.4.5.1): `readerId`(4) + `writerId`(4) +
/// `base`(8) + `numBits`(4, always 32) + `bitmap`(4) + `count`(4) = 28
/// bytes. Matches go-DDS's `marshalAckNack` byte-for-byte.
//fusa:req REQ-RTPS-044
pub fn encode_acknack_submessage(an: AckNack) -> Vec<u8> {
    let mut body = Vec::with_capacity(28);
    an.reader_entity_id.encode(&mut body);
    an.writer_entity_id.encode(&mut body);
    an.base.encode(&mut body);
    body.extend_from_slice(&32u32.to_le_bytes()); // numBits
    body.extend_from_slice(&an.bitmap.to_le_bytes());
    body.extend_from_slice(&an.count.to_le_bytes());

    let mut out = Vec::with_capacity(SubmessageHeader::LEN + body.len());
    let header = SubmessageHeader {
        submessage_id: SUBMSG_ACKNACK,
        flags: FLAG_ENDIANNESS,
        octets_to_next_header: body.len() as u16,
    };
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// Decodes an `AckNack` from an ACKNACK submessage *body* (the bytes after
/// the 4-byte `SubmessageHeader`). The `numBits` field (body[16..20]) is
/// ignored on decode — this crate, like go-DDS, always treats the bitmap as
/// exactly 32 bits. Matches go-DDS's `parseAckNack`. Never panics on
/// truncated input (REQ-RTPS-009).
//fusa:req REQ-RTPS-044
//fusa:req REQ-RTPS-009
pub fn decode_acknack_submessage(body: &[u8]) -> Result<AckNack, RtpsDecodeError> {
    if body.len() < 28 {
        return Err(RtpsDecodeError::Truncated {
            expected: 28,
            got: body.len(),
        });
    }
    let reader_entity_id = EntityId::decode(&body[0..4])?;
    let writer_entity_id = EntityId::decode(&body[4..8])?;
    let base = SequenceNumber::decode(&body[8..16])?;
    // body[16..20] = numBits — ignored, always treated as 32.
    let bitmap = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
    let count = i32::from_le_bytes([body[24], body[25], body[26], body[27]]);
    Ok(AckNack {
        reader_entity_id,
        writer_entity_id,
        base,
        bitmap,
        count,
    })
}

// ---------------------------------------------------------------------------
// GAP submessage (RTPS 2.3 §9.4.5.4)
// ---------------------------------------------------------------------------

/// Indicates a contiguous range of sequence numbers that are permanently
/// unavailable from a writer (evicted from its history). Receiving a GAP
/// tells a reader to advance its expected-SN watermark past the covered
/// range. Matches go-DDS's `Gap` struct.
///
/// Encode-only (like go-DDS itself, which sends GAP but never parses one
/// back on receipt — see `handleAckNack` in `participant.go`; no
/// `parseGAP`/`submsgGAP` case exists in go-DDS's own `handleDataPacket`
/// switch): a reliable reader that never receives its requested samples
/// falls back to re-NACKing on every subsequent periodic HEARTBEAT rather
/// than consuming a GAP directly, exactly mirroring go-DDS's own current
/// behavior (a documented parity decision, not a rust-DDS-only gap).
//fusa:req REQ-RTPS-045
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gap {
    pub reader_entity_id: EntityId,
    pub writer_entity_id: EntityId,
    /// First irrelevant sequence number (inclusive).
    pub gap_start: SequenceNumber,
    /// Last irrelevant sequence number (inclusive).
    pub gap_end: SequenceNumber,
}

/// Builds a full GAP submessage covering `[g.gap_start, g.gap_end]`
/// inclusive (4-byte `SubmessageHeader` + 28-byte body). Body layout
/// (RTPS 2.3 §9.4.5.4): `readerId`(4) + `writerId`(4) + `gapStart`(8) +
/// `gapList`(`bitmapBase`(8) + `numBits`(4)) = 28 bytes. `gapList`'s
/// `bitmapBase` is set to `gap_end.low + 1` with `numBits = 0` (no extra
/// bitmap words), so the contiguous gap `[gap_start, bitmapBase - 1]` =
/// `[gap_start, gap_end]` is declared. Matches go-DDS's `marshalGAP`
/// byte-for-byte.
//fusa:req REQ-RTPS-045
pub fn encode_gap_submessage(g: Gap) -> Vec<u8> {
    let mut body = Vec::with_capacity(28);
    g.reader_entity_id.encode(&mut body);
    g.writer_entity_id.encode(&mut body);
    g.gap_start.encode(&mut body);
    // gapList.bitmapBase = first SN *after* the gap = gap_end.low + 1.
    body.extend_from_slice(&g.gap_end.high.to_le_bytes());
    body.extend_from_slice(&g.gap_end.low.wrapping_add(1).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // numBits = 0, no bitmap words

    let mut out = Vec::with_capacity(SubmessageHeader::LEN + body.len());
    let header = SubmessageHeader {
        submessage_id: SUBMSG_GAP,
        flags: FLAG_ENDIANNESS,
        octets_to_next_header: body.len() as u16,
    };
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------------
// Submessage iteration (RTPS 2.3 §9.4.2)
// ---------------------------------------------------------------------------

/// A single raw (not-yet-interpreted) submessage: its 1-byte id, 1-byte
/// flags, and body bytes (the `octetsToNextHeader`-length slice following
/// its 4-byte `SubmessageHeader`).
//fusa:req REQ-RTPS-022
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSubmessage<'a> {
    pub id: u8,
    pub flags: u8,
    pub body: &'a [u8],
}

/// Iterates over the submessages in an RTPS message body (the bytes
/// immediately after the 20-byte [`Header`]). Matches go-DDS's
/// `parseSubmessages`: stops cleanly (no error) once fewer than 4 bytes
/// remain, but yields one `Err` — and then stops — if a submessage's
/// declared `octetsToNextHeader` length would run past the end of the
/// input. Never panics or indexes out of bounds on malformed input
/// (REQ-RTPS-009).
//fusa:req REQ-RTPS-022
//fusa:req REQ-RTPS-009
#[derive(Debug)]
pub struct SubmessageIter<'a> {
    body: &'a [u8],
    errored: bool,
}

impl<'a> SubmessageIter<'a> {
    /// Creates an iterator over `body`.
    //fusa:req REQ-RTPS-022
    pub fn new(body: &'a [u8]) -> Self {
        SubmessageIter {
            body,
            errored: false,
        }
    }
}

impl<'a> Iterator for SubmessageIter<'a> {
    type Item = Result<RawSubmessage<'a>, RtpsDecodeError>;

    //fusa:req REQ-RTPS-022
    //fusa:req REQ-RTPS-009
    fn next(&mut self) -> Option<Self::Item> {
        if self.errored || self.body.len() < 4 {
            return None;
        }
        let id = self.body[0];
        let flags = self.body[1];
        let mut length = u16::from_le_bytes([self.body[2], self.body[3]]) as usize;
        let rest = &self.body[4..];
        // RTPS 2.3 §9.4.5.1.3: an `octetsToNextHeader` of 0 on any
        // submessage other than PAD/INFO_TS means the submessage is the last
        // one in the message and extends to the end of the message. Treat a
        // zero length as "consume the remainder" so a conformant peer that
        // emits a final DATA/DATA_FRAG with length 0 is parsed correctly
        // instead of having its body silently discarded.
        //
        // PAD and INFO_TS are excluded: per §9.4.5.8, INFO_TS with the
        // Invalidate flag set has a genuine 0-byte body and is commonly NOT
        // the last submessage in the message, so extending it to consume
        // the remainder would wrongly swallow every submessage after it.
        // PAD messages are likewise legitimately empty and not necessarily
        // terminal.
        if length == 0 && id != SUBMSG_PAD && id != SUBMSG_INFO_TS {
            length = rest.len();
        }
        if length > rest.len() {
            self.errored = true;
            return Some(Err(RtpsDecodeError::Truncated {
                expected: length,
                got: rest.len(),
            }));
        }
        let (msg_body, remainder) = rest.split_at(length);
        self.body = remainder;
        Some(Ok(RawSubmessage {
            id,
            flags,
            body: msg_body,
        }))
    }
}

// ---------------------------------------------------------------------------
// Message wrapping
// ---------------------------------------------------------------------------

/// Prepends the 20-byte RTPS [`Header`] to already-encoded submessage bytes.
/// Matches go-DDS's `wrapInRTPSMessage`.
//fusa:req REQ-RTPS-023
pub fn wrap_in_rtps_message(header: Header, submessages: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(Header::LEN + submessages.len());
    header.encode(&mut out);
    out.extend_from_slice(submessages);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Reference bytes reproduced from go-DDS's actual rtps package. Go
    // reproduction (package-local scratch test file, never committed):
    //
    //   h := Header{
    //       ProtocolVersion: [2]byte{2, 3},
    //       VendorId:        [2]byte{0x01, 0x27},
    //       GuidPrefix:      prefix, // 0102030405060708090a0b0c
    //   }
    //   fmt.Printf("%x\n", marshalHeader(h))
    //   // -> 52545053020301270102030405060708090a0b0c
    //
    //   dataMsg := marshalDataSubmessage(EntityIdUnknown, EntityIdUnknown,
    //       SequenceNumber{High: 0, Low: 1}, nil)
    //   fmt.Printf("%x\n", dataMsg[:4])
    //   // -> 15051400   (id=DATA, flags=E|D, octetsToNextHeader=20)
    //
    //   hb := Heartbeat{ReaderEntityId: EntityIdUnknown, WriterEntityId: EntityIdSPDPWriter,
    //       FirstSN: SequenceNumber{High:0,Low:1}, LastSN: SequenceNumber{High:0,Low:5}, Count: 3}
    //   fmt.Printf("%x\n", marshalHeartbeat(hb)[:4])
    //   // -> 07011c00   (id=HEARTBEAT, flags=E, octetsToNextHeader=28)
    //
    //   sn := SequenceNumber{High: 1, Low: 42}
    //   buf := make([]byte, 8)
    //   binary.LittleEndian.PutUint32(buf[0:], uint32(sn.High))
    //   binary.LittleEndian.PutUint32(buf[4:], sn.Low)
    //   fmt.Printf("%x\n", buf)
    //   // -> 010000002a000000
    //
    //   fmt.Printf("%#x\n", snToU64(SequenceNumber{High: -1, Low: 0xFFFFFFFE}))
    //   // -> 0xfffffffffffffffe
    //   fmt.Printf("%+v\n", u64ToSN(0xfffffffffffffffe))
    //   // -> {High:-1 Low:0xfffffffe}
    //
    // Full run: `go test ./rtps/... -run TestZZReproWireBytes -v`
    // (go-DDS commit 1343891 / rust-DDS branch feat/rtps-wire-types).

    fn ascending_prefix() -> GuidPrefix {
        let mut b = [0u8; 12];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i + 1) as u8; // safe: i in [0,11], (i+1) in [1,12] fits u8
        }
        GuidPrefix(b)
    }

    //fusa:test REQ-RTPS-004
    //fusa:test REQ-RTPS-005
    #[test]
    fn protocol_version_and_vendor_id_raw_bytes() {
        let mut buf = Vec::new();
        PROTOCOL_VERSION_2_3.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "0203");

        buf.clear();
        VendorId([0x01, 0x27]).encode(&mut buf); // go-DDS's own vendor id value
        assert_eq!(hex::encode(&buf), "0127");

        buf.clear();
        VENDOR_ID_RUST_DDS.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "0128");
        assert_ne!(VENDOR_ID_RUST_DDS, VendorId([0x01, 0x27]));
    }

    //fusa:test REQ-RTPS-008
    #[test]
    fn header_matches_go_dds_reference() {
        let h = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: VendorId([0x01, 0x27]),
            guid_prefix: ascending_prefix(),
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(
            hex::encode(&buf),
            "52545053020301270102030405060708090a0b0c"
        );
        assert_eq!(buf.len(), Header::LEN);
        assert_eq!(&buf[0..4], b"RTPS");
    }

    //fusa:test REQ-RTPS-008
    #[test]
    fn header_round_trip() {
        let h = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: VENDOR_ID_RUST_DDS,
            guid_prefix: ascending_prefix(),
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(Header::decode(&buf).unwrap(), h);
    }

    //fusa:test REQ-RTPS-008
    //fusa:test REQ-RTPS-009
    #[test]
    fn header_decode_rejects_bad_magic() {
        let mut buf = vec![b'X', b'X', b'X', b'X'];
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(Header::decode(&buf), Err(RtpsDecodeError::BadMagic));
    }

    //fusa:test REQ-RTPS-010
    #[test]
    fn submessage_header_data_matches_go_dds_reference() {
        // id=DATA, flags=E|D, octetsToNextHeader=20 (the DATA body length
        // for an empty payload — see marshalDataSubmessage in message.go).
        let sh = SubmessageHeader {
            submessage_id: SUBMSG_DATA,
            flags: FLAG_ENDIANNESS | FLAG_DATA,
            octets_to_next_header: 20,
        };
        let mut buf = Vec::new();
        sh.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "15051400");
    }

    //fusa:test REQ-RTPS-010
    #[test]
    fn submessage_header_heartbeat_matches_go_dds_reference() {
        // id=HEARTBEAT, flags=E, octetsToNextHeader=28.
        let sh = SubmessageHeader {
            submessage_id: SUBMSG_HEARTBEAT,
            flags: FLAG_ENDIANNESS,
            octets_to_next_header: 28,
        };
        let mut buf = Vec::new();
        sh.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "07011c00");
        assert_eq!(SUBMSG_GAP, 0x08);
        assert_eq!(SUBMSG_ACKNACK, 0x06);
        assert_eq!(SUBMSG_INFO_TS, 0x09);
        assert_eq!(FLAG_INLINE_QOS, 0x02);
    }

    //fusa:test REQ-RTPS-010
    #[test]
    fn submessage_header_round_trip() {
        let sh = SubmessageHeader {
            submessage_id: SUBMSG_ACKNACK,
            flags: FLAG_ENDIANNESS,
            octets_to_next_header: 28,
        };
        let mut buf = Vec::new();
        sh.encode(&mut buf);
        assert_eq!(SubmessageHeader::decode(&buf).unwrap(), sh);
    }

    //fusa:test REQ-RTPS-006
    #[test]
    fn sequence_number_matches_go_dds_reference() {
        let sn = SequenceNumber { high: 1, low: 42 };
        let mut buf = Vec::new();
        sn.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "010000002a000000");
    }

    //fusa:test REQ-RTPS-006
    //fusa:test REQ-RTPS-009
    #[test]
    fn sequence_number_round_trip_and_truncation() {
        let sn = SequenceNumber {
            high: 7,
            low: 0xDEADBEEF,
        };
        let mut buf = Vec::new();
        sn.encode(&mut buf);
        assert_eq!(SequenceNumber::decode(&buf).unwrap(), sn);
        assert_eq!(
            SequenceNumber::decode(&buf[..7]),
            Err(RtpsDecodeError::Truncated {
                expected: 8,
                got: 7
            })
        );
    }

    //fusa:test REQ-RTPS-007
    #[test]
    fn sequence_number_u64_packing_matches_go_dds_reference() {
        // High:-1, Low:0xFFFFFFFE — deliberately exercises the 32-bit
        // wraparound-aliasing case snToU64/to_u64 exists to avoid.
        let sn = SequenceNumber {
            high: -1,
            low: 0xFFFFFFFE,
        };
        assert_eq!(sn.to_u64(), 0xFFFF_FFFF_FFFF_FFFE);
        let back = SequenceNumber::from_u64(0xFFFF_FFFF_FFFF_FFFE);
        assert_eq!(back.high, -1);
        assert_eq!(back.low, 0xFFFFFFFE);
        assert_eq!(back, sn);
    }

    //fusa:test REQ-RTPS-007
    #[test]
    fn sequence_number_u64_round_trip_ordinary_values() {
        let sn = SequenceNumber { high: 0, low: 5 };
        assert_eq!(sn.to_u64(), 5);
        assert_eq!(SequenceNumber::from_u64(5), sn);
    }

    // Reference bytes reproduced from go-DDS's actual rtps package (real
    // marshalDataSubmessage/wrapInRTPSMessage/parseDataSubmessage/
    // parseSubmessages, not reimplemented). Go reproduction (package-local
    // scratch test file, `rtps/zzrepro_message2_test.go`, never committed to
    // go-DDS, deleted after use):
    //
    //   var prefix GuidPrefix
    //   for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    //
    //   payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
    //   submsg := marshalDataSubmessage(EntityIdSPDPWriter, EntityIdSPDPReader,
    //       SequenceNumber{High: 0, Low: 7}, payload)
    //   fmt.Printf("%x\n", submsg)
    //   // -> 1505190000001000000100c7000100c20000000007000000aabbccddee
    //
    //   fmt.Printf("%x\n", wrapInRTPSMessage(prefix, submsg))
    //   // -> 52545053020301270102030405060708090a0b0c1505190000001000000100
    //   //    c7000100c20000000007000000aabbccddee
    //
    //   ds, ok := parseDataSubmessage(flagEndianness|flagData, submsg[4:])
    //   // ok=true readerEID=000100c7 writerEID=000100c2 seq={0 7} payload=aabbccddee
    //
    //   submsg2 := marshalDataSubmessage(EntityIdSEDPPubWriter, EntityIdSEDPPubReader,
    //       SequenceNumber{High: 0, Low: 8}, nil)
    //   both := append(append([]byte{}, submsg...), submsg2...)
    //   count := 0
    //   parseSubmessages(both, func(id, flags byte, body []byte) error {
    //       fmt.Printf("id=%#x flags=%#x bodylen=%d\n", id, flags, len(body))
    //       count++
    //       return nil
    //   })
    //   // submsg[0]: id=0x15 flags=0x5 bodylen=25
    //   // submsg[1]: id=0x15 flags=0x5 bodylen=20
    //   // count = 2
    //
    // Full run: `go test ./rtps/... -run TestZZReproMessageFramingBytes -v`
    // (go-DDS commit 3329f86 / rust-DDS branch feat/rtps-spdp).

    //fusa:test REQ-RTPS-021
    #[test]
    fn encode_data_submessage_matches_go_dds_reference() {
        use crate::rtps::guid::{ENTITYID_SPDP_READER, ENTITYID_SPDP_WRITER};

        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 7 },
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        );
        assert_eq!(
            hex::encode(&submsg),
            "1505190000001000000100c7000100c20000000007000000aabbccddee"
        );
    }

    //fusa:test REQ-RTPS-023
    #[test]
    fn wrap_in_rtps_message_matches_go_dds_reference() {
        use crate::rtps::guid::{ENTITYID_SPDP_READER, ENTITYID_SPDP_WRITER};

        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 7 },
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        );
        let header = Header {
            protocol_version: PROTOCOL_VERSION_2_3,
            vendor_id: VendorId([0x01, 0x27]), // go-DDS's own vendor id, for byte-exact parity
            guid_prefix: ascending_prefix(),
        };
        let msg = wrap_in_rtps_message(header, &submsg);
        assert_eq!(
            hex::encode(&msg),
            concat!(
                "52545053020301270102030405060708090a0b0c",
                "1505190000001000000100c7000100c20000000007000000aabbccddee",
            )
        );
    }

    //fusa:test REQ-RTPS-021
    #[test]
    fn decode_data_submessage_matches_go_dds_reference() {
        use crate::rtps::guid::{ENTITYID_SPDP_READER, ENTITYID_SPDP_WRITER};

        let submsg =
            hex::decode("1505190000001000000100c7000100c20000000007000000aabbccddee").unwrap();
        let ds = decode_data_submessage(FLAG_ENDIANNESS | FLAG_DATA, &submsg[4..]).unwrap();
        assert_eq!(ds.reader_entity_id, ENTITYID_SPDP_READER);
        assert_eq!(ds.writer_entity_id, ENTITYID_SPDP_WRITER);
        assert_eq!(ds.seq_num, SequenceNumber { high: 0, low: 7 });
        assert_eq!(ds.payload, Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));
    }

    //fusa:test REQ-RTPS-021
    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_data_submessage_rejects_truncated_input_without_panicking() {
        assert_eq!(
            decode_data_submessage(FLAG_ENDIANNESS | FLAG_DATA, &[0u8; 19]),
            Err(RtpsDecodeError::Truncated {
                expected: 20,
                got: 19
            })
        );
    }

    //fusa:test REQ-RTPS-021
    #[test]
    fn data_submessage_round_trip() {
        use crate::rtps::guid::{ENTITYID_SEDP_PUB_READER, ENTITYID_SEDP_PUB_WRITER};

        let submsg = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            SequenceNumber { high: 3, low: 99 },
            &[0x01, 0x02, 0x03],
        );
        let sh = SubmessageHeader::decode(&submsg).unwrap();
        let ds = decode_data_submessage(sh.flags, &submsg[SubmessageHeader::LEN..]).unwrap();
        assert_eq!(ds.reader_entity_id, ENTITYID_SEDP_PUB_READER);
        assert_eq!(ds.writer_entity_id, ENTITYID_SEDP_PUB_WRITER);
        assert_eq!(ds.seq_num, SequenceNumber { high: 3, low: 99 });
        assert_eq!(ds.payload, Some(vec![0x01, 0x02, 0x03]));
    }

    //fusa:test REQ-RTPS-021
    #[test]
    fn data_submessage_with_no_payload_has_none_payload() {
        use crate::rtps::guid::ENTITYID_UNKNOWN;

        let submsg = encode_data_submessage(
            ENTITYID_UNKNOWN,
            ENTITYID_UNKNOWN,
            SequenceNumber { high: 0, low: 1 },
            &[],
        );
        // id=DATA, flags=E|D, octetsToNextHeader=20 — matches the doc
        // comment above `submessage_header_data_matches_go_dds_reference`.
        assert_eq!(&submsg[..4], hex::decode("15051400").unwrap().as_slice());
        let ds = decode_data_submessage(FLAG_ENDIANNESS | FLAG_DATA, &submsg[4..]).unwrap();
        assert_eq!(ds.payload, None);
    }

    //fusa:test REQ-RTPS-022
    #[test]
    fn submessage_iter_matches_go_dds_reference() {
        use crate::rtps::guid::{
            ENTITYID_SEDP_PUB_READER, ENTITYID_SEDP_PUB_WRITER, ENTITYID_SPDP_READER,
            ENTITYID_SPDP_WRITER,
        };

        let submsg1 = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 7 },
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        );
        let submsg2 = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            SequenceNumber { high: 0, low: 8 },
            &[],
        );
        let mut both = submsg1.clone();
        both.extend_from_slice(&submsg2);

        let parsed: Vec<_> = SubmessageIter::new(&both)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, SUBMSG_DATA);
        assert_eq!(parsed[0].flags, 0x5);
        assert_eq!(parsed[0].body.len(), 25);
        assert_eq!(parsed[1].id, SUBMSG_DATA);
        assert_eq!(parsed[1].flags, 0x5);
        assert_eq!(parsed[1].body.len(), 20);
    }

    // Reference bytes reproduced from go-DDS's actual rtps package (real
    // marshalHeartbeat/marshalAckNack/marshalGAP/parseHeartbeat/parseAckNack,
    // not reimplemented). Go reproduction (package-local scratch test file,
    // `rtps/zzrepro_reliable_test.go`, never committed to go-DDS, deleted
    // after use):
    //
    //   readerEID := EntityIdUnknown
    //   writerEID := entityIdForWriter(1) // -> 00000103
    //
    //   hb := Heartbeat{ReaderEntityId: readerEID, WriterEntityId: writerEID,
    //       FirstSN: SequenceNumber{High: 0, Low: 1},
    //       LastSN:  SequenceNumber{High: 0, Low: 5}, Count: 3}
    //   fmt.Printf("%x\n", marshalHeartbeat(hb))
    //   // -> 07011c0000000000000001030000000001000000000000000500000003000000
    //
    //   an := AckNack{ReaderEntityId: entityIdForReader(2), WriterEntityId: writerEID,
    //       Base: SequenceNumber{High: 0, Low: 3}, Bitmap: 0b101, Count: 7}
    //   fmt.Printf("%x\n", marshalAckNack(an))
    //   // -> 06011c0000000204000001030000000003000000200000000500000007000000
    //
    //   g := Gap{ReaderEntityId: entityIdForReader(2), WriterEntityId: writerEID,
    //       GapStart: SequenceNumber{High: 0, Low: 1}, GapEnd: SequenceNumber{High: 0, Low: 4}}
    //   fmt.Printf("%x\n", marshalGAP(g))
    //   // -> 08011c0000000204000001030000000001000000000000000500000000000000
    //
    //   hbParsed, ok := parseHeartbeat(hbMsg[4:])
    //   // ok=true {ReaderEntityId:00000000 WriterEntityId:00000103 FirstSN:{0 1} LastSN:{0 5} Count:3}
    //   anParsed, ok := parseAckNack(anMsg[4:])
    //   // ok=true {ReaderEntityId:00000204 WriterEntityId:00000103 Base:{0 3} Bitmap:5 Count:7}
    //
    // Full run: `go test ./rtps/... -run TestZZReproReliableBytes -v`
    // (go-DDS commit e9b36f5 / rust-DDS branch feat/rtps-reliable-qos).

    //fusa:test REQ-RTPS-043
    #[test]
    fn encode_heartbeat_submessage_matches_go_dds_reference() {
        use crate::rtps::guid::ENTITYID_UNKNOWN;

        let hb = Heartbeat {
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_entity_id: crate::rtps::guid::entity_id_for_writer(1),
            first_sn: SequenceNumber { high: 0, low: 1 },
            last_sn: SequenceNumber { high: 0, low: 5 },
            count: 3,
        };
        let msg = encode_heartbeat_submessage(hb);
        assert_eq!(
            hex::encode(&msg),
            "07011c0000000000000001030000000001000000000000000500000003000000"
        );
        assert_eq!(msg.len(), 32);
    }

    //fusa:test REQ-RTPS-043
    #[test]
    fn heartbeat_round_trip() {
        use crate::rtps::guid::ENTITYID_UNKNOWN;

        let hb = Heartbeat {
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_entity_id: crate::rtps::guid::entity_id_for_writer(1),
            first_sn: SequenceNumber { high: 0, low: 1 },
            last_sn: SequenceNumber { high: 0, low: 5 },
            count: 3,
        };
        let msg = encode_heartbeat_submessage(hb);
        let decoded = decode_heartbeat_submessage(&msg[SubmessageHeader::LEN..]).unwrap();
        assert_eq!(decoded, hb);
    }

    //fusa:test REQ-RTPS-043
    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_heartbeat_submessage_rejects_truncated_input_without_panicking() {
        assert_eq!(
            decode_heartbeat_submessage(&[0u8; 27]),
            Err(RtpsDecodeError::Truncated {
                expected: 28,
                got: 27
            })
        );
    }

    //fusa:test REQ-RTPS-044
    #[test]
    fn encode_acknack_submessage_matches_go_dds_reference() {
        let an = AckNack {
            reader_entity_id: crate::rtps::guid::entity_id_for_reader(2),
            writer_entity_id: crate::rtps::guid::entity_id_for_writer(1),
            base: SequenceNumber { high: 0, low: 3 },
            bitmap: 0b101,
            count: 7,
        };
        let msg = encode_acknack_submessage(an);
        assert_eq!(
            hex::encode(&msg),
            "06011c0000000204000001030000000003000000200000000500000007000000"
        );
        assert_eq!(msg.len(), 32);
    }

    //fusa:test REQ-RTPS-044
    #[test]
    fn acknack_round_trip() {
        let an = AckNack {
            reader_entity_id: crate::rtps::guid::entity_id_for_reader(2),
            writer_entity_id: crate::rtps::guid::entity_id_for_writer(1),
            base: SequenceNumber { high: 0, low: 3 },
            bitmap: 0b101,
            count: 7,
        };
        let msg = encode_acknack_submessage(an);
        let decoded = decode_acknack_submessage(&msg[SubmessageHeader::LEN..]).unwrap();
        assert_eq!(decoded, an);
    }

    //fusa:test REQ-RTPS-044
    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_acknack_submessage_rejects_truncated_input_without_panicking() {
        assert_eq!(
            decode_acknack_submessage(&[0u8; 10]),
            Err(RtpsDecodeError::Truncated {
                expected: 28,
                got: 10
            })
        );
    }

    //fusa:test REQ-RTPS-045
    #[test]
    fn encode_gap_submessage_matches_go_dds_reference() {
        let g = Gap {
            reader_entity_id: crate::rtps::guid::entity_id_for_reader(2),
            writer_entity_id: crate::rtps::guid::entity_id_for_writer(1),
            gap_start: SequenceNumber { high: 0, low: 1 },
            gap_end: SequenceNumber { high: 0, low: 4 },
        };
        let msg = encode_gap_submessage(g);
        assert_eq!(
            hex::encode(&msg),
            "08011c0000000204000001030000000001000000000000000500000000000000"
        );
        assert_eq!(msg.len(), 32);
    }

    //fusa:test REQ-RTPS-022
    #[test]
    fn submessage_iter_stops_cleanly_below_four_bytes() {
        let parsed: Vec<_> = SubmessageIter::new(&[0x01, 0x02, 0x03]).collect();
        assert!(parsed.is_empty());
        let parsed: Vec<_> = SubmessageIter::new(&[]).collect();
        assert!(parsed.is_empty());
    }

    //fusa:test REQ-RTPS-022
    //fusa:test REQ-RTPS-009
    #[test]
    fn submessage_iter_yields_error_and_stops_on_length_past_end_without_panicking() {
        let mut buf = vec![SUBMSG_DATA, FLAG_ENDIANNESS, 0xFF, 0xFF]; // claims 65535 bytes
        buf.extend_from_slice(&[0x01, 0x02]); // but only 2 remain
        let mut iter = SubmessageIter::new(&buf);
        assert_eq!(
            iter.next(),
            Some(Err(RtpsDecodeError::Truncated {
                expected: 0xFFFF,
                got: 2
            }))
        );
        assert_eq!(iter.next(), None);
    }

    // RTPS 2.3 §9.4.5.1.3: a non-PAD/INFO_TS submessage with
    // octetsToNextHeader==0 is the last submessage in the Message and its
    // body extends to the end of the Message, rather than being treated as
    // an empty (0-byte) body followed by more submessages parsed out of its
    // own payload bytes.
    //fusa:test REQ-RTPS-022
    #[test]
    fn submessage_iter_extends_zero_length_data_to_end_of_message() {
        // id=DATA, flags=E, octetsToNextHeader=0, followed by 6 bytes of
        // payload that must NOT be reinterpreted as further submessages.
        let mut buf = vec![SUBMSG_DATA, FLAG_ENDIANNESS, 0x00, 0x00];
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let parsed: Vec<_> = SubmessageIter::new(&buf)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, SUBMSG_DATA);
        assert_eq!(parsed[0].body, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF][..]);
    }

    // PAD is explicitly excluded from the "extend to end" rule: a 0-length
    // PAD is a genuine empty submessage and must not swallow the
    // submessages that follow it.
    //fusa:test REQ-RTPS-022
    #[test]
    fn submessage_iter_does_not_extend_zero_length_pad() {
        let mut buf = vec![SUBMSG_PAD, FLAG_ENDIANNESS, 0x00, 0x00];
        // A second, real submessage that must still be parsed as its own
        // entry rather than being consumed as PAD's "remainder" body.
        let submsg2 = encode_data_submessage(
            crate::rtps::guid::ENTITYID_UNKNOWN,
            crate::rtps::guid::ENTITYID_UNKNOWN,
            SequenceNumber { high: 0, low: 1 },
            &[],
        );
        buf.extend_from_slice(&submsg2);

        let parsed: Vec<_> = SubmessageIter::new(&buf)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, SUBMSG_PAD);
        assert!(parsed[0].body.is_empty());
        assert_eq!(parsed[1].id, SUBMSG_DATA);
    }

    // INFO_TS is likewise excluded: per §9.4.5.8, INFO_TS with the
    // Invalidate flag set legitimately has a 0-byte body and is commonly
    // NOT the last submessage in the Message.
    //fusa:test REQ-RTPS-022
    #[test]
    fn submessage_iter_does_not_extend_zero_length_info_ts() {
        let mut buf = vec![SUBMSG_INFO_TS, FLAG_ENDIANNESS, 0x00, 0x00];
        let submsg2 = encode_data_submessage(
            crate::rtps::guid::ENTITYID_UNKNOWN,
            crate::rtps::guid::ENTITYID_UNKNOWN,
            SequenceNumber { high: 0, low: 1 },
            &[],
        );
        buf.extend_from_slice(&submsg2);

        let parsed: Vec<_> = SubmessageIter::new(&buf)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, SUBMSG_INFO_TS);
        assert!(parsed[0].body.is_empty());
        assert_eq!(parsed[1].id, SUBMSG_DATA);
    }
}
