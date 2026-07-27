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

use super::guid::GuidPrefix;
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
}
