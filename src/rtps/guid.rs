// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `GuidPrefix`, `EntityId`, and `GUID` — RTPS 2.3 §9.3.1.
//!
//! Wire layout ported 1:1 from go-DDS's `rtps/guid.go` (the ecosystem's
//! RTPS correctness oracle, see `ROADMAP.md` Tier 1). A `GuidPrefix` is the
//! 12-byte participant identifier; an `EntityId` is the 4-byte identifier
//! of an endpoint within that participant; a `GUID` is their 16-byte
//! concatenation (prefix bytes first, then entity bytes) with no separator
//! or length prefix.

use super::RtpsDecodeError;

// ---------------------------------------------------------------------------
// GuidPrefix
// ---------------------------------------------------------------------------

/// 12-byte participant identifier (RTPS 2.3 §9.3.1).
//fusa:req REQ-RTPS-001
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidPrefix(pub [u8; 12]);

impl GuidPrefix {
    /// Wire size in bytes.
    pub const LEN: usize = 12;

    /// Append the 12-byte wire encoding of this `GuidPrefix` to `buf`.
    //fusa:req REQ-RTPS-001
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    /// Decode a `GuidPrefix` from the first 12 bytes of `buf`.
    ///
    /// Returns `Err(RtpsDecodeError::Truncated)` — never panics — if `buf`
    /// is shorter than [`GuidPrefix::LEN`].
    //fusa:req REQ-RTPS-001
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        let mut b = [0u8; 12];
        b.copy_from_slice(&buf[..Self::LEN]);
        Ok(GuidPrefix(b))
    }
}

/// Generates a process-unique `GuidPrefix` for a live network participant:
/// 8 random bytes followed by this process's PID (4 bytes, little-endian) —
/// matches go-DDS's `newGuidPrefix` (`rtps/guid.go`) byte-for-byte layout,
/// though rust-DDS uses `rand`'s default (non-cryptographic) generator
/// rather than `crypto/rand`, since this assignment only needs to be
/// distinct enough across concurrently-running participants on one host,
/// not unguessable — go-DDS's own doc comment for `newGuidPrefix` makes the
/// same "distinguish the participant" claim, not a security one. Used by
/// [`super::dds_participant::RtpsUdpParticipant::new`]; every existing
/// internal test in this module tree instead uses a fixed prefix (see
/// `participant.rs::tests::ascending_prefix`), since deterministic test
/// output matters more there than realistic identity assignment.
//fusa:req REQ-GUID-001
//fusa:req REQ-GUID-002
pub(crate) fn random_guid_prefix() -> GuidPrefix {
    let mut bytes = [0u8; 12];
    let random_part: [u8; 8] = rand::random();
    bytes[..8].copy_from_slice(&random_part);
    bytes[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    GuidPrefix(bytes)
}

// ---------------------------------------------------------------------------
// EntityId
// ---------------------------------------------------------------------------

/// Identifies a specific endpoint within a participant (RTPS 2.3 §9.3.1).
//fusa:req REQ-RTPS-001
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EntityId(pub [u8; 4]);

impl EntityId {
    /// Wire size in bytes.
    pub const LEN: usize = 4;

    /// Append the 4-byte wire encoding of this `EntityId` to `buf`.
    //fusa:req REQ-RTPS-001
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    /// Decode an `EntityId` from the first 4 bytes of `buf`.
    //fusa:req REQ-RTPS-001
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&buf[..Self::LEN]);
        Ok(EntityId(b))
    }
}

// Well-known entity IDs per RTPS 2.3 Table 9.1, mirroring go-DDS's
// `rtps/guid.go` exactly (same byte values, same names modulo Rust casing).
//fusa:req REQ-RTPS-002
pub const ENTITYID_PARTICIPANT: EntityId = EntityId([0x00, 0x00, 0x01, 0xC1]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_SPDP_WRITER: EntityId = EntityId([0x00, 0x01, 0x00, 0xC2]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_SPDP_READER: EntityId = EntityId([0x00, 0x01, 0x00, 0xC7]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_SEDP_PUB_WRITER: EntityId = EntityId([0x00, 0x00, 0x03, 0xC2]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_SEDP_PUB_READER: EntityId = EntityId([0x00, 0x00, 0x03, 0xC7]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_SEDP_SUB_WRITER: EntityId = EntityId([0x00, 0x00, 0x04, 0xC2]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_SEDP_SUB_READER: EntityId = EntityId([0x00, 0x00, 0x04, 0xC7]);
//fusa:req REQ-RTPS-002
pub const ENTITYID_UNKNOWN: EntityId = EntityId([0x00, 0x00, 0x00, 0x00]);

// Builtin endpoint availability bitmask (RTPS 2.3 §8.5.4.3 / §9.6.2.2),
// carried in an SPDP ParticipantProxy's `PID_BUILTIN_ENDPOINT_SET`
// parameter. Matches go-DDS's `rtps/guid.go` exactly (same bit positions).
//fusa:req REQ-RTPS-024
pub const ENDPOINT_SPDP_ANNOUNCER: u32 = 1 << 0;
//fusa:req REQ-RTPS-024
pub const ENDPOINT_SPDP_DETECTOR: u32 = 1 << 1;
//fusa:req REQ-RTPS-024
pub const ENDPOINT_SEDP_PUB_ANNOUNCER: u32 = 1 << 2;
//fusa:req REQ-RTPS-024
pub const ENDPOINT_SEDP_PUB_DETECTOR: u32 = 1 << 3;
//fusa:req REQ-RTPS-024
pub const ENDPOINT_SEDP_SUB_ANNOUNCER: u32 = 1 << 4;
//fusa:req REQ-RTPS-024
pub const ENDPOINT_SEDP_SUB_DETECTOR: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------

/// Globally identifies a DDS entity: participant + endpoint (16 bytes).
///
/// Wire layout: `prefix` (12 bytes) followed by `entity` (4 bytes), no
/// separator — matches go-DDS's `GUID{Prefix, Entity}` field order.
//fusa:req REQ-RTPS-001
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Guid {
    pub prefix: GuidPrefix,
    pub entity: EntityId,
}

impl Guid {
    /// Wire size in bytes.
    pub const LEN: usize = GuidPrefix::LEN + EntityId::LEN;

    /// Append the 16-byte wire encoding of this `Guid` to `buf`.
    //fusa:req REQ-RTPS-001
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.prefix.encode(buf);
        self.entity.encode(buf);
    }

    /// Decode a `Guid` from the first 16 bytes of `buf`.
    //fusa:req REQ-RTPS-001
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        let prefix = GuidPrefix::decode(&buf[..GuidPrefix::LEN])?;
        let entity = EntityId::decode(&buf[GuidPrefix::LEN..Self::LEN])?;
        Ok(Guid { prefix, entity })
    }

    /// Flattens this `Guid` into the plain 16-byte array shape used by
    /// [`crate::types::Sample::writer_guid`] (`prefix` bytes first, then
    /// `entity` bytes — the same field order as [`Guid::encode`]). Matches
    /// go-DDS's `dispatchToReaders`'s
    /// `copy(writerDDS[:12], source.Prefix[:]); copy(writerDDS[12:],
    /// source.Entity[:])`.
    //fusa:req REQ-RTPS-036
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..GuidPrefix::LEN].copy_from_slice(&self.prefix.0);
        out[GuidPrefix::LEN..].copy_from_slice(&self.entity.0);
        out
    }
}

// ---------------------------------------------------------------------------
// User-defined entity ID assignment (RTPS 2.3 §9.3.1.2 "no key" kinds)
// ---------------------------------------------------------------------------

/// Builds a user-defined writer `EntityId` from a per-participant, strictly
/// increasing counter `n` (the caller is expected to start `n` at 1 and
/// never reuse a value). Entity-kind octet `0x03` ("no key" writer),
/// matching go-DDS's `entityIdForWriter` byte-for-byte:
/// `EntityId{byte(n>>16), byte(n>>8), byte(n), 0x03}`.
//fusa:req REQ-RTPS-036
pub fn entity_id_for_writer(n: u32) -> EntityId {
    EntityId([(n >> 16) as u8, (n >> 8) as u8, n as u8, 0x03])
}

/// Builds a user-defined reader `EntityId` from a per-participant, strictly
/// increasing counter `n`. Entity-kind octet `0x04` ("no key" reader),
/// matching go-DDS's `entityIdForReader` byte-for-byte.
//fusa:req REQ-RTPS-036
pub fn entity_id_for_reader(n: u32) -> EntityId {
    EntityId([(n >> 16) as u8, (n >> 8) as u8, n as u8, 0x04])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-GUID-001
    //fusa:test REQ-GUID-002
    #[test]
    fn random_guid_prefix_embeds_this_process_pid_and_varies() {
        let a = random_guid_prefix();
        let b = random_guid_prefix();
        let pid_bytes = std::process::id().to_le_bytes();
        assert_eq!(&a.0[8..12], &pid_bytes[..]);
        assert_eq!(&b.0[8..12], &pid_bytes[..]);
        // The random first 8 bytes differ between two independent calls
        // (astronomically unlikely to collide by chance — not a flaky
        // assertion in practice).
        assert_ne!(&a.0[..8], &b.0[..8]);
    }

    // Reference bytes reproduced from go-DDS's actual rtps package. Go
    // reproduction (run from a go-DDS checkout, package-local scratch test
    // file, never committed):
    //
    //   var prefix GuidPrefix
    //   for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    //   fmt.Printf("%x\n", prefix[:])
    //   // -> 0102030405060708090a0b0c
    //
    //   fmt.Printf("%x\n", EntityIdParticipant[:]) // -> 000001c1
    //   fmt.Printf("%x\n", EntityIdSPDPWriter[:])  // -> 000100c2
    //   fmt.Printf("%x\n", EntityIdSPDPReader[:])  // -> 000100c7
    //   fmt.Printf("%x\n", EntityIdUnknown[:])     // -> 00000000
    //
    //   guidBytes := append(append([]byte{}, prefix[:]...), EntityIdParticipant[:]...)
    //   fmt.Printf("%x\n", guidBytes)
    //   // -> 0102030405060708090a0b0c000001c1
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

    //fusa:test REQ-RTPS-001
    #[test]
    fn guid_prefix_matches_go_dds_reference() {
        let mut buf = Vec::new();
        ascending_prefix().encode(&mut buf);
        assert_eq!(hex::encode(&buf), "0102030405060708090a0b0c");
    }

    //fusa:test REQ-RTPS-001
    //fusa:test REQ-RTPS-002
    #[test]
    fn well_known_entity_ids_match_go_dds_reference() {
        let mut buf = Vec::new();
        ENTITYID_PARTICIPANT.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "000001c1");

        buf.clear();
        ENTITYID_SPDP_WRITER.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "000100c2");

        buf.clear();
        ENTITYID_SPDP_READER.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "000100c7");

        buf.clear();
        ENTITYID_UNKNOWN.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "00000000");

        // Every well-known constant round-trips through decode too.
        for eid in [
            ENTITYID_PARTICIPANT,
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            ENTITYID_SEDP_SUB_WRITER,
            ENTITYID_SEDP_SUB_READER,
            ENTITYID_UNKNOWN,
        ] {
            let mut b = Vec::new();
            eid.encode(&mut b);
            assert_eq!(EntityId::decode(&b).unwrap(), eid);
        }
    }

    //fusa:test REQ-RTPS-001
    #[test]
    fn guid_matches_go_dds_reference() {
        let g = Guid {
            prefix: ascending_prefix(),
            entity: ENTITYID_PARTICIPANT,
        };
        let mut buf = Vec::new();
        g.encode(&mut buf);
        assert_eq!(hex::encode(&buf), "0102030405060708090a0b0c000001c1");
        assert_eq!(buf.len(), Guid::LEN);
    }

    //fusa:test REQ-RTPS-001
    #[test]
    fn guid_round_trip() {
        let g = Guid {
            prefix: ascending_prefix(),
            entity: ENTITYID_SEDP_SUB_READER,
        };
        let mut buf = Vec::new();
        g.encode(&mut buf);
        let decoded = Guid::decode(&buf).unwrap();
        assert_eq!(decoded, g);
    }

    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_rejects_truncated_input_without_panicking() {
        assert_eq!(
            GuidPrefix::decode(&[0u8; 11]),
            Err(RtpsDecodeError::Truncated {
                expected: 12,
                got: 11
            })
        );
        assert_eq!(
            EntityId::decode(&[0u8; 3]),
            Err(RtpsDecodeError::Truncated {
                expected: 4,
                got: 3
            })
        );
        assert_eq!(
            Guid::decode(&[0u8; 15]),
            Err(RtpsDecodeError::Truncated {
                expected: 16,
                got: 15
            })
        );
    }

    //fusa:test REQ-RTPS-001
    #[test]
    fn decode_ignores_trailing_bytes() {
        // Mirrors go-DDS's own tolerance: unmarshal only reads the fixed
        // wire width and ignores anything after it.
        let mut buf = Vec::new();
        ENTITYID_PARTICIPANT.encode(&mut buf);
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(EntityId::decode(&buf).unwrap(), ENTITYID_PARTICIPANT);
    }

    //fusa:test REQ-RTPS-024
    #[test]
    fn builtin_endpoint_bitmask_matches_go_dds_reference() {
        // Bit positions ported 1:1 from go-DDS's rtps/guid.go; a
        // ParticipantProxy advertising all six SPDP+SEDP builtin endpoints
        // encodes PID_BUILTIN_ENDPOINT_SET = 0x3f, matching the value used
        // throughout this crate's SPDP/CDR reference tests.
        assert_eq!(ENDPOINT_SPDP_ANNOUNCER, 0x01);
        assert_eq!(ENDPOINT_SPDP_DETECTOR, 0x02);
        assert_eq!(ENDPOINT_SEDP_PUB_ANNOUNCER, 0x04);
        assert_eq!(ENDPOINT_SEDP_PUB_DETECTOR, 0x08);
        assert_eq!(ENDPOINT_SEDP_SUB_ANNOUNCER, 0x10);
        assert_eq!(ENDPOINT_SEDP_SUB_DETECTOR, 0x20);
        let all = ENDPOINT_SPDP_ANNOUNCER
            | ENDPOINT_SPDP_DETECTOR
            | ENDPOINT_SEDP_PUB_ANNOUNCER
            | ENDPOINT_SEDP_PUB_DETECTOR
            | ENDPOINT_SEDP_SUB_ANNOUNCER
            | ENDPOINT_SEDP_SUB_DETECTOR;
        assert_eq!(all, 0x3f);
    }

    // Reference bytes reproduced from go-DDS's actual rtps package (real
    // entityIdForWriter/entityIdForReader, not reimplemented). Go
    // reproduction (package-local scratch test file,
    // `rtps/zzrepro_entityid_test.go`, never committed to go-DDS, deleted
    // after use):
    //
    //   w1, r1 := entityIdForWriter(1), entityIdForReader(1)
    //   w2, r2 := entityIdForWriter(0x010203), entityIdForReader(0x010203)
    //   fmt.Printf("%x\n", [4]byte(w1)) // -> 00000103
    //   fmt.Printf("%x\n", [4]byte(r1)) // -> 00000104
    //   fmt.Printf("%x\n", [4]byte(w2)) // -> 01020303
    //   fmt.Printf("%x\n", [4]byte(r2)) // -> 01020304
    //
    // Full run: `go test ./rtps/... -run TestZZReproEntityIDBytes -v`
    // (go-DDS commit 9d81543 / rust-DDS branch feat/rtps-bestEffort).

    //fusa:test REQ-RTPS-036
    #[test]
    fn entity_id_for_writer_matches_go_dds_reference() {
        assert_eq!(entity_id_for_writer(1), EntityId([0x00, 0x00, 0x01, 0x03]));
        assert_eq!(
            entity_id_for_writer(0x010203),
            EntityId([0x01, 0x02, 0x03, 0x03])
        );
    }

    //fusa:test REQ-RTPS-036
    #[test]
    fn entity_id_for_reader_matches_go_dds_reference() {
        assert_eq!(entity_id_for_reader(1), EntityId([0x00, 0x00, 0x01, 0x04]));
        assert_eq!(
            entity_id_for_reader(0x010203),
            EntityId([0x01, 0x02, 0x03, 0x04])
        );
    }

    //fusa:test REQ-RTPS-036
    #[test]
    fn guid_to_bytes_matches_field_order() {
        let g = Guid {
            prefix: ascending_prefix(),
            entity: ENTITYID_PARTICIPANT,
        };
        let mut expected = Vec::new();
        g.encode(&mut expected);
        assert_eq!(g.to_bytes().to_vec(), expected);
    }
}
