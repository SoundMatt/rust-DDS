// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Minimal wire-level CDR (Common Data Representation) — RTPS 2.3 §10.2 /
//! §9.6.3.
//!
//! This is Tier 1 sub-phase 2 of the parity build-out plan in
//! `ROADMAP.md` ("Tier 1 — RTPS wire-protocol port" → "Minimal wire-level
//! CDR"): just enough CDR to encode/decode the `PL_CDR_LE` inline QoS
//! parameter lists that SPDP/SEDP (later Tier 1 sub-phases) carry inside
//! DATA submessage payloads. **This is deliberately not** the
//! general-purpose XCDR1/XCDR2 payload codec for typed, IDL-generated
//! application data — that is Tier 3's `dds-tools` crate (mirrors go-DDS's
//! top-level `cdr` package, a separate and larger thing). Only the
//! little-endian encapsulation variant is implemented, matching go-DDS's
//! own scope note ("the de-facto standard for modern RTPS implementations").
//!
//! Wire layout ported 1:1 from go-DDS's `rtps/cdr.go`: the `plCDREncoder`/
//! `plCDRDecoder` parameter-list codec and its parameter-ID (PID) table.
//! Also includes the plain `CDR_LE` payload encapsulation wrap/unwrap
//! helpers (go-DDS's `cdrWrapPayload`/`cdrUnwrapPayload`, which physically
//! live in `rtps/message.go` there but use the scheme constants defined in
//! `cdr.go` and are the natural companion of the parameter-list codec —
//! grouped here rather than split across two files).
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001) and no panics on
//! malformed/truncated decode input (REQ-ASIL-003 / REQ-RTPS-009):
//! [`PlCdrDecoder`], [`decode_string`], [`decode_guid`], and
//! [`unwrap_payload`] all return an error (or, for the iterator, simply
//! stop) instead of indexing out of bounds.
//!
//! One deliberate deviation from go-DDS: `plCDRDecoder.next()` there
//! recurses on a `PID_PAD` entry; [`PlCdrDecoder`] is implemented as a
//! plain `Iterator` with an internal `loop` instead, so a parameter list
//! with many consecutive pad entries cannot grow the call stack. Same
//! externally observable behaviour (pad entries are skipped, decoding
//! resumes at the next real parameter), safer implementation.

use super::guid::Guid;
use super::locator::Locator;
use super::RtpsDecodeError;

// ---------------------------------------------------------------------------
// CDR encapsulation scheme identifiers (RTPS 2.3 §10.2 Table 10.1)
// ---------------------------------------------------------------------------

/// CDR, little-endian.
//fusa:req REQ-RTPS-015
pub const CDR_LE: u16 = 0x0001;
/// PL_CDR (parameter-list CDR), little-endian.
//fusa:req REQ-RTPS-011
pub const PL_CDR_LE: u16 = 0x0003;

// ---------------------------------------------------------------------------
// Parameter IDs for SPDP ParticipantProxy and SEDP EndpointData (§9.6.3)
// ---------------------------------------------------------------------------

/// Padding — a zero-cost filler parameter, always skipped on decode.
//fusa:req REQ-RTPS-014
pub const PID_PAD: u16 = 0x0000;
/// Terminates a parameter list.
//fusa:req REQ-RTPS-014
pub const PID_SENTINEL: u16 = 0x0001;
pub const PID_USER_DATA: u16 = 0x002C;
pub const PID_TOPIC_NAME: u16 = 0x0005;
pub const PID_TYPE_NAME: u16 = 0x0007;
pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
pub const PID_VENDOR_ID: u16 = 0x0016;
pub const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
pub const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x002F;
pub const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0030;
pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
pub const PID_ENDPOINT_GUID: u16 = 0x005A;
pub const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
pub const PID_RELIABILITY: u16 = 0x001A;
pub const PID_DURABILITY: u16 = 0x001D;
/// Vendor-specific PID (OMG vendor-extension range `0x8000`–`0xBFFF`)
/// carrying the SPDP discovery authentication tag produced by a
/// `DiscoveryPlugin` (later Tier 2 work).
pub const PID_DISCOVERY_TOKEN: u16 = 0x8001;
/// Vendor-specific PID carrying the SEDP endpoint authentication tag
/// produced by an `EndpointPlugin` (later Tier 2 work).
pub const PID_ENDPOINT_TOKEN: u16 = 0x8002;

// ---------------------------------------------------------------------------
// PlCdrEncoder
// ---------------------------------------------------------------------------

/// Builds a `PL_CDR_LE`-encoded parameter list.
//fusa:req REQ-RTPS-011
#[derive(Debug, Default)]
pub struct PlCdrEncoder {
    buf: Vec<u8>,
}

impl PlCdrEncoder {
    /// Returns an encoder pre-seeded with the `PL_CDR_LE` encapsulation
    /// header (2-byte scheme + 2 zero option bytes).
    //fusa:req REQ-RTPS-011
    pub fn new() -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&PL_CDR_LE.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);
        PlCdrEncoder { buf }
    }

    /// Appends a `(pid, length, value)` triple, padding `value` up to a
    /// 4-byte boundary with zero bytes.
    //fusa:req REQ-RTPS-012
    fn add_param(&mut self, pid: u16, value: &[u8]) {
        let padded = (value.len() + 3) & !3;
        self.buf.extend_from_slice(&pid.to_le_bytes());
        self.buf.extend_from_slice(&(padded as u16).to_le_bytes());
        self.buf.extend_from_slice(value);
        for _ in value.len()..padded {
            self.buf.push(0x00);
        }
    }

    /// Appends a 4-byte little-endian `u32` parameter.
    //fusa:req REQ-RTPS-011
    pub fn add_u32(&mut self, pid: u16, v: u32) {
        self.add_param(pid, &v.to_le_bytes());
    }

    /// Appends a 24-byte [`Locator`] parameter.
    //fusa:req REQ-RTPS-011
    pub fn add_locator(&mut self, pid: u16, loc: &Locator) {
        let mut value = Vec::with_capacity(Locator::LEN);
        loc.encode(&mut value);
        self.add_param(pid, &value);
    }

    /// Appends a 16-byte [`Guid`] parameter.
    //fusa:req REQ-RTPS-011
    pub fn add_guid(&mut self, pid: u16, guid: &Guid) {
        let mut value = Vec::with_capacity(Guid::LEN);
        guid.encode(&mut value);
        self.add_param(pid, &value);
    }

    /// Appends a CDR string parameter: 4-byte little-endian length
    /// (character count including the null terminator) + UTF-8 bytes +
    /// null terminator, then padded to a 4-byte boundary by [`Self::add_param`].
    //fusa:req REQ-RTPS-013
    pub fn add_string(&mut self, pid: u16, s: &str) {
        let mut raw = Vec::with_capacity(4 + s.len() + 1);
        raw.extend_from_slice(&((s.len() + 1) as u32).to_le_bytes());
        raw.extend_from_slice(s.as_bytes());
        raw.push(0x00);
        self.add_param(pid, &raw);
    }

    /// Appends an arbitrary byte-slice parameter.
    //fusa:req REQ-RTPS-011
    pub fn add_bytes(&mut self, pid: u16, v: &[u8]) {
        self.add_param(pid, v);
    }

    /// Appends `PID_SENTINEL` and returns the encoded parameter list.
    //fusa:req REQ-RTPS-011
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
        self.buf.extend_from_slice(&[0x00, 0x00]);
        self.buf
    }
}

// ---------------------------------------------------------------------------
// PlCdrDecoder
// ---------------------------------------------------------------------------

/// A single decoded `(pid, value)` parameter, borrowing from the buffer
/// passed to [`PlCdrDecoder::new`].
//fusa:req REQ-RTPS-014
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Param<'a> {
    pub pid: u16,
    pub value: &'a [u8],
}

/// Iterates over a `PL_CDR_LE`-encoded parameter list.
//fusa:req REQ-RTPS-014
#[derive(Debug)]
pub struct PlCdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PlCdrDecoder<'a> {
    /// Creates a decoder over `buf`.
    ///
    /// Returns `Err(RtpsDecodeError::Truncated)` if `buf` is shorter than
    /// the 4-byte encapsulation header, or
    /// `Err(RtpsDecodeError::InvalidCdrScheme)` if the header's scheme is
    /// not `PL_CDR_LE`. Never panics.
    //fusa:req REQ-RTPS-014
    //fusa:req REQ-RTPS-009
    pub fn new(buf: &'a [u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < 4 {
            return Err(RtpsDecodeError::Truncated {
                expected: 4,
                got: buf.len(),
            });
        }
        let scheme = u16::from_le_bytes([buf[0], buf[1]]);
        if scheme != PL_CDR_LE {
            return Err(RtpsDecodeError::InvalidCdrScheme { got: scheme });
        }
        Ok(PlCdrDecoder { buf, pos: 4 })
    }
}

impl<'a> Iterator for PlCdrDecoder<'a> {
    type Item = Param<'a>;

    /// Returns the next parameter, advancing the cursor.
    ///
    /// Returns `None` at `PID_SENTINEL`, at end of input, or on malformed
    /// input (a header claiming a length that would run past the end of
    /// `buf`) — never panics or indexes out of bounds. `PID_PAD` entries
    /// are skipped transparently.
    //fusa:req REQ-RTPS-014
    //fusa:req REQ-RTPS-009
    fn next(&mut self) -> Option<Param<'a>> {
        loop {
            if self.pos + 4 > self.buf.len() {
                return None;
            }
            let pid = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
            let length =
                u16::from_le_bytes([self.buf[self.pos + 2], self.buf[self.pos + 3]]) as usize;
            self.pos += 4;
            if pid == PID_SENTINEL {
                return None;
            }
            if pid == PID_PAD {
                continue;
            }
            if self.pos + length > self.buf.len() {
                return None;
            }
            let value = &self.buf[self.pos..self.pos + length];
            self.pos += length;
            return Some(Param { pid, value });
        }
    }
}

/// Decodes a CDR string from a parameter value byte slice: a 4-byte
/// little-endian length prefix, followed by that many bytes (the last of
/// which — if any — is a null terminator that is stripped).
///
/// Invalid UTF-8 is replaced losslessly (never panics) rather than
/// rejected outright, since a malformed/hostile peer must not be able to
/// abort decoding of the rest of the message.
//fusa:req REQ-RTPS-013
//fusa:req REQ-RTPS-009
pub fn decode_string(b: &[u8]) -> Result<String, RtpsDecodeError> {
    if b.len() < 4 {
        return Err(RtpsDecodeError::Truncated {
            expected: 4,
            got: b.len(),
        });
    }
    let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if b.len() < 4 + n {
        return Err(RtpsDecodeError::Truncated {
            expected: 4 + n,
            got: b.len(),
        });
    }
    let mut s = &b[4..4 + n];
    if let Some((0, rest)) = s.split_last() {
        s = rest;
    }
    Ok(String::from_utf8_lossy(s).into_owned())
}

/// Decodes a 16-byte [`Guid`] from a parameter value. Thin wrapper over
/// [`Guid::decode`], kept here to mirror go-DDS's `cdr.go` file layout
/// (`decodeGUID` sits alongside `decodeString` there too).
//fusa:req REQ-RTPS-011
//fusa:req REQ-RTPS-009
pub fn decode_guid(b: &[u8]) -> Result<Guid, RtpsDecodeError> {
    Guid::decode(b)
}

// ---------------------------------------------------------------------------
// Plain CDR_LE / PL_CDR_LE payload encapsulation (go-DDS's cdrWrapPayload /
// cdrUnwrapPayload)
// ---------------------------------------------------------------------------

/// Prepends the 4-byte `CDR_LE` encapsulation header (scheme + zero
/// options) to a raw payload.
//fusa:req REQ-RTPS-015
pub fn wrap_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&CDR_LE.to_le_bytes());
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(payload);
    out
}

/// Strips a 4-byte CDR encapsulation header, accepting either the `CDR_LE`
/// or `PL_CDR_LE` scheme.
///
/// Returns `Err(RtpsDecodeError::Truncated)` if `b` is shorter than 4
/// bytes, or `Err(RtpsDecodeError::InvalidCdrScheme)` if the scheme is
/// neither `CDR_LE` nor `PL_CDR_LE`. Never panics.
//fusa:req REQ-RTPS-015
//fusa:req REQ-RTPS-009
pub fn unwrap_payload(b: &[u8]) -> Result<&[u8], RtpsDecodeError> {
    if b.len() < 4 {
        return Err(RtpsDecodeError::Truncated {
            expected: 4,
            got: b.len(),
        });
    }
    let scheme = u16::from_le_bytes([b[0], b[1]]);
    if scheme != CDR_LE && scheme != PL_CDR_LE {
        return Err(RtpsDecodeError::InvalidCdrScheme { got: scheme });
    }
    Ok(&b[4..])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtps::guid::{GuidPrefix, ENTITYID_PARTICIPANT};
    use crate::rtps::locator::Locator;

    // Reference bytes reproduced from go-DDS's actual rtps package (real
    // plCDREncoder/plCDRDecoder/cdrWrapPayload/cdrUnwrapPayload, not
    // reimplemented). Go reproduction (package-local scratch test file,
    // `rtps/zzrepro_cdr_test.go`, never committed to go-DDS, deleted after
    // use):
    //
    //   func TestZZReproCDRBytes(t *testing.T) {
    //       // empty parameter list
    //       enc := newPLCDREncoder()
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 0300000001000000
    //
    //       // uint32: PID_BUILTIN_ENDPOINT_SET, 0x3f
    //       enc = newPLCDREncoder()
    //       enc.addUint32(pidBuiltinEndpointSet, 0x3f)
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 03000000580004003f00000001000000
    //
    //       // string: PID_TOPIC_NAME, "Square"
    //       enc = newPLCDREncoder()
    //       enc.addString(pidTopicName, "Square")
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 0300000005000c0007000000537175617265000001000000
    //
    //       // guid: PID_PARTICIPANT_GUID, ascending prefix + EntityIdParticipant
    //       var prefix GuidPrefix
    //       for i := 0; i < 12; i++ { prefix[i] = byte(i + 1) }
    //       g := GUID{Prefix: prefix, Entity: EntityIdParticipant}
    //       enc = newPLCDREncoder()
    //       enc.addGUID(pidParticipantGUID, g)
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 03000000500010000102030405060708090a0b0c000001c101000000
    //
    //       // locator: PID_DEFAULT_UNICAST_LOCATOR, UDPv4 192.168.1.50:7412
    //       loc := Locator{Kind: LocatorKindUDPv4, Port: 7412}
    //       loc.Address[12], loc.Address[13], loc.Address[14], loc.Address[15] = 192, 168, 1, 50
    //       enc = newPLCDREncoder()
    //       enc.addLocator(pidDefaultUnicastLocator, loc)
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 030000002f00180001000000f41c0000000000000000000000000000c0a8013201000000
    //
    //       // bytes: PID_USER_DATA, 3 raw bytes (odd length, needs padding)
    //       enc = newPLCDREncoder()
    //       enc.addBytes(pidUserData, []byte{0xDE, 0xAD, 0xBE})
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 030000002c000400deadbe0001000000
    //
    //       // combined realistic parameter list (mirrors spdp.go/sedp.go)
    //       enc = newPLCDREncoder()
    //       enc.addString(pidTopicName, "Square")
    //       enc.addString(pidTypeName, "ShapeType")
    //       enc.addGUID(pidParticipantGUID, g)
    //       enc.addLocator(pidDefaultUnicastLocator, loc)
    //       enc.addUint32(pidBuiltinEndpointSet, 0x3f)
    //       fmt.Printf("%x\n", enc.finish())
    //       // -> 0300000005000c00070000005371756172650000070010000a0000005368617065
    //       //    54797065000000500010000102030405060708090a0b0c000001c12f0018000100
    //       //    0000f41c0000000000000000000000000000c0a80132580004003f00000001000000
    //
    //       // wrap/unwrap
    //       fmt.Printf("%x\n", cdrWrapPayload([]byte{0x01, 0x02, 0x03}))
    //       // -> 01000000010203
    //   }
    //
    // Full run: `go test ./rtps/... -run TestZZReproCDRBytes -v`
    // (go-DDS commit df20115 / rust-DDS branch feat/rtps-cdr-wire-format).

    fn ascending_prefix() -> GuidPrefix {
        let mut b = [0u8; 12];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i + 1) as u8; // safe: i in [0,11], (i+1) in [1,12] fits u8
        }
        GuidPrefix(b)
    }

    fn sample_guid() -> Guid {
        Guid {
            prefix: ascending_prefix(),
            entity: ENTITYID_PARTICIPANT,
        }
    }

    fn sample_locator() -> Locator {
        Locator::udp_v4([192, 168, 1, 50], 7412)
    }

    //fusa:test REQ-RTPS-011
    #[test]
    fn empty_parameter_list_matches_go_dds_reference() {
        let out = PlCdrEncoder::new().finish();
        assert_eq!(hex::encode(&out), "0300000001000000");
    }

    //fusa:test REQ-RTPS-011
    #[test]
    fn add_u32_matches_go_dds_reference() {
        let mut enc = PlCdrEncoder::new();
        enc.add_u32(PID_BUILTIN_ENDPOINT_SET, 0x3f);
        assert_eq!(
            hex::encode(enc.finish()),
            "03000000580004003f00000001000000"
        );
    }

    //fusa:test REQ-RTPS-013
    //fusa:test REQ-RTPS-012
    #[test]
    fn add_string_matches_go_dds_reference() {
        let mut enc = PlCdrEncoder::new();
        enc.add_string(PID_TOPIC_NAME, "Square");
        assert_eq!(
            hex::encode(enc.finish()),
            "0300000005000c0007000000537175617265000001000000"
        );
    }

    //fusa:test REQ-RTPS-011
    #[test]
    fn add_guid_matches_go_dds_reference() {
        let mut enc = PlCdrEncoder::new();
        enc.add_guid(PID_PARTICIPANT_GUID, &sample_guid());
        assert_eq!(
            hex::encode(enc.finish()),
            "03000000500010000102030405060708090a0b0c000001c101000000"
        );
    }

    //fusa:test REQ-RTPS-011
    #[test]
    fn add_locator_matches_go_dds_reference() {
        let mut enc = PlCdrEncoder::new();
        enc.add_locator(PID_DEFAULT_UNICAST_LOCATOR, &sample_locator());
        assert_eq!(
            hex::encode(enc.finish()),
            "030000002f00180001000000f41c0000000000000000000000000000c0a8013201000000"
        );
    }

    //fusa:test REQ-RTPS-011
    //fusa:test REQ-RTPS-012
    #[test]
    fn add_bytes_pads_odd_length_matches_go_dds_reference() {
        let mut enc = PlCdrEncoder::new();
        enc.add_bytes(PID_USER_DATA, &[0xDE, 0xAD, 0xBE]);
        assert_eq!(
            hex::encode(enc.finish()),
            "030000002c000400deadbe0001000000"
        );
    }

    //fusa:test REQ-RTPS-011
    //fusa:test REQ-RTPS-013
    #[test]
    fn combined_parameter_list_matches_go_dds_reference() {
        let mut enc = PlCdrEncoder::new();
        enc.add_string(PID_TOPIC_NAME, "Square");
        enc.add_string(PID_TYPE_NAME, "ShapeType");
        enc.add_guid(PID_PARTICIPANT_GUID, &sample_guid());
        enc.add_locator(PID_DEFAULT_UNICAST_LOCATOR, &sample_locator());
        enc.add_u32(PID_BUILTIN_ENDPOINT_SET, 0x3f);
        let out = enc.finish();
        assert_eq!(
            hex::encode(&out),
            concat!(
                "0300000005000c0007000000537175617265000007001000",
                "0a000000536861706554797065000000",
                "500010000102030405060708090a0b0c000001c1",
                "2f00180001000000f41c0000000000000000000000000000c0a80132",
                "580004003f00000001000000",
            )
        );

        // Decode round-trip: every param value byte-matches go-DDS's own
        // decoder output for the same input (see doc comment above).
        let dec = PlCdrDecoder::new(&out).expect("valid PL_CDR_LE header");
        let params: Vec<Param<'_>> = dec.collect();
        assert_eq!(params.len(), 5);
        assert_eq!(params[0].pid, PID_TOPIC_NAME);
        assert_eq!(hex::encode(params[0].value), "070000005371756172650000");
        assert_eq!(params[1].pid, PID_TYPE_NAME);
        assert_eq!(
            hex::encode(params[1].value),
            "0a000000536861706554797065000000"
        );
        assert_eq!(params[2].pid, PID_PARTICIPANT_GUID);
        assert_eq!(
            hex::encode(params[2].value),
            "0102030405060708090a0b0c000001c1"
        );
        assert_eq!(params[3].pid, PID_DEFAULT_UNICAST_LOCATOR);
        assert_eq!(
            hex::encode(params[3].value),
            "01000000f41c0000000000000000000000000000c0a80132"
        );
        assert_eq!(params[4].pid, PID_BUILTIN_ENDPOINT_SET);
        assert_eq!(hex::encode(params[4].value), "3f000000");

        // Field-level round trip through the typed decode helpers too.
        assert_eq!(decode_string(params[0].value).unwrap(), "Square");
        assert_eq!(decode_string(params[1].value).unwrap(), "ShapeType");
        assert_eq!(decode_guid(params[2].value).unwrap(), sample_guid());
    }

    //fusa:test REQ-RTPS-015
    #[test]
    fn wrap_payload_matches_go_dds_reference() {
        let wrapped = wrap_payload(&[0x01, 0x02, 0x03]);
        assert_eq!(hex::encode(&wrapped), "01000000010203");
        assert_eq!(unwrap_payload(&wrapped).unwrap(), &[0x01, 0x02, 0x03]);
    }

    //fusa:test REQ-RTPS-015
    #[test]
    fn unwrap_payload_accepts_both_schemes() {
        let mut plain = CDR_LE.to_le_bytes().to_vec();
        plain.extend_from_slice(&[0x00, 0x00, 0xAA]);
        assert_eq!(unwrap_payload(&plain).unwrap(), &[0xAA]);

        let mut pl = PL_CDR_LE.to_le_bytes().to_vec();
        pl.extend_from_slice(&[0x00, 0x00, 0xBB]);
        assert_eq!(unwrap_payload(&pl).unwrap(), &[0xBB]);
    }

    //fusa:test REQ-RTPS-014
    //fusa:test REQ-RTPS-009
    #[test]
    fn decoder_rejects_bad_scheme_and_truncated_header() {
        assert_eq!(
            PlCdrDecoder::new(&[]).unwrap_err(),
            RtpsDecodeError::Truncated {
                expected: 4,
                got: 0
            }
        );
        assert_eq!(
            PlCdrDecoder::new(&[0x01, 0x00, 0x00, 0x00]).unwrap_err(),
            RtpsDecodeError::InvalidCdrScheme { got: CDR_LE }
        );
    }

    //fusa:test REQ-RTPS-014
    #[test]
    fn decoder_skips_pad_entries() {
        // PL_CDR_LE header, then two PID_PAD entries, then a real param,
        // then sentinel — self-constructed (protocol-behaviour test, not a
        // go-DDS byte-exact case): the encoder never emits PID_PAD itself,
        // but a decoder must tolerate a peer that does.
        let mut buf = PL_CDR_LE.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0x00, 0x00]); // options
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PID_PAD, len 0
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PID_PAD, len 0
        buf.extend_from_slice(&PID_BUILTIN_ENDPOINT_SET.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0x3fu32.to_le_bytes());
        buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);

        let params: Vec<Param<'_>> = PlCdrDecoder::new(&buf).unwrap().collect();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].pid, PID_BUILTIN_ENDPOINT_SET);
        assert_eq!(params[0].value, &0x3fu32.to_le_bytes());
    }

    //fusa:test REQ-RTPS-014
    //fusa:test REQ-RTPS-009
    #[test]
    fn decoder_stops_without_panicking_on_length_past_end() {
        let mut buf = PL_CDR_LE.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0x00, 0x00]); // options
        buf.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // claims 65535 bytes of value
        buf.extend_from_slice(&[0x01, 0x02]); // but only 2 remain

        let params: Vec<Param<'_>> = PlCdrDecoder::new(&buf).unwrap().collect();
        assert!(params.is_empty());
    }

    //fusa:test REQ-RTPS-013
    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_string_rejects_truncated_input_without_panicking() {
        assert_eq!(
            decode_string(&[0x00, 0x00]).unwrap_err(),
            RtpsDecodeError::Truncated {
                expected: 4,
                got: 2
            }
        );
        // Claims 100 chars but only 0 follow.
        assert_eq!(
            decode_string(&100u32.to_le_bytes()).unwrap_err(),
            RtpsDecodeError::Truncated {
                expected: 104,
                got: 4
            }
        );
    }

    //fusa:test REQ-RTPS-011
    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_guid_rejects_truncated_input_without_panicking() {
        assert_eq!(
            decode_guid(&[0u8; 15]),
            Err(RtpsDecodeError::Truncated {
                expected: 16,
                got: 15
            })
        );
    }

    //fusa:test REQ-RTPS-015
    //fusa:test REQ-RTPS-009
    #[test]
    fn unwrap_payload_rejects_truncated_and_unknown_scheme() {
        assert_eq!(
            unwrap_payload(&[0x00, 0x00, 0x00]),
            Err(RtpsDecodeError::Truncated {
                expected: 4,
                got: 3
            })
        );
        assert_eq!(
            unwrap_payload(&[0xFF, 0xFF, 0x00, 0x00]),
            Err(RtpsDecodeError::InvalidCdrScheme { got: 0xFFFF })
        );
    }
}
