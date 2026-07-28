// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! General-purpose CDR/XCDR1 (Common Data Representation) codec for typed,
//! non-opaque RTPS DATA/DATA_FRAG payloads — RTPS 2.3 §10.2 / OMG DDS-XTypes
//! 1.3.
//!
//! This is the `ROADMAP.md` "Planned — v0.2 — RTPS Transport (Tier 1)"
//! checklist item "CDR/XCDR1 serialization for RTPS wire format". It is
//! **deliberately distinct** from [`super::cdr`], which is Tier 1
//! sub-phase 2's `PL_CDR_LE` **parameter-list** codec
//! (`PlCdrEncoder`/`PlCdrDecoder`) plus the plain `CDR_LE`/`PL_CDR_LE`
//! payload-encapsulation `wrap_payload`/`unwrap_payload` helpers used for
//! SPDP/SEDP inline QoS and RTPS submessage headers — see that module's own
//! doc comment. This module is what goes *inside* a `wrap_payload`
//! envelope for a typed, application-defined struct: primitive-type and
//! string/sequence encode/decode with CDR/XCDR1 alignment rules, the
//! general building block IDL-generated (de)serialization code composes
//! structs and sequences out of. Only the little-endian encapsulation
//! variant is implemented (`CDR_LE`, matching this crate's existing
//! `CDR_LE`/`PL_CDR_LE` convention in [`super::cdr`]).
//!
//! Ported 1:1 from go-DDS's top-level `cdr` package
//! (`github.com/SoundMatt/go-DDS/tools/cdr`, `cdr.go`): [`XcdrEncoder`]
//! mirrors `cdr.Encoder`'s `Write*` methods and [`XcdrDecoder`] mirrors
//! `cdr.Decoder`'s `Read*` methods, including go-DDS's own alignment
//! convention of counting the 4-byte encapsulation header as part of the
//! stream's byte-0 origin (so an 8-byte-aligned field immediately after the
//! header gets 4 bytes of padding, not 0) and its own decoder quirk of
//! accepting either scheme `0x0001` (`CDR_LE`) or `0x0000` (`CDR_BE`) on
//! decode while only ever decoding little-endian content (go-DDS's own
//! doc comment: "we decode LE only").
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001) and no panics on
//! malformed/truncated decode input (REQ-ASIL-003 / REQ-RTPS-009):
//! [`XcdrDecoder`] returns `Err(RtpsDecodeError)` on a short encapsulation
//! header, an unrecognised scheme, or a buffer underrun on any `read_*`
//! call — never indexes out of bounds or panics on invalid UTF-8 (a
//! decoded string that is not valid UTF-8 is lossily converted instead of
//! rejected, the same deviation [`super::cdr::decode_string`] already
//! documents and for the same reason: a malformed/hostile peer must not be
//! able to abort decoding of the rest of the message).

use super::cdr::CDR_LE;
use super::RtpsDecodeError;

/// Big-endian encapsulation scheme identifier (RTPS 2.3 §10.2 Table 10.1).
/// [`XcdrDecoder::new`] accepts this on the header (matching go-DDS's own
/// decoder) but — like go-DDS — never actually decodes big-endian content;
/// see the module doc comment.
const CDR_BE: u16 = 0x0000;

/// Length in bytes of the CDR encapsulation header every [`XcdrEncoder`]
/// output starts with and every [`XcdrDecoder`] input must start with.
pub const ENCAP_HEADER_LEN: usize = 4;

// ---------------------------------------------------------------------------
// XcdrEncoder
// ---------------------------------------------------------------------------

/// Writes CDR/XCDR1 little-endian bytes to an internal buffer. Call
/// [`XcdrEncoder::bytes`]/[`XcdrEncoder::into_bytes`] to retrieve the
/// complete encoded message, including the 4-byte encapsulation header.
//fusa:req REQ-RTPS-063
#[derive(Debug, Default)]
pub struct XcdrEncoder {
    buf: Vec<u8>,
}

impl XcdrEncoder {
    /// Returns an encoder pre-seeded with the `CDR_LE` encapsulation header
    /// (2-byte little-endian scheme `0x0001` + 2 zero option bytes).
    //fusa:req REQ-RTPS-063
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(ENCAP_HEADER_LEN);
        buf.extend_from_slice(&CDR_LE.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);
        XcdrEncoder { buf }
    }

    /// Returns the complete encoded buffer, including the encapsulation
    /// header.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the encoder and returns the complete encoded buffer,
    /// including the encapsulation header.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Current encoded length in bytes, including the encapsulation
    /// header (so a freshly-constructed encoder reports 4, never 0).
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Always `false`: an [`XcdrEncoder`] always holds at least its 4-byte
    /// encapsulation header.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Pads the buffer with zero bytes up to the next multiple of `n`
    /// bytes, counting from the start of the buffer (the encapsulation
    /// header included) — see the module doc comment.
    fn align(&mut self, n: usize) {
        let pad = (n - (self.buf.len() % n)) % n;
        self.buf.resize(self.buf.len() + pad, 0);
    }

    /// Encodes a boolean as one byte (`1` for `true`, `0` for `false`).
    //fusa:req REQ-RTPS-063
    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    /// Encodes an unsigned octet.
    //fusa:req REQ-RTPS-063
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Encodes a signed octet.
    //fusa:req REQ-RTPS-063
    pub fn write_i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }

    /// Encodes a `char` as a single unsigned octet (CDR §10.2/DDS-XTypes
    /// narrow `char`), matching go-DDS's `WriteUint8` usage for character
    /// fields — only the low byte of `v` is encoded.
    //fusa:req REQ-RTPS-063
    pub fn write_char(&mut self, v: char) {
        self.write_u8(v as u8);
    }

    /// Encodes a signed 16-bit integer (2-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_i16(&mut self, v: i16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes an unsigned 16-bit integer (2-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes a signed 32-bit integer (4-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_i32(&mut self, v: i32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes an unsigned 32-bit integer (4-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes a signed 64-bit integer (8-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_i64(&mut self, v: i64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes an unsigned 64-bit integer (8-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes a 32-bit IEEE 754 float (4-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_f32(&mut self, v: f32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    /// Encodes a 64-bit IEEE 754 float (8-byte aligned).
    //fusa:req REQ-RTPS-063
    pub fn write_f64(&mut self, v: f64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    /// Encodes a CDR string: a 4-byte little-endian length (character
    /// count including a null terminator, 4-byte aligned), the UTF-8
    /// bytes of `s`, then a null terminator byte.
    //fusa:req REQ-RTPS-064
    pub fn write_string(&mut self, s: &str) {
        self.align(4);
        let n = (s.len() + 1) as u32;
        self.buf.extend_from_slice(&n.to_le_bytes());
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0x00);
    }

    /// Encodes a byte sequence: a 4-byte little-endian element count
    /// (4-byte aligned) followed by the raw bytes, no per-element padding
    /// (octet sequences have 1-byte element alignment).
    //fusa:req REQ-RTPS-064
    pub fn write_bytes_seq(&mut self, b: &[u8]) {
        self.align(4);
        let n = b.len() as u32;
        self.buf.extend_from_slice(&n.to_le_bytes());
        self.buf.extend_from_slice(b);
    }
}

// ---------------------------------------------------------------------------
// XcdrDecoder
// ---------------------------------------------------------------------------

/// Reads CDR/XCDR1 little-endian bytes from a buffer that begins with a
/// 4-byte CDR encapsulation header.
//fusa:req REQ-RTPS-065
#[derive(Debug)]
pub struct XcdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XcdrDecoder<'a> {
    /// Creates a decoder over `buf`.
    ///
    /// Returns `Err(RtpsDecodeError::Truncated)` if `buf` is shorter than
    /// the 4-byte encapsulation header, or
    /// `Err(RtpsDecodeError::InvalidCdrScheme)` if the header's scheme is
    /// neither `CDR_LE` (`0x0001`) nor `CDR_BE` (`0x0000`) — see the
    /// module doc comment for why `CDR_BE` is accepted on the header
    /// without a big-endian decode path. Never panics.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn new(buf: &'a [u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < ENCAP_HEADER_LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: ENCAP_HEADER_LEN,
                got: buf.len(),
            });
        }
        let scheme = u16::from_le_bytes([buf[0], buf[1]]);
        if scheme != CDR_LE && scheme != CDR_BE {
            return Err(RtpsDecodeError::InvalidCdrScheme { got: scheme });
        }
        Ok(XcdrDecoder {
            buf,
            pos: ENCAP_HEADER_LEN,
        })
    }

    /// Number of undecoded bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Advances the cursor to the next multiple of `n` bytes, counting
    /// from the start of the buffer (the encapsulation header included) —
    /// see the module doc comment.
    fn align(&mut self, n: usize) {
        let pad = (n - (self.pos % n)) % n;
        self.pos += pad;
    }

    /// Returns `Err(RtpsDecodeError::Truncated)` if fewer than `n` bytes
    /// remain at the current cursor position.
    fn need(&self, n: usize) -> Result<(), RtpsDecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(RtpsDecodeError::Truncated {
                expected: self.pos + n,
                got: self.buf.len(),
            });
        }
        Ok(())
    }

    /// Decodes a boolean byte (any non-zero byte decodes as `true`).
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_bool(&mut self) -> Result<bool, RtpsDecodeError> {
        self.need(1)?;
        let v = self.buf[self.pos] != 0;
        self.pos += 1;
        Ok(v)
    }

    /// Decodes an unsigned octet.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_u8(&mut self) -> Result<u8, RtpsDecodeError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Decodes a signed octet.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_i8(&mut self) -> Result<i8, RtpsDecodeError> {
        Ok(self.read_u8()? as i8)
    }

    /// Decodes a `char` from a single unsigned octet — the inverse of
    /// [`XcdrEncoder::write_char`]. A byte with the high bit set (not
    /// ASCII) decodes as `char::REPLACEMENT_CHARACTER` rather than
    /// failing, so malformed/hostile input never aborts decoding of the
    /// rest of the message (REQ-ASIL-003).
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_char(&mut self) -> Result<char, RtpsDecodeError> {
        let v = self.read_u8()?;
        Ok(if v.is_ascii() {
            v as char
        } else {
            char::REPLACEMENT_CHARACTER
        })
    }

    /// Decodes a signed 16-bit integer.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_i16(&mut self) -> Result<i16, RtpsDecodeError> {
        self.align(2);
        self.need(2)?;
        let v = i16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Decodes an unsigned 16-bit integer.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_u16(&mut self) -> Result<u16, RtpsDecodeError> {
        self.align(2);
        self.need(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Decodes a signed 32-bit integer.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_i32(&mut self) -> Result<i32, RtpsDecodeError> {
        self.align(4);
        self.need(4)?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(i32::from_le_bytes(b))
    }

    /// Decodes an unsigned 32-bit integer.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_u32(&mut self) -> Result<u32, RtpsDecodeError> {
        self.align(4);
        self.need(4)?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(b))
    }

    /// Decodes a signed 64-bit integer.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_i64(&mut self) -> Result<i64, RtpsDecodeError> {
        self.align(8);
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(i64::from_le_bytes(b))
    }

    /// Decodes an unsigned 64-bit integer.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_u64(&mut self) -> Result<u64, RtpsDecodeError> {
        self.align(8);
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(b))
    }

    /// Decodes a 32-bit IEEE 754 float.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_f32(&mut self) -> Result<f32, RtpsDecodeError> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    /// Decodes a 64-bit IEEE 754 float.
    //fusa:req REQ-RTPS-065
    //fusa:req REQ-RTPS-009
    pub fn read_f64(&mut self) -> Result<f64, RtpsDecodeError> {
        Ok(f64::from_bits(self.read_u64()?))
    }

    /// Decodes a CDR string (4-byte length prefix + bytes + null
    /// terminator). A zero-length prefix decodes as an empty string
    /// (matching go-DDS's own defensive `n == 0` fast path).
    ///
    /// Invalid UTF-8 is replaced losslessly (never panics) rather than
    /// rejected outright — see the module doc comment.
    //fusa:req REQ-RTPS-066
    //fusa:req REQ-RTPS-009
    pub fn read_string(&mut self) -> Result<String, RtpsDecodeError> {
        let n = self.read_u32()? as usize;
        if n == 0 {
            return Ok(String::new());
        }
        self.need(n)?;
        let mut raw = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        if let Some((0, rest)) = raw.split_last() {
            raw = rest;
        }
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    /// Decodes a byte sequence (4-byte count prefix + raw bytes).
    //fusa:req REQ-RTPS-066
    //fusa:req REQ-RTPS-009
    pub fn read_bytes_seq(&mut self) -> Result<Vec<u8>, RtpsDecodeError> {
        let n = self.read_u32()? as usize;
        self.need(n)?;
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Reference bytes reproduced from go-DDS's actual tools/cdr package
    // (real cdr.Encoder/cdr.Decoder, not reimplemented). Go reproduction
    // (package-local scratch test file, `tools/cdr/zzrepro_test.go`, never
    // committed to go-DDS, deleted after use):
    //
    //   func TestZZReproCDRBytes(t *testing.T) {
    //       e := cdr.NewEncoder()
    //       fmt.Printf("empty: %x\n", e.Bytes())
    //       // -> 01000000
    //
    //       e = cdr.NewEncoder(); e.WriteBool(true); e.WriteBool(false)
    //       fmt.Printf("bool_true_false: %x\n", e.Bytes())
    //       // -> 010000000100
    //
    //       e = cdr.NewEncoder(); e.WriteUint8(0xAB)
    //       fmt.Printf("uint8: %x\n", e.Bytes())
    //       // -> 01000000ab
    //
    //       e = cdr.NewEncoder(); e.WriteInt8(-7)
    //       fmt.Printf("int8: %x\n", e.Bytes())
    //       // -> 01000000f9
    //
    //       e = cdr.NewEncoder(); e.WriteInt16(-1234)
    //       fmt.Printf("int16: %x\n", e.Bytes())
    //       // -> 010000002efb
    //
    //       e = cdr.NewEncoder(); e.WriteUint16(0xABCD)
    //       fmt.Printf("uint16: %x\n", e.Bytes())
    //       // -> 01000000cdab
    //
    //       e = cdr.NewEncoder(); e.WriteInt32(-123456789)
    //       fmt.Printf("int32: %x\n", e.Bytes())
    //       // -> 01000000eb32a4f8
    //
    //       e = cdr.NewEncoder(); e.WriteUint32(0xDEADBEEF)
    //       fmt.Printf("uint32: %x\n", e.Bytes())
    //       // -> 01000000efbeadde
    //
    //       e = cdr.NewEncoder(); e.WriteInt64(-9876543210)
    //       fmt.Printf("int64: %x\n", e.Bytes())
    //       // -> 010000000000000016e94fb3fdffffff
    //
    //       e = cdr.NewEncoder(); e.WriteUint64(0xCAFEBABEDEADBEEF)
    //       fmt.Printf("uint64: %x\n", e.Bytes())
    //       // -> 0100000000000000efbeaddebebafeca
    //
    //       e = cdr.NewEncoder(); e.WriteFloat32(3.14)
    //       fmt.Printf("float32: %x\n", e.Bytes())
    //       // -> 01000000c3f54840
    //
    //       e = cdr.NewEncoder(); e.WriteFloat64(2.718281828)
    //       fmt.Printf("float64: %x\n", e.Bytes())
    //       // -> 01000000000000009b91048b0abf0540
    //
    //       e = cdr.NewEncoder(); e.WriteString("hello")
    //       fmt.Printf("string_hello: %x\n", e.Bytes())
    //       // -> 010000000600000068656c6c6f00
    //
    //       e = cdr.NewEncoder(); e.WriteString("")
    //       fmt.Printf("string_empty: %x\n", e.Bytes())
    //       // -> 010000000100000000
    //
    //       e = cdr.NewEncoder(); e.WriteString("unicode: 日本語")
    //       fmt.Printf("string_unicode: %x\n", e.Bytes())
    //       // -> 0100000013000000756e69636f64653a20e697a5e69cace8aa9e00
    //
    //       e = cdr.NewEncoder(); e.WriteBytes([]byte{0x00, 0x01, 0xFF, 0x80})
    //       fmt.Printf("bytes: %x\n", e.Bytes())
    //       // -> 01000000040000000001ff80
    //
    //       e = cdr.NewEncoder(); e.WriteBool(true); e.WriteInt32(42)
    //       fmt.Printf("bool_then_int32: %x\n", e.Bytes())
    //       // -> 01000000010000002a000000
    //
    //       e = cdr.NewEncoder(); e.WriteUint8(0x01); e.WriteInt64(1234567890123)
    //       fmt.Printf("uint8_then_int64: %x\n", e.Bytes())
    //       // -> 0100000001000000cb04fb711f010000
    //
    //       e = cdr.NewEncoder(); e.WriteUint16(0x0102); e.WriteFloat64(1.5)
    //       fmt.Printf("uint16_then_float64: %x\n", e.Bytes())
    //       // -> 0100000002010000000000000000f83f
    //
    //       e = cdr.NewEncoder()
    //       e.WriteString("ECU-1"); e.WriteFloat64(95.5)
    //       e.WriteInt64(1749000000000); e.WriteBool(true); e.WriteUint32(7)
    //       fmt.Printf("multifield: %x\n", e.Bytes())
    //       // -> 01000000060000004543552d310000000000000000e0574000
    //       //    1286389701000001000000 07000000
    //
    //       e = cdr.NewEncoder()
    //       e.WriteUint32(3); e.WriteInt32(10); e.WriteInt32(-20); e.WriteInt32(30)
    //       fmt.Printf("int32_seq: %x\n", e.Bytes())
    //       // -> 01000000030000000a000000ecffffff1e000000
    //
    //       e = cdr.NewEncoder()
    //       e.WriteInt16(7); e.WriteFloat64(1.0); e.WriteFloat64(-2.5); e.WriteBool(false)
    //       fmt.Printf("nested_struct: %x\n", e.Bytes())
    //       // -> 0100000007000000000000000000f03f00000000000004c000
    //
    //       e = cdr.NewEncoder()
    //       e.WriteUint32(2); e.WriteString("ab"); e.WriteString("cde")
    //       fmt.Printf("string_seq: %x\n", e.Bytes())
    //       // -> 010000000200000003000000616200000400000063646500
    //
    //       e = cdr.NewEncoder()
    //       e.WriteInt8(-128); e.WriteInt8(127)
    //       e.WriteInt16(-32768); e.WriteInt16(32767)
    //       e.WriteInt32(-2147483648); e.WriteInt32(2147483647)
    //       e.WriteInt64(-9223372036854775808); e.WriteInt64(9223372036854775807)
    //       fmt.Printf("boundaries: %x\n", e.Bytes())
    //       // -> 01000000807f0080ff7f000000000080ffffff7f0000000000
    //       //    00000000000080ffffffffffffff7f
    //   }
    //
    // Full run: `go test ./tools/cdr/... -run TestZZReproCDRBytes -v`
    // (go-DDS commit 5fedbc6 / rust-DDS branch feat/rtps-xcdr1-general-codec).

    //fusa:test REQ-RTPS-063
    #[test]
    fn empty_encoder_matches_go_dds_reference() {
        let e = XcdrEncoder::new();
        assert_eq!(hex::encode(e.bytes()), "01000000");
        assert_eq!(e.len(), 4);
        assert!(!e.is_empty());
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn bool_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_bool(true);
        e.write_bool(false);
        assert_eq!(hex::encode(e.into_bytes()), "010000000100");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn uint8_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u8(0xAB);
        assert_eq!(hex::encode(e.into_bytes()), "01000000ab");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn int8_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_i8(-7);
        assert_eq!(hex::encode(e.into_bytes()), "01000000f9");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn int16_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_i16(-1234);
        assert_eq!(hex::encode(e.into_bytes()), "010000002efb");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn uint16_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u16(0xABCD);
        assert_eq!(hex::encode(e.into_bytes()), "01000000cdab");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn int32_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_i32(-123456789);
        assert_eq!(hex::encode(e.into_bytes()), "01000000eb32a4f8");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn uint32_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u32(0xDEADBEEF);
        assert_eq!(hex::encode(e.into_bytes()), "01000000efbeadde");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn int64_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_i64(-9876543210);
        assert_eq!(
            hex::encode(e.into_bytes()),
            "010000000000000016e94fb3fdffffff"
        );
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn uint64_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u64(0xCAFEBABEDEADBEEF);
        assert_eq!(
            hex::encode(e.into_bytes()),
            "0100000000000000efbeaddebebafeca"
        );
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn float32_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_f32(3.14);
        assert_eq!(hex::encode(e.into_bytes()), "01000000c3f54840");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn float64_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_f64(2.718281828);
        assert_eq!(
            hex::encode(e.into_bytes()),
            "01000000000000009b91048b0abf0540"
        );
    }

    //fusa:test REQ-RTPS-064
    #[test]
    fn string_hello_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_string("hello");
        assert_eq!(hex::encode(e.into_bytes()), "010000000600000068656c6c6f00");
    }

    //fusa:test REQ-RTPS-064
    #[test]
    fn string_empty_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_string("");
        assert_eq!(hex::encode(e.into_bytes()), "010000000100000000");
    }

    //fusa:test REQ-RTPS-064
    #[test]
    fn string_unicode_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_string("unicode: 日本語");
        assert_eq!(
            hex::encode(e.into_bytes()),
            "0100000013000000756e69636f64653a20e697a5e69cace8aa9e00"
        );
    }

    //fusa:test REQ-RTPS-064
    #[test]
    fn bytes_seq_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_bytes_seq(&[0x00, 0x01, 0xFF, 0x80]);
        assert_eq!(hex::encode(e.into_bytes()), "01000000040000000001ff80");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn bool_then_int32_alignment_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_bool(true);
        e.write_i32(42);
        assert_eq!(hex::encode(e.into_bytes()), "01000000010000002a000000");
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn uint8_then_int64_alignment_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u8(0x01);
        e.write_i64(1234567890123);
        assert_eq!(
            hex::encode(e.into_bytes()),
            "0100000001000000cb04fb711f010000"
        );
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn uint16_then_float64_alignment_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u16(0x0102);
        e.write_f64(1.5);
        assert_eq!(
            hex::encode(e.into_bytes()),
            "0100000002010000000000000000f83f"
        );
    }

    //fusa:test REQ-RTPS-063
    //fusa:test REQ-RTPS-064
    #[test]
    fn multifield_struct_matches_go_dds_reference() {
        // Simulates a struct { string name; double x; int64 ts; bool ok;
        // uint32 count; } — exactly how IDL-generated code would compose
        // these primitive writes into a typed payload.
        let mut e = XcdrEncoder::new();
        e.write_string("ECU-1");
        e.write_f64(95.5);
        e.write_i64(1749000000000);
        e.write_bool(true);
        e.write_u32(7);
        let out = e.into_bytes();
        assert_eq!(
            hex::encode(&out),
            concat!(
                "01000000060000004543552d3100000000000000",
                "00e057400012863897010000",
                "0100000007000000",
            )
        );

        let mut d = XcdrDecoder::new(&out).expect("valid CDR_LE header");
        assert_eq!(d.read_string().unwrap(), "ECU-1");
        assert!((d.read_f64().unwrap() - 95.5).abs() < 1e-9);
        assert_eq!(d.read_i64().unwrap(), 1749000000000);
        assert!(d.read_bool().unwrap());
        assert_eq!(d.read_u32().unwrap(), 7);
        assert_eq!(d.remaining(), 0);
    }

    //fusa:test REQ-RTPS-063
    //fusa:test REQ-RTPS-064
    #[test]
    fn int32_sequence_matches_go_dds_reference() {
        // A sequence<long> is composed from a uint32 element count followed
        // by that many int32 writes — this package has no dedicated
        // "write_i32_seq" any more than go-DDS's cdr.Encoder has a
        // WriteInt32Seq; callers compose it exactly like this.
        let mut e = XcdrEncoder::new();
        e.write_u32(3);
        e.write_i32(10);
        e.write_i32(-20);
        e.write_i32(30);
        let out = e.into_bytes();
        assert_eq!(
            hex::encode(&out),
            "01000000030000000a000000ecffffff1e000000"
        );

        let mut d = XcdrDecoder::new(&out).unwrap();
        let n = d.read_u32().unwrap();
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(d.read_i32().unwrap());
        }
        assert_eq!(v, vec![10, -20, 30]);
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn nested_struct_matches_go_dds_reference() {
        // Simulates struct Outer { short id; struct { double x; double y; }
        // inner; bool flag; } — a nested struct is just its fields' writes
        // in sequence, no distinct "nested" encoding.
        let mut e = XcdrEncoder::new();
        e.write_i16(7);
        e.write_f64(1.0);
        e.write_f64(-2.5);
        e.write_bool(false);
        let out = e.into_bytes();
        assert_eq!(
            hex::encode(&out),
            "0100000007000000000000000000f03f00000000000004c000"
        );

        let mut d = XcdrDecoder::new(&out).unwrap();
        assert_eq!(d.read_i16().unwrap(), 7);
        assert_eq!(d.read_f64().unwrap(), 1.0);
        assert_eq!(d.read_f64().unwrap(), -2.5);
        assert!(!d.read_bool().unwrap());
    }

    //fusa:test REQ-RTPS-064
    #[test]
    fn string_sequence_matches_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_u32(2);
        e.write_string("ab");
        e.write_string("cde");
        let out = e.into_bytes();
        assert_eq!(
            hex::encode(&out),
            "010000000200000003000000616200000400000063646500"
        );

        let mut d = XcdrDecoder::new(&out).unwrap();
        let n = d.read_u32().unwrap();
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(d.read_string().unwrap());
        }
        assert_eq!(v, vec!["ab".to_string(), "cde".to_string()]);
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn integer_boundary_values_match_go_dds_reference() {
        let mut e = XcdrEncoder::new();
        e.write_i8(i8::MIN);
        e.write_i8(i8::MAX);
        e.write_i16(i16::MIN);
        e.write_i16(i16::MAX);
        e.write_i32(i32::MIN);
        e.write_i32(i32::MAX);
        e.write_i64(i64::MIN);
        e.write_i64(i64::MAX);
        let out = e.into_bytes();
        assert_eq!(
            hex::encode(&out),
            concat!(
                "01000000807f0080ff7f000000000080ffffff7f",
                "000000000000000000000080",
                "ffffffffffffff7f",
            )
        );

        let mut d = XcdrDecoder::new(&out).unwrap();
        assert_eq!(d.read_i8().unwrap(), i8::MIN);
        assert_eq!(d.read_i8().unwrap(), i8::MAX);
        assert_eq!(d.read_i16().unwrap(), i16::MIN);
        assert_eq!(d.read_i16().unwrap(), i16::MAX);
        assert_eq!(d.read_i32().unwrap(), i32::MIN);
        assert_eq!(d.read_i32().unwrap(), i32::MAX);
        assert_eq!(d.read_i64().unwrap(), i64::MIN);
        assert_eq!(d.read_i64().unwrap(), i64::MAX);
    }

    //fusa:test REQ-RTPS-063
    #[test]
    fn char_round_trips() {
        // No go-DDS reference case: go's cdr package has no dedicated
        // char write/read (Go callers use WriteUint8/ReadUint8 directly
        // for a `char` IDL field), so this is a protocol-behaviour test
        // of the Rust-idiomatic `char` convenience wrapper only, not a
        // byte-exact comparison.
        let mut e = XcdrEncoder::new();
        e.write_char('Q');
        let out = e.into_bytes();
        assert_eq!(hex::encode(&out), "0100000051");
        let mut d = XcdrDecoder::new(&out).unwrap();
        assert_eq!(d.read_char().unwrap(), 'Q');
    }

    //fusa:test REQ-RTPS-065
    //fusa:test REQ-RTPS-009
    #[test]
    fn decoder_rejects_short_header_and_bad_scheme() {
        assert_eq!(
            XcdrDecoder::new(&[0x01, 0x00, 0x00]).unwrap_err(),
            RtpsDecodeError::Truncated {
                expected: 4,
                got: 3
            }
        );
        assert_eq!(
            XcdrDecoder::new(&[0xFF, 0xFF, 0x00, 0x00]).unwrap_err(),
            RtpsDecodeError::InvalidCdrScheme { got: 0xFFFF }
        );
    }

    //fusa:test REQ-RTPS-065
    #[test]
    fn decoder_accepts_cdr_be_header_byte_but_decodes_le_content() {
        // Matches go-DDS's cdr.NewDecoder: scheme 0x0000 (CDR_BE) is
        // accepted on the header without switching decode endianness.
        let mut buf = vec![0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&0xABu8.to_le_bytes());
        let mut d = XcdrDecoder::new(&buf).unwrap();
        assert_eq!(d.read_u8().unwrap(), 0xAB);
    }

    //fusa:test REQ-RTPS-065
    //fusa:test REQ-RTPS-009
    #[test]
    fn decoder_reports_underrun_without_panicking() {
        let e = XcdrEncoder::new();
        let out = e.into_bytes();
        let mut d = XcdrDecoder::new(&out).unwrap();
        assert!(d.read_bool().is_err());

        let mut e2 = XcdrEncoder::new();
        e2.write_i32(1);
        let out2 = e2.into_bytes();
        let mut d2 = XcdrDecoder::new(&out2).unwrap();
        assert_eq!(d2.read_i32().unwrap(), 1);
        assert!(d2.read_i32().is_err());
    }

    //fusa:test REQ-RTPS-066
    //fusa:test REQ-RTPS-009
    #[test]
    fn decoder_reports_underrun_on_truncated_string_and_bytes_without_panicking() {
        let mut e = XcdrEncoder::new();
        e.write_u32(100); // claims 100 bytes of string data that never follow
        let out = e.into_bytes();
        let mut d = XcdrDecoder::new(&out).unwrap();
        assert!(d.read_string().is_err());

        let mut e2 = XcdrEncoder::new();
        e2.write_u32(4); // claims 4 bytes of sequence data that never follow
        let out2 = e2.into_bytes();
        let mut d2 = XcdrDecoder::new(&out2).unwrap();
        assert!(d2.read_bytes_seq().is_err());
    }

    //fusa:test REQ-RTPS-066
    #[test]
    fn decoder_zero_length_string_is_empty() {
        let mut e = XcdrEncoder::new();
        e.write_u32(0);
        let out = e.into_bytes();
        let mut d = XcdrDecoder::new(&out).unwrap();
        assert_eq!(d.read_string().unwrap(), "");
    }

    //fusa:test REQ-RTPS-066
    #[test]
    fn round_trip_bytes_seq() {
        let mut e = XcdrEncoder::new();
        e.write_bytes_seq(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
        let out = e.into_bytes();
        let mut d = XcdrDecoder::new(&out).unwrap();
        assert_eq!(
            d.read_bytes_seq().unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]
        );
    }

    //fusa:test REQ-RTPS-066
    #[test]
    fn decoder_handles_invalid_utf8_losslessly_without_panicking() {
        // Manually crafted CDR string with an invalid UTF-8 byte inside —
        // a malformed/hostile peer must not be able to abort decoding.
        let mut buf = CDR_LE.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0x00, 0x00]); // encapsulation option bytes
        let invalid = [0xFFu8, b'x', 0x00]; // invalid UTF-8 lead byte + 'x' + NUL
        buf.extend_from_slice(&(invalid.len() as u32).to_le_bytes());
        buf.extend_from_slice(&invalid);
        let mut d = XcdrDecoder::new(&buf).unwrap();
        // Never panics; produces the Unicode replacement character for the
        // invalid byte instead of erroring out.
        let s = d.read_string().unwrap();
        assert!(s.contains('x'));
    }
}
