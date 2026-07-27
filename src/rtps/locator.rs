// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `Locator` — 24-byte transport endpoint address (RTPS 2.3 §9.3.2).
//!
//! Wire layout ported 1:1 from go-DDS's `rtps/locator.go`: `kind` (4-byte
//! little-endian `i32`) + `port` (4-byte little-endian `u32`) + `address`
//! (16 raw bytes — an IPv4 address occupies the last 4 bytes with the first
//! 12 zeroed; an IPv6 address occupies the full 16 bytes).

use super::RtpsDecodeError;

/// 24-byte transport endpoint address (RTPS 2.3 §9.3.2).
//fusa:req REQ-RTPS-003
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Locator {
    pub kind: i32,
    pub port: u32,
    pub address: [u8; 16],
}

/// Sentinel kind: locator not set / invalid.
//fusa:req REQ-RTPS-003
pub const LOCATOR_KIND_INVALID: i32 = -1;
/// UDPv4 transport.
//fusa:req REQ-RTPS-003
pub const LOCATOR_KIND_UDPV4: i32 = 1;
/// UDPv6 transport.
//fusa:req REQ-RTPS-003
pub const LOCATOR_KIND_UDPV6: i32 = 2;

impl Default for Locator {
    fn default() -> Self {
        Locator {
            kind: LOCATOR_KIND_INVALID,
            port: 0,
            address: [0u8; 16],
        }
    }
}

impl Locator {
    /// Wire size in bytes.
    pub const LEN: usize = 24;

    /// Append the 24-byte little-endian wire encoding of this `Locator` to
    /// `buf`.
    //fusa:req REQ-RTPS-003
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.kind.to_le_bytes());
        buf.extend_from_slice(&self.port.to_le_bytes());
        buf.extend_from_slice(&self.address);
    }

    /// Decode a `Locator` from the first 24 bytes of `buf`.
    ///
    /// Returns `Err(RtpsDecodeError::Truncated)` — never panics — if `buf`
    /// is shorter than [`Locator::LEN`].
    //fusa:req REQ-RTPS-003
    //fusa:req REQ-RTPS-009
    pub fn decode(buf: &[u8]) -> Result<Self, RtpsDecodeError> {
        if buf.len() < Self::LEN {
            return Err(RtpsDecodeError::Truncated {
                expected: Self::LEN,
                got: buf.len(),
            });
        }
        let kind = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let port = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut address = [0u8; 16];
        address.copy_from_slice(&buf[8..24]);
        Ok(Locator {
            kind,
            port,
            address,
        })
    }

    /// Build a UDPv4 `Locator` from a 4-byte address and port.
    /// The address is placed in the last 4 bytes of the 16-byte field, per
    /// go-DDS's `locatorFromUDP`.
    //fusa:req REQ-RTPS-003
    pub fn udp_v4(addr: [u8; 4], port: u32) -> Self {
        let mut address = [0u8; 16];
        address[12..16].copy_from_slice(&addr);
        Locator {
            kind: LOCATOR_KIND_UDPV4,
            port,
            address,
        }
    }

    /// Build a UDPv6 `Locator` from a 16-byte address and port.
    //fusa:req REQ-RTPS-003
    pub fn udp_v6(addr: [u8; 16], port: u32) -> Self {
        Locator {
            kind: LOCATOR_KIND_UDPV6,
            port,
            address: addr,
        }
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
    //   loc := Locator{Kind: LocatorKindUDPv4, Port: 7412}
    //   loc.Address[12], loc.Address[13], loc.Address[14], loc.Address[15] = 192, 168, 1, 50
    //   fmt.Printf("%x\n", marshalLocator(loc))
    //   // -> 01000000f41c0000000000000000000000000000c0a80132
    //
    //   loc6 := Locator{Kind: LocatorKindUDPv6, Port: 7412}
    //   copy(loc6.Address[:], []byte{0xFF,0x03,0,0,0,0,0,0,0,0,0,0,0,0,0,1})
    //   fmt.Printf("%x\n", marshalLocator(loc6))
    //   // -> 02000000f41c0000ff030000000000000000000000000001
    //
    // Full run: `go test ./rtps/... -run TestZZReproWireBytes -v`
    // (go-DDS commit 1343891 / rust-DDS branch feat/rtps-wire-types).

    //fusa:test REQ-RTPS-003
    #[test]
    fn udpv4_locator_matches_go_dds_reference() {
        let loc = Locator::udp_v4([192, 168, 1, 50], 7412);
        let mut buf = Vec::new();
        loc.encode(&mut buf);
        assert_eq!(
            hex::encode(&buf),
            "01000000f41c0000000000000000000000000000c0a80132"
        );
        assert_eq!(buf.len(), Locator::LEN);
    }

    //fusa:test REQ-RTPS-003
    #[test]
    fn udpv6_locator_matches_go_dds_reference() {
        let mut addr = [0u8; 16];
        addr[0] = 0xFF;
        addr[1] = 0x03;
        addr[15] = 0x01;
        let loc = Locator::udp_v6(addr, 7412);
        let mut buf = Vec::new();
        loc.encode(&mut buf);
        assert_eq!(
            hex::encode(&buf),
            "02000000f41c0000ff030000000000000000000000000001"
        );
    }

    //fusa:test REQ-RTPS-003
    #[test]
    fn locator_round_trip() {
        let loc = Locator::udp_v4([10, 0, 0, 1], 12345);
        let mut buf = Vec::new();
        loc.encode(&mut buf);
        assert_eq!(Locator::decode(&buf).unwrap(), loc);
    }

    //fusa:test REQ-RTPS-003
    #[test]
    fn invalid_kind_is_negative_one() {
        assert_eq!(Locator::default().kind, LOCATOR_KIND_INVALID);
        assert_eq!(LOCATOR_KIND_INVALID, -1);
        assert_eq!(LOCATOR_KIND_UDPV4, 1);
        assert_eq!(LOCATOR_KIND_UDPV6, 2);
    }

    //fusa:test REQ-RTPS-009
    #[test]
    fn decode_rejects_truncated_input_without_panicking() {
        assert_eq!(
            Locator::decode(&[0u8; 23]),
            Err(RtpsDecodeError::Truncated {
                expected: 24,
                got: 23
            })
        );
        assert_eq!(
            Locator::decode(&[]),
            Err(RtpsDecodeError::Truncated {
                expected: 24,
                got: 0
            })
        );
    }
}
