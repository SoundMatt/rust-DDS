// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`HmacPlugin`] — an HMAC-SHA-256 message-integrity [`SecurityPlugin`].
//!
//! Direct port of go-DDS's `security.HMACPlugin`
//! (`github.com/SoundMatt/go-DDS`, `security/security.go`). go-DDS's own
//! doc comment for the type states the property this port preserves
//! exactly: "`HMACPlugin` appends an HMAC-SHA-256 authentication tag to
//! each payload. It provides integrity and peer authentication but NOT
//! confidentiality — the payload travels in plaintext. Use when
//! eavesdropping is not a concern but tampering or spoofing must be
//! detected."
//!
//! Wire format, identical to go-DDS's `| plaintext... | HMAC[32] |`:
//!
//! ```text
//! | plaintext (variable length) | HMAC-SHA-256 tag (32 bytes) |
//! ```
//!
//! This is `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" second
//! checklist item ("HMAC-SHA-256 integrity plugin"). Confidentiality
//! (encryption) is explicitly out of scope for this plugin, matching
//! go-DDS: an AES-256-GCM encryption plugin (go-DDS's `AESGCMPlugin`) is a
//! separate, later checklist item under the same milestone. Likewise,
//! wiring `seal`/`open` calls into
//! `crate::rtps::participant::RtpsParticipant`'s write/receive paths
//! remains deferred, per the `plugin` module's own scoping note — this
//! plugin is a transport-agnostic `SecurityPlugin` implementation only.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::plugin::{SecurityError, SecurityPlugin};

/// HMAC-SHA-256 tag length in bytes, per RFC 6234's SHA-256 output size.
/// go-DDS's `security.go` defines the equivalent unexported `hmacSize =
/// 32` constant.
const HMAC_TAG_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// An HMAC-SHA-256 message-integrity [`SecurityPlugin`]: [`seal`](
/// SecurityPlugin::seal) appends a 32-byte HMAC-SHA-256 tag computed over
/// the plaintext, and [`open`](SecurityPlugin::open) verifies that tag
/// (in constant time, via [`hmac::Mac::verify_slice`]) before stripping it
/// and returning the original plaintext.
///
/// Direct port of go-DDS's `security.HMACPlugin` / `NewHMACPlugin`. Like
/// its go-DDS counterpart, `HmacPlugin` provides integrity and
/// authentication (a peer without the shared key cannot produce a tag
/// that verifies, and any bit-flip in transit is detected) but **not**
/// confidentiality: the plaintext itself is not encrypted and travels in
/// the clear as the first `len(plaintext)` bytes of the sealed output.
///
/// # Key material
///
/// Any key length is accepted (HMAC's construction pads short keys and
/// hashes long ones internally, per RFC 2104), matching go-DDS's
/// `NewHMACPlugin`, which likewise performs no minimum-length check on
/// this plugin's key — unlike the *discovery* HMAC plugin (go-DDS's
/// `HMACDiscoveryPlugin`, a separate, later checklist item not
/// implemented here), which does enforce a 16-byte minimum. Callers
/// wanting a strong key should supply at least 32 bytes of
/// cryptographically random data.
//fusa:req REQ-SEC-020
//fusa:req REQ-SEC-021
#[derive(Clone)]
pub struct HmacPlugin {
    key: Vec<u8>,
}

impl HmacPlugin {
    /// Creates an `HmacPlugin` keyed with `key`.
    ///
    /// `key` is copied into the plugin (mirroring go-DDS's
    /// `NewHMACPlugin`, which copies its input slice rather than
    /// retaining the caller's backing array). No minimum key length is
    /// enforced — see the type-level docs.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Computes an `HmacSha256` instance keyed with this plugin's key.
    ///
    /// `Hmac::<Sha256>::new_from_slice` only returns `Err` for key
    /// lengths its underlying block cipher rejects; HMAC accepts any key
    /// length (RFC 2104), so this never fails in practice for the `Vec<u8>`
    /// keys this plugin stores. The `Result` is still handled explicitly
    /// rather than `.unwrap()`ed, per this crate's no-`.unwrap()`-on-
    /// user-visible-paths convention (REQ-ASIL-003): a failure here is
    /// surfaced as [`SecurityError::Other`] rather than panicking.
    fn keyed_mac(&self) -> Result<HmacSha256, SecurityError> {
        HmacSha256::new_from_slice(&self.key)
            .map_err(|e| SecurityError::Other(format!("HMAC key error: {e}")))
    }
}

impl SecurityPlugin for HmacPlugin {
    /// Appends a 32-byte HMAC-SHA-256 tag, computed over `plaintext`
    /// under this plugin's key, to the end of `plaintext`.
    ///
    /// Matches go-DDS's `HMACPlugin.Seal`, which returns `len(plaintext)
    /// + 32` bytes: the plaintext unchanged, followed by the tag.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let mut mac = self.keyed_mac()?;
        mac.update(plaintext);
        let tag = mac.finalize().into_bytes();

        let mut out = Vec::with_capacity(plaintext.len() + HMAC_TAG_LEN);
        out.extend_from_slice(plaintext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Verifies the trailing 32-byte HMAC-SHA-256 tag against the
    /// leading plaintext of `ciphertext`, returning the plaintext with
    /// the tag stripped on success.
    ///
    /// Matches go-DDS's `HMACPlugin.Open`: returns
    /// [`SecurityError::PayloadTooShort`] if `ciphertext` is shorter than
    /// the 32-byte tag (go-DDS: `"security: HMAC payload too short"`), or
    /// [`SecurityError::VerificationFailed`] if the tag does not verify
    /// (go-DDS: `"security: HMAC verification failed"`). Tag comparison
    /// is constant-time (via `hmac::Mac::verify_slice`), matching
    /// go-DDS's use of `hmac.Equal`, so `open` does not leak timing
    /// information about how much of a forged tag was correct.
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.len() < HMAC_TAG_LEN {
            return Err(SecurityError::PayloadTooShort);
        }
        let (plaintext, tag) = ciphertext.split_at(ciphertext.len() - HMAC_TAG_LEN);

        let mut mac = self.keyed_mac()?;
        mac.update(plaintext);
        mac.verify_slice(tag)
            .map_err(|_| SecurityError::VerificationFailed)?;

        Ok(plaintext.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Independently-reproducible reference vectors, generated directly
    /// from a fresh clone of go-DDS's own `security.HMACPlugin` (not
    /// hand-derived): for each `(key, plaintext)` pair, `sealed` is
    /// exactly go-DDS's `HMACPlugin{key}.Seal(plaintext)` output. Pinning
    /// these keeps this port byte-exact with the reference implementation
    /// (this crate's established wire-format correctness bar), not just
    /// self-consistent.
    ///
    /// Regenerate by running a small Go program against
    /// `github.com/SoundMatt/go-DDS`'s `security` package:
    ///
    /// ```text
    /// p := security.NewHMACPlugin(key)
    /// sealed, _ := p.Seal(plaintext)
    /// fmt.Println(hex.EncodeToString(sealed))
    /// ```
    //fusa:test REQ-SEC-020
    #[test]
    fn matches_go_dds_reference_vectors() {
        struct Vector {
            key: &'static [u8],
            plaintext: &'static [u8],
            sealed_hex: &'static str,
        }

        let vectors = [
            Vector {
                key: &[0x01; 32],
                plaintext: b"",
                sealed_hex: "2e72eb6626e1d4f7fc6dff111585898f2e37c471a68862f07f10aa2824d57c75",
            },
            Vector {
                key: &[0x02; 32],
                plaintext: b"hello world",
                sealed_hex: "68656c6c6f20776f726c647e497c12e3446669c1448b34107e2a4628fb02eab5122b32f0f25ca342b8b7e8",
            },
            Vector {
                key: b"k",
                plaintext: b"payload",
                sealed_hex: "7061796c6f616453e1cedd550e0e693ce03bafe5ae424d9f292717018d586aaade877481dc824c",
            },
            Vector {
                key: b"super-secret-hmac-key-material!",
                plaintext: b"RELAY interop vector",
                sealed_hex: "52454c415920696e7465726f7020766563746f728231e3a3e2d71c2b32a5f542d2a9dbf8abc27ddb2b037a3d0d3dd7114aa84d5f",
            },
        ];

        for v in vectors {
            let plugin = HmacPlugin::new(v.key.to_vec());
            let sealed = plugin.seal(v.plaintext).unwrap();
            let expected = hex::decode(v.sealed_hex).expect("reference vector hex must decode");
            assert_eq!(
                sealed, expected,
                "HmacPlugin::seal must match go-DDS's HMACPlugin.Seal byte-for-byte"
            );

            // The reference vector's own sealed bytes must also open back
            // to the original plaintext under this port's Open.
            assert_eq!(plugin.open(&expected).unwrap(), v.plaintext);
        }
    }

    /// One further reference vector over a longer (1024-byte) plaintext,
    /// kept separate from the table above for readability, generated the
    /// same way against go-DDS's `HMACPlugin`.
    //fusa:test REQ-SEC-020
    #[test]
    fn matches_go_dds_reference_vector_long_plaintext() {
        let key = [0xABu8; 32];
        let plaintext = [0x5Au8; 1024];
        let expected_hex = "4b614dcb23d80a6e834f543171c6d749dc3bdace28b92be515e12ec72d663522";

        let plugin = HmacPlugin::new(key.to_vec());
        let sealed = plugin.seal(&plaintext).unwrap();
        let (sealed_plaintext, sealed_tag) = sealed.split_at(plaintext.len());
        assert_eq!(sealed_plaintext, &plaintext[..]);
        assert_eq!(hex::encode(sealed_tag), expected_hex);
    }

    /// `seal`/`open` are inverses, matching the general `SecurityPlugin`
    /// contract, across empty, short, and larger plaintexts.
    //fusa:test REQ-SEC-016
    #[test]
    fn seal_open_roundtrip() {
        let plugin = HmacPlugin::new(b"a reasonably long test key".to_vec());
        for plaintext in [&b""[..], b"hello world", &[0x42u8; 1024][..]] {
            let sealed = plugin.seal(plaintext).unwrap();
            assert_eq!(plugin.open(&sealed).unwrap(), plaintext);
        }
    }

    /// `seal` appends exactly 32 bytes to the plaintext, matching go-DDS's
    /// `TestHMACPlugin_TagApended`.
    //fusa:test REQ-SEC-020
    #[test]
    fn seal_appends_32_byte_tag() {
        let plugin = HmacPlugin::new(b"key material".to_vec());
        let plaintext = b"payload";
        let sealed = plugin.seal(plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + HMAC_TAG_LEN);
        assert_eq!(&sealed[..plaintext.len()], plaintext);
    }

    /// `open` rejects a payload shorter than the 32-byte tag with
    /// `PayloadTooShort`, matching go-DDS's `TestHMACPlugin_TooShort`
    /// ("security: HMAC payload too short").
    //fusa:test REQ-SEC-021
    #[test]
    fn open_rejects_payload_shorter_than_tag() {
        let plugin = HmacPlugin::new(b"key".to_vec());
        for short in [&b""[..], b"short", &[0u8; 31][..]] {
            assert_eq!(plugin.open(short), Err(SecurityError::PayloadTooShort));
        }
    }

    /// A payload of exactly 32 bytes (all tag, no plaintext) is long
    /// enough to attempt verification — it must not be rejected by the
    /// length check, though it will (correctly) fail verification since
    /// 32 zero bytes is not a valid tag for an empty plaintext under any
    /// key with overwhelming probability.
    //fusa:test REQ-SEC-021
    #[test]
    fn open_accepts_exactly_tag_length_input_for_length_check() {
        let plugin = HmacPlugin::new(b"key".to_vec());
        let result = plugin.open(&[0u8; HMAC_TAG_LEN]);
        // Not PayloadTooShort — the 32-byte input clears the length
        // check, so any failure here must be VerificationFailed.
        assert_ne!(result, Err(SecurityError::PayloadTooShort));
    }

    /// `open` detects a tampered payload: flipping a single plaintext bit
    /// after `seal` invalidates the tag, matching go-DDS's
    /// `TestHMACPlugin_TamperDetected`.
    //fusa:test REQ-SEC-021
    #[test]
    fn open_detects_tampered_plaintext() {
        let plugin = HmacPlugin::new(b"integrity key".to_vec());
        let mut sealed = plugin.seal(b"important data").unwrap();
        sealed[0] ^= 0xFF;
        assert_eq!(plugin.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// `open` detects a tampered (corrupted) tag, distinct from a
    /// tampered-plaintext corruption above.
    //fusa:test REQ-SEC-021
    #[test]
    fn open_detects_tampered_tag() {
        let plugin = HmacPlugin::new(b"integrity key".to_vec());
        let mut sealed = plugin.seal(b"important data").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert_eq!(plugin.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// `open` detects a truncated (but still >= 32-byte) tag: dropping
    /// trailing bytes of a validly-sealed payload changes both the
    /// plaintext/tag split point and the tag itself, so verification
    /// must fail rather than silently accepting a shorter plaintext.
    //fusa:test REQ-SEC-021
    #[test]
    fn open_detects_truncated_ciphertext() {
        let plugin = HmacPlugin::new(b"integrity key".to_vec());
        let sealed = plugin.seal(b"important data, truncate me").unwrap();
        let truncated = &sealed[..sealed.len() - 5];
        // Still >= HMAC_TAG_LEN bytes, so this exercises verification
        // failure, not the too-short path.
        assert!(truncated.len() >= HMAC_TAG_LEN);
        assert_eq!(
            plugin.open(truncated),
            Err(SecurityError::VerificationFailed)
        );
    }

    /// `open` run with a different key than the one used to `seal`
    /// fails verification, matching go-DDS's `TestHMACPlugin_WrongKey`.
    //fusa:test REQ-SEC-021
    #[test]
    fn open_with_wrong_key_fails() {
        let sealer = HmacPlugin::new(b"key one".to_vec());
        let opener = HmacPlugin::new(b"key two".to_vec());
        let sealed = sealer.seal(b"secret").unwrap();
        assert_eq!(opener.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// Two plugins keyed identically produce identical tags for the same
    /// plaintext, and either can open what the other sealed — the key,
    /// not plugin identity, determines interoperability.
    //fusa:test REQ-SEC-020
    #[test]
    fn same_key_interoperates_across_plugin_instances() {
        let a = HmacPlugin::new(b"shared key".to_vec());
        let b = HmacPlugin::new(b"shared key".to_vec());
        let sealed = a.seal(b"cross-instance").unwrap();
        assert_eq!(b.open(&sealed).unwrap(), b"cross-instance");
    }

    /// Any key length is accepted at construction, including very short
    /// and empty keys — matching go-DDS's `NewHMACPlugin`, which performs
    /// no minimum-length validation (unlike the separate discovery HMAC
    /// plugin).
    #[test]
    fn accepts_any_key_length() {
        for key in [&b""[..], b"x", &[0u8; 1024][..]] {
            let plugin = HmacPlugin::new(key.to_vec());
            let sealed = plugin.seal(b"data").unwrap();
            assert_eq!(plugin.open(&sealed).unwrap(), b"data");
        }
    }

    /// `HmacPlugin` is object-safe: usable as `Box<dyn SecurityPlugin>`
    /// and `Arc<dyn SecurityPlugin>`, the same property `NullPlugin` is
    /// tested for in `plugin::tests::object_safety`.
    //fusa:test REQ-SEC-017
    #[test]
    fn object_safety() {
        let boxed: Box<dyn SecurityPlugin> = Box::new(HmacPlugin::new(b"boxed key".to_vec()));
        let sealed = boxed.seal(b"boxed").unwrap();
        assert_eq!(boxed.open(&sealed).unwrap(), b"boxed");

        let arced: Arc<dyn SecurityPlugin> = Arc::new(HmacPlugin::new(b"arced key".to_vec()));
        let sealed = arced.seal(b"arced").unwrap();
        assert_eq!(arced.open(&sealed).unwrap(), b"arced");
    }

    /// `HmacPlugin` is usable across concurrent tokio tasks: a single
    /// `Arc<dyn SecurityPlugin>` is shared and called from multiple
    /// spawned tasks, mirroring `plugin::tests::plugin_usable_across_concurrent_tasks`
    /// for this concrete, non-trivial plugin. Compiling and passing this
    /// test is itself proof of the `Send + Sync` bound.
    //fusa:test REQ-SEC-018
    #[tokio::test]
    async fn plugin_usable_across_concurrent_tasks() {
        let plugin: Arc<dyn SecurityPlugin> =
            Arc::new(HmacPlugin::new(b"concurrent-tasks key".to_vec()));
        let mut handles = Vec::new();
        for i in 0u8..8 {
            let plugin = Arc::clone(&plugin);
            handles.push(tokio::spawn(async move {
                let payload = vec![i; 16];
                let sealed = plugin.seal(&payload).unwrap();
                assert_eq!(plugin.open(&sealed).unwrap(), payload);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// Compile-time assertion helper mirroring `plugin::tests`'s
    /// `null_plugin_is_send_sync`, pinning that `HmacPlugin` itself (not
    /// just a `Box`/`Arc` around it) meets the `Send + Sync` bound.
    //fusa:test REQ-SEC-018
    #[test]
    fn hmac_plugin_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HmacPlugin>();
    }
}
