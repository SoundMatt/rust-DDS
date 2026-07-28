// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`AesGcmPlugin`] — an AES-256-GCM confidentiality-and-integrity
//! [`SecurityPlugin`].
//!
//! Direct port of go-DDS's `security.AESGCMPlugin`
//! (`github.com/SoundMatt/go-DDS`, `security/security.go`). go-DDS's own
//! doc comment for the type states the property this port preserves
//! exactly: "`AESGCMPlugin` encrypts payloads with AES-256-GCM
//! (authenticated encryption). It provides confidentiality, integrity, and
//! authenticity. Each `Seal` call generates a fresh 12-byte random nonce
//! prepended to the ciphertext."
//!
//! Wire format, identical to go-DDS's `| nonce[12] | ciphertext... |
//! GCM-tag[16] |`:
//!
//! ```text
//! | nonce (12 bytes) | ciphertext (variable length) | GCM tag (16 bytes) |
//! ```
//!
//! This is `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" third
//! checklist item ("AES-256-GCM encryption plugin"), the first of the
//! milestone's plugins to add **confidentiality**: unlike
//! [`crate::security::hmac::HmacPlugin`], which authenticates a plaintext
//! payload that still travels in the clear, `AesGcmPlugin` encrypts the
//! payload itself. A topic ACL (`AccessPolicy`), an anti-replay guard
//! (`ReplayGuard`), and HMAC-SHA-256 discovery authentication remain
//! separate, later checklist items under the same milestone, not
//! implemented here. Likewise, wiring `seal`/`open` calls into
//! `crate::rtps::participant::RtpsParticipant`'s write/receive paths
//! remains deferred, per the `plugin` module's own scoping note — this
//! plugin is a transport-agnostic `SecurityPlugin` implementation only.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use super::plugin::{SecurityError, SecurityPlugin};

/// AES-GCM nonce length in bytes (96 bits), the standard/recommended nonce
/// size for AES-GCM per NIST SP 800-38D and the size go-DDS's
/// `security.go` uses (`p.aead.NonceSize()`, which for `cipher.NewGCM` is
/// always 12).
const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes (128 bits) — the standard
/// GCM tag size and the value go-DDS's `security.go` gets from
/// `p.aead.Overhead()`.
const TAG_LEN: usize = 16;

/// An AES-256-GCM confidentiality-and-integrity [`SecurityPlugin`]:
/// [`seal`](SecurityPlugin::seal) encrypts the plaintext under a fresh,
/// randomly generated 12-byte nonce and prepends that nonce to the
/// resulting ciphertext (which itself has the 16-byte GCM tag appended, an
/// artifact of the underlying AEAD's postfix-tag convention); [`open`](
/// SecurityPlugin::open) splits the nonce back off, decrypts, and verifies
/// the tag.
///
/// Direct port of go-DDS's `security.AESGCMPlugin` / `NewAESGCMPlugin`.
/// Unlike [`crate::security::hmac::HmacPlugin`], `AesGcmPlugin` provides
/// full confidentiality (the payload is encrypted, not merely
/// authenticated) in addition to integrity and authenticity.
///
/// # Key material
///
/// The key must be exactly 32 bytes (AES-256), matching go-DDS's
/// `NewAESGCMPlugin`, which returns an error for any other length rather
/// than accepting and truncating/padding a mismatched key.
///
/// # Nonce uniqueness
///
/// Every [`seal`](SecurityPlugin::seal) call draws a fresh nonce from the
/// OS's cryptographically secure random number generator, matching
/// go-DDS's use of `crypto/rand.Reader` via `io.ReadFull`. AES-GCM's
/// security guarantees depend on a nonce never being reused under the same
/// key; a 96-bit random nonce makes accidental collision astronomically
/// unlikely across the sample volumes any single `AesGcmPlugin` instance
/// will realistically seal.
//fusa:req REQ-SEC-022
//fusa:req REQ-SEC-023
#[derive(Clone)]
pub struct AesGcmPlugin {
    cipher: Aes256Gcm,
}

impl AesGcmPlugin {
    /// Creates an `AesGcmPlugin` keyed with `key`.
    ///
    /// Matches go-DDS's `NewAESGCMPlugin`: returns
    /// [`SecurityError::Other`] (go-DDS: `"security: AES-GCM key must be
    /// 32 bytes (AES-256)"`) if `key` is not exactly 32 bytes, rather than
    /// silently accepting a mismatched key length the way
    /// [`crate::security::hmac::HmacPlugin::new`] does for HMAC keys.
    pub fn new(key: &[u8]) -> Result<Self, SecurityError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
            SecurityError::Other("AES-GCM key must be 32 bytes (AES-256)".to_string())
        })?;
        Ok(Self { cipher })
    }
}

impl SecurityPlugin for AesGcmPlugin {
    /// Encrypts `plaintext` under a fresh random 12-byte nonce, returning
    /// `nonce || ciphertext || tag`.
    ///
    /// Matches go-DDS's `AESGCMPlugin.Seal`, which returns
    /// `p.aead.Seal(nonce, nonce, plaintext, nil)` after generating
    /// `nonce` via `crypto/rand.Reader`: the output is exactly
    /// `len(plaintext) + 12 + 16` bytes (28 bytes of framing overhead per
    /// sample). The OS random source is read via [`OsRng::try_fill_bytes`]
    /// rather than the panicking `fill_bytes`, so an OS RNG failure
    /// surfaces as [`SecurityError::Other`] instead of a panic, per this
    /// crate's no-`.unwrap()`/no-panic-on-user-visible-paths convention
    /// (REQ-ASIL-003).
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| SecurityError::Other(format!("AES-GCM nonce generation failed: {e}")))?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| SecurityError::Other("AES-GCM nonce framing error".to_string()))?;

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SecurityError::Other("AES-GCM encryption failed".to_string()))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Splits the leading 12-byte nonce off `ciphertext`, then decrypts
    /// and verifies the remainder, returning the original plaintext.
    ///
    /// Matches go-DDS's `AESGCMPlugin.Open`: returns
    /// [`SecurityError::PayloadTooShort`] if `ciphertext` is shorter than
    /// `12 + 16 = 28` bytes (go-DDS: `"security: AES-GCM payload too
    /// short"`, checked as `len(data) < ns+p.aead.Overhead()`), or
    /// [`SecurityError::VerificationFailed`] if authenticated decryption
    /// fails — a tampered nonce, tampered ciphertext, tampered tag, or a
    /// key mismatch all surface identically, matching AEAD decryption's
    /// standard failure semantics (go-DDS: the bare `p.aead.Open` error).
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(SecurityError::PayloadTooShort);
        }
        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce_bytes)
            .map_err(|_| SecurityError::Other("AES-GCM nonce framing error".to_string()))?;

        self.cipher
            .decrypt(&nonce, ct)
            .map_err(|_| SecurityError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const KEY_32: [u8; 32] = [0x11; 32];

    /// Independently-reproducible reference vectors pinning this port's
    /// wire format byte-for-byte against go-DDS's `security.AESGCMPlugin`
    /// wire format. `AESGCMPlugin.Seal` itself always draws a fresh random
    /// nonce (via `crypto/rand.Reader`), so unlike `HmacPlugin`'s
    /// deterministic reference vectors, its own output cannot be pinned
    /// directly — go-DDS's own `security_test.go` does not attempt this
    /// either, instead verifying `AESGCMPlugin` behaviourally (round-trip,
    /// distinct-nonce, tamper-detection, wrong-key rejection; mirrored
    /// below by this module's other tests).
    ///
    /// These vectors instead pin the *wire format itself*: each was
    /// produced by a small standalone Go program
    /// (`aes.NewCipher(key)` -> `cipher.NewGCM(block)` ->
    /// `aead.Seal(nonce, nonce, plaintext, nil)`) that reimplements
    /// exactly the three stdlib calls `AESGCMPlugin.Seal` makes
    /// internally, substituting an explicit fixed nonce for
    /// `crypto/rand.Reader`'s random one — the same
    /// `aes.NewCipher`/`cipher.NewGCM`/`Seal(nonce, nonce, ...)` sequence,
    /// against the same Go standard-library AES-GCM implementation, just
    /// with reproducible input. Since Go's `crypto/cipher.NewGCM` and this
    /// port's `aes_gcm::Aes256Gcm` both implement the same NIST SP 800-38D
    /// AES-GCM construction (96-bit nonce, 128-bit tag, `Seal`/`encrypt`
    /// producing `nonce || ciphertext || tag` under postfix-tag
    /// convention), a match here proves this port's *decryption* of a
    /// go-DDS-produced payload — and its *wire format for encryption* —
    /// are byte-exact with the reference implementation, which is what
    /// interop requires; only the random nonce a live `AESGCMPlugin.Seal`
    /// call would choose is untestable directly, and that is a property of
    /// `crypto/rand`, not of the wire format.
    //fusa:test REQ-SEC-022
    #[test]
    fn matches_go_dds_reference_vectors() {
        struct Vector {
            key: [u8; 32],
            nonce: [u8; 12],
            plaintext: &'static [u8],
            sealed_hex: &'static str,
        }

        let vectors = [
            Vector {
                key: [0x01; 32],
                nonce: [0x00; 12],
                plaintext: b"",
                sealed_hex: "000000000000000000000000aea8ae8944b639cd082adec4fed32207",
            },
            Vector {
                key: [0x02; 32],
                nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                plaintext: b"hello world",
                sealed_hex: "000102030405060708090a0b216d8e96be69fb2b59e4248824d8be2fd12728156e26cd00b0eb38",
            },
            Vector {
                key: *b"this-is-a-32-byte-aes-256-key!!!",
                nonce: [0xAB; 12],
                plaintext: b"RELAY interop vector",
                sealed_hex: "abababababababababababab2c91cfc0b6428ab7eaa7ea9bc8adf162d368c9913d8dc42202cdb1eb0087e6679b37e781",
            },
        ];

        for v in vectors {
            let expected = hex::decode(v.sealed_hex).expect("reference vector hex must decode");

            // This port's Open must decrypt go-DDS's reference ciphertext
            // back to the exact original plaintext (proves decrypt-side
            // byte-exactness and wire-format compatibility).
            let plugin = AesGcmPlugin::new(&v.key).unwrap();
            assert_eq!(plugin.open(&expected).unwrap(), v.plaintext);

            // This port's own encryption, given the *same* fixed nonce
            // go-DDS used (bypassing this plugin's own random nonce
            // generation to isolate the AEAD construction itself), must
            // reproduce go-DDS's sealed bytes exactly (proves encrypt-side
            // byte-exactness).
            let nonce = Nonce::try_from(v.nonce.as_slice()).unwrap();
            let ciphertext = plugin.cipher.encrypt(&nonce, v.plaintext).unwrap();
            let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
            sealed.extend_from_slice(&v.nonce);
            sealed.extend_from_slice(&ciphertext);
            assert_eq!(
                sealed, expected,
                "AesGcmPlugin's AEAD construction must match go-DDS's AESGCMPlugin byte-for-byte \
                 given the same key, nonce, and plaintext"
            );
        }
    }

    /// `seal`/`open` are inverses, matching the general `SecurityPlugin`
    /// contract, across empty, short, and larger plaintexts.
    //fusa:test REQ-SEC-016
    #[test]
    fn seal_open_roundtrip() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        for plaintext in [&b""[..], b"hello world", &[0x42u8; 1024][..]] {
            let sealed = plugin.seal(plaintext).unwrap();
            assert_eq!(plugin.open(&sealed).unwrap(), plaintext);
        }
    }

    /// `seal` expands the plaintext by exactly 28 bytes (12-byte nonce +
    /// 16-byte GCM tag), matching go-DDS's documented "Payload overhead:
    /// 28 bytes per sample."
    //fusa:test REQ-SEC-022
    #[test]
    fn seal_adds_28_bytes_of_overhead() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let plaintext = b"payload";
        let sealed = plugin.seal(plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + NONCE_LEN + TAG_LEN);
    }

    /// Two `seal` calls over identical plaintext produce different
    /// ciphertexts because each draws an independent random nonce,
    /// matching go-DDS's `TestAESGCMPlugin_DistinctNonces`.
    //fusa:test REQ-SEC-022
    #[test]
    fn seal_uses_distinct_nonces() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let a = plugin.seal(b"same plaintext").unwrap();
        let b = plugin.seal(b"same plaintext").unwrap();
        assert_ne!(
            a, b,
            "two Seal calls produced identical output (nonce reuse)"
        );
        // The nonces themselves (the leading 12 bytes) must differ.
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    /// `open` rejects a payload shorter than nonce+tag (28 bytes) with
    /// `PayloadTooShort`, matching go-DDS's `TestAESGCMPlugin_TooShort`
    /// ("security: AES-GCM payload too short").
    //fusa:test REQ-SEC-023
    #[test]
    fn open_rejects_payload_shorter_than_nonce_plus_tag() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        for short in [&b""[..], b"short", &[0u8; NONCE_LEN + TAG_LEN - 1][..]] {
            assert_eq!(plugin.open(short), Err(SecurityError::PayloadTooShort));
        }
    }

    /// A payload of exactly 28 bytes (nonce + tag, no ciphertext) is long
    /// enough to attempt decryption — it must not be rejected by the
    /// length check, though it will (correctly) fail authentication since
    /// 16 zero bytes is not a valid GCM tag for an empty ciphertext under
    /// any key with overwhelming probability.
    //fusa:test REQ-SEC-023
    #[test]
    fn open_accepts_exactly_nonce_plus_tag_length_input_for_length_check() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let result = plugin.open(&[0u8; NONCE_LEN + TAG_LEN]);
        assert_ne!(result, Err(SecurityError::PayloadTooShort));
    }

    /// `open` detects a tampered ciphertext body: flipping a bit strictly
    /// inside the encrypted plaintext region invalidates the GCM tag.
    //fusa:test REQ-SEC-023
    #[test]
    fn open_detects_tampered_ciphertext() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let mut sealed = plugin.seal(b"important data").unwrap();
        let mid = NONCE_LEN + 1; // first byte strictly inside the ciphertext
        sealed[mid] ^= 0xFF;
        assert_eq!(plugin.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// `open` detects a tampered GCM tag (the trailing 16 bytes), distinct
    /// from a tampered-ciphertext-body corruption above, matching go-DDS's
    /// `TestAESGCMPlugin_TamperDetected` ("corrupt last byte of GCM tag").
    //fusa:test REQ-SEC-023
    #[test]
    fn open_detects_tampered_tag() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let mut sealed = plugin.seal(b"sensitive").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert_eq!(plugin.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// `open` detects a tampered nonce: AES-GCM's authentication covers
    /// the nonce implicitly (decrypting under the wrong nonce yields a
    /// different keystream/GHASH input), so flipping a nonce byte must
    /// also fail verification.
    //fusa:test REQ-SEC-023
    #[test]
    fn open_detects_tampered_nonce() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let mut sealed = plugin.seal(b"sensitive").unwrap();
        sealed[0] ^= 0xFF;
        assert_eq!(plugin.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// `open` detects a truncated (but still >= 28-byte) payload: dropping
    /// trailing bytes changes the ciphertext/tag split, so authentication
    /// must fail rather than silently accepting a shorter plaintext.
    //fusa:test REQ-SEC-023
    #[test]
    fn open_detects_truncated_ciphertext() {
        let plugin = AesGcmPlugin::new(&KEY_32).unwrap();
        let sealed = plugin.seal(b"important data, truncate me").unwrap();
        let truncated = &sealed[..sealed.len() - 5];
        assert!(truncated.len() >= NONCE_LEN + TAG_LEN);
        assert_eq!(
            plugin.open(truncated),
            Err(SecurityError::VerificationFailed)
        );
    }

    /// `open` run with a different key than the one used to `seal` fails
    /// verification, matching go-DDS's `TestAESGCMPlugin_WrongKey`.
    //fusa:test REQ-SEC-023
    #[test]
    fn open_with_wrong_key_fails() {
        let sealer = AesGcmPlugin::new(&[0x01; 32]).unwrap();
        let opener = AesGcmPlugin::new(&[0x02; 32]).unwrap();
        let sealed = sealer.seal(b"secret").unwrap();
        assert_eq!(opener.open(&sealed), Err(SecurityError::VerificationFailed));
    }

    /// Construction rejects any key length other than exactly 32 bytes,
    /// matching go-DDS's `TestAESGCMPlugin_BadKeyLength`.
    //fusa:test REQ-SEC-022
    #[test]
    fn new_rejects_non_32_byte_keys() {
        for key in [
            &b""[..],
            b"tooshort",
            &[0u8; 16][..],
            &[0u8; 31][..],
            &[0u8; 33][..],
        ] {
            assert!(
                AesGcmPlugin::new(key).is_err(),
                "expected error for {}-byte key",
                key.len()
            );
        }
    }

    /// Exactly 32 bytes is accepted.
    //fusa:test REQ-SEC-022
    #[test]
    fn new_accepts_32_byte_key() {
        assert!(AesGcmPlugin::new(&[0u8; 32]).is_ok());
    }

    /// Two plugins keyed identically produce cross-compatible output: a
    /// payload sealed by one opens under the other, matching go-DDS's
    /// same-key-interoperates behaviour for `HMACPlugin` extended here to
    /// `AESGCMPlugin`. Ciphertexts themselves still differ (independent
    /// random nonces), matching `seal_uses_distinct_nonces` above.
    //fusa:test REQ-SEC-022
    #[test]
    fn same_key_interoperates_across_plugin_instances() {
        let a = AesGcmPlugin::new(&KEY_32).unwrap();
        let b = AesGcmPlugin::new(&KEY_32).unwrap();
        let sealed = a.seal(b"cross-instance").unwrap();
        assert_eq!(b.open(&sealed).unwrap(), b"cross-instance");
    }

    /// `AesGcmPlugin` is object-safe: usable as `Box<dyn SecurityPlugin>`
    /// and `Arc<dyn SecurityPlugin>`, the same property `NullPlugin` and
    /// `HmacPlugin` are tested for.
    //fusa:test REQ-SEC-017
    #[test]
    fn object_safety() {
        let boxed: Box<dyn SecurityPlugin> = Box::new(AesGcmPlugin::new(&KEY_32).unwrap());
        let sealed = boxed.seal(b"boxed").unwrap();
        assert_eq!(boxed.open(&sealed).unwrap(), b"boxed");

        let arced: Arc<dyn SecurityPlugin> = Arc::new(AesGcmPlugin::new(&KEY_32).unwrap());
        let sealed = arced.seal(b"arced").unwrap();
        assert_eq!(arced.open(&sealed).unwrap(), b"arced");
    }

    /// `AesGcmPlugin` is usable across concurrent tokio tasks: a single
    /// `Arc<dyn SecurityPlugin>` is shared and called from multiple
    /// spawned tasks, mirroring `hmac::tests::plugin_usable_across_concurrent_tasks`
    /// for this concrete, non-trivial plugin. Compiling and passing this
    /// test is itself proof of the `Send + Sync` bound.
    //fusa:test REQ-SEC-018
    #[tokio::test]
    async fn plugin_usable_across_concurrent_tasks() {
        let plugin: Arc<dyn SecurityPlugin> = Arc::new(AesGcmPlugin::new(&KEY_32).unwrap());
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
    /// `null_plugin_is_send_sync` and `hmac::tests`'s
    /// `hmac_plugin_is_send_sync`, pinning that `AesGcmPlugin` itself (not
    /// just a `Box`/`Arc` around it) meets the `Send + Sync` bound.
    //fusa:test REQ-SEC-018
    #[test]
    fn aes_gcm_plugin_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AesGcmPlugin>();
    }
}
