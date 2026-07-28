// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The [`SecurityPlugin`] trait — the pluggable payload-security extension
//! point, and its trivial [`NullPlugin`] implementation.
//!
//! Direct port of go-DDS's `security.Plugin` interface
//! (`github.com/SoundMatt/go-DDS`, `security/security.go`). go-DDS's own
//! doc comment for the package states the intent this port preserves
//! exactly: "Security is applied at the packet level in the RTPS
//! transport: every outbound payload is passed through Plugin.Seal before
//! transmission, and every inbound payload through Plugin.Open before
//! delivery to the application."
//!
//! This is `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" first
//! checklist item ("Pluggable payload security trait (`SecurityPlugin`)")
//! and only that item: the trait plus [`NullPlugin`] (go-DDS's identity
//! transform, defined in the same file as the interface it implements, so
//! ported alongside it here). Of the five plugins/mechanisms that make the
//! trait do something non-trivial, an HMAC-SHA-256 integrity plugin is now
//! landed as [`crate::security::hmac::HmacPlugin`] (the milestone's second
//! checklist item); an AES-256-GCM encryption plugin, a topic ACL
//! (`AccessPolicy`), an anti-replay guard (`ReplayGuard`), and HMAC-SHA-256
//! discovery authentication remain separate, later checklist items under
//! the same milestone, not implemented here. Likewise, wiring `seal`/`open`
//! calls into `crate::rtps::participant::RtpsParticipant`'s write/receive
//! paths is deferred — including for `HmacPlugin` — until a caller wires
//! a concrete plugin in; the trait itself is transport-agnostic and does
//! not require that wiring to exist or to be tested.

use thiserror::Error;

/// Error returned by a [`SecurityPlugin`]'s [`seal`](SecurityPlugin::seal)
/// or [`open`](SecurityPlugin::open).
///
/// go-DDS's `security.go` returns plain `errors.New("security: ...")`
/// strings from `HMACPlugin`/`AESGCMPlugin` (e.g. "security: HMAC payload
/// too short", "security: HMAC verification failed", "security: AES-GCM
/// payload too short"). This port expresses the same failure categories as
/// a typed enum instead of an opaque string, per this crate's
/// no-`.unwrap()`-on-user-visible-paths convention (REQ-ASIL-003) — every
/// later plugin that implements [`SecurityPlugin`] returns one of these
/// variants rather than inventing its own ad hoc error type.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SecurityError {
    /// The input was shorter than the security transform's minimum
    /// framing requires (e.g. shorter than an appended HMAC tag, or
    /// shorter than a prepended AEAD nonce plus its tag).
    #[error("security: payload too short for the security transform's framing")]
    PayloadTooShort,

    /// Integrity or authenticity verification failed: the payload was
    /// tampered with, corrupted in transit, or sealed under a different
    /// key than the one `open` is using.
    #[error("security: integrity or authenticity verification failed")]
    VerificationFailed,

    /// Any other plugin-specific failure not covered above (e.g. a
    /// malformed key supplied at plugin-construction time). The message
    /// must never include payload bytes, key material, or other secret
    /// data (REQ-SEC-005 — error messages contain no addresses, counters,
    /// or internal state that could assist an attacker).
    #[error("security: {0}")]
    Other(String),
}

/// A pluggable payload-security transform — the extension point that later
/// integrity, encryption, and authentication mechanisms plug into.
///
/// Direct port of go-DDS's `security.Plugin` interface. An implementation
/// seals (signs and/or encrypts) an outbound payload and opens (verifies
/// and/or decrypts) an inbound one; `seal` and `open` must be inverses for
/// any conforming implementation and any plaintext:
///
/// ```text
/// plaintext == plugin.open(&plugin.seal(&plaintext)?)?
/// ```
///
/// `open` must reject (return `Err`, never panic) any input that was not
/// produced by the matching `seal` call — including truncated, corrupted,
/// or maliciously crafted input — since in real use `open` runs on bytes
/// received from an untrusted network peer, not just on `seal`'s own
/// output.
///
/// # Object safety
///
/// `SecurityPlugin` has no generic parameters and both methods take
/// `&self` and return owned types, so the trait is dyn-compatible: a
/// plugin can be chosen at runtime and stored as `Box<dyn SecurityPlugin>`
/// or `Arc<dyn SecurityPlugin>` without the caller knowing the concrete
/// plugin type at compile time — the "pluggable" half of this trait's
/// name. See the `object_safety` test below.
///
/// # Concurrency
///
/// Implementations must be `Send + Sync`, so a single plugin instance can
/// be shared (typically behind an `Arc`) across the concurrent tokio tasks
/// this crate already uses for its writer/reader/receive loops (see
/// `crate::rtps::transport`), without the caller adding its own
/// synchronization. This mirrors go-DDS's own doc comment on
/// `security.Plugin`: "Implementations must be safe for concurrent use
/// from multiple goroutines."
//fusa:req REQ-SEC-016
//fusa:req REQ-SEC-017
//fusa:req REQ-SEC-018
pub trait SecurityPlugin: Send + Sync {
    /// Transforms `plaintext` into a protected form ready for
    /// transmission.
    ///
    /// The returned bytes may be the same length as `plaintext` (e.g. an
    /// identity transform such as [`NullPlugin`]), shorter, or longer
    /// (e.g. an appended authentication tag or a prepended nonce) — the
    /// trait places no constraint on the relationship between input and
    /// output length.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError>;

    /// Reverses [`seal`](SecurityPlugin::seal), returning the original
    /// plaintext.
    ///
    /// Returns [`SecurityError`] — never panics — if `ciphertext` is
    /// invalid, has been tampered with, or otherwise cannot be verified or
    /// decrypted; `ciphertext` must be treated as attacker-controlled
    /// input since it originates from network bytes.
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError>;
}

/// The identity transform: [`seal`](SecurityPlugin::seal) and
/// [`open`](SecurityPlugin::open) return the input unchanged and never
/// fail.
///
/// Direct port of go-DDS's `security.NullPlugin`. Use `NullPlugin` when no
/// payload security is required — development, testing, or interop with a
/// peer that is not running any DDS-Security plugin. It provides no
/// confidentiality and no integrity protection; this is a deliberate,
/// documented no-op, not a placeholder that will eventually reject input.
//fusa:req REQ-SEC-019
#[derive(Clone, Copy, Debug, Default)]
pub struct NullPlugin;

impl SecurityPlugin for NullPlugin {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        Ok(ciphertext.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// `NullPlugin::seal` returns the input unchanged, matching go-DDS's
    /// `func (NullPlugin) Seal(p []byte) ([]byte, error) { return p, nil }`.
    //fusa:test REQ-SEC-019
    #[test]
    fn null_plugin_seal_is_identity() {
        let plugin = NullPlugin;
        for input in [&b""[..], b"x", b"hello, world", &[0u8; 256][..]] {
            assert_eq!(plugin.seal(input).unwrap(), input);
        }
    }

    /// `NullPlugin::open` returns the input unchanged, matching go-DDS's
    /// `func (NullPlugin) Open(p []byte) ([]byte, error) { return p, nil }`.
    //fusa:test REQ-SEC-019
    #[test]
    fn null_plugin_open_is_identity() {
        let plugin = NullPlugin;
        for input in [&b""[..], b"x", b"hello, world", &[0xffu8; 256][..]] {
            assert_eq!(plugin.open(input).unwrap(), input);
        }
    }

    /// `NullPlugin` never fails, for any input including empty input —
    /// there is no framing to validate.
    //fusa:test REQ-SEC-019
    #[test]
    fn null_plugin_never_fails() {
        let plugin = NullPlugin;
        assert!(plugin.seal(&[]).is_ok());
        assert!(plugin.open(&[]).is_ok());
    }

    /// `seal`/`open` are inverses for the identity plugin — the trivial
    /// case of the general contract every `SecurityPlugin` must satisfy.
    //fusa:test REQ-SEC-016
    #[test]
    fn null_plugin_seal_open_roundtrip() {
        let plugin = NullPlugin;
        let plaintext = b"round trip me".to_vec();
        let sealed = plugin.seal(&plaintext).unwrap();
        let opened = plugin.open(&sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    /// A minimal, test-local plugin exercising the general
    /// seal/open-are-inverses contract with a *non*-identity transform
    /// (append a fixed marker byte on seal, strip and validate it on
    /// open), and exercising the error path — `open` must reject input
    /// that was not produced by `seal`, not just accept everything the way
    /// `NullPlugin` trivially does.
    struct MarkerPlugin;

    const MARKER: u8 = 0xAB;

    impl SecurityPlugin for MarkerPlugin {
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
            let mut out = Vec::with_capacity(plaintext.len() + 1);
            out.extend_from_slice(plaintext);
            out.push(MARKER);
            Ok(out)
        }

        fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
            match ciphertext.split_last() {
                Some((&MARKER, rest)) => Ok(rest.to_vec()),
                Some(_) => Err(SecurityError::VerificationFailed),
                None => Err(SecurityError::PayloadTooShort),
            }
        }
    }

    /// `seal`/`open` are inverses for a non-trivial (marker-appending)
    /// plugin — pins the general contract stated in the trait's doc
    /// comment, not just the identity-transform special case.
    //fusa:test REQ-SEC-016
    #[test]
    fn non_identity_plugin_seal_open_roundtrip() {
        let plugin = MarkerPlugin;
        for plaintext in [&b""[..], b"a payload", &[1, 2, 3, 4, 5][..]] {
            let sealed = plugin.seal(plaintext).unwrap();
            assert_eq!(plugin.open(&sealed).unwrap(), plaintext);
        }
    }

    /// `open` must reject input that was not produced by the matching
    /// `seal` call, returning `Err` rather than panicking or silently
    /// producing wrong plaintext — the property that matters once `open`
    /// is fed real, potentially-hostile network bytes.
    //fusa:test REQ-SEC-016
    #[test]
    fn open_rejects_input_not_produced_by_seal() {
        let plugin = MarkerPlugin;
        assert_eq!(plugin.open(&[]), Err(SecurityError::PayloadTooShort));
        assert_eq!(
            plugin.open(b"no marker"),
            Err(SecurityError::VerificationFailed)
        );
    }

    /// `SecurityPlugin` is object-safe: a plugin can be selected at
    /// runtime and stored/called through `Box<dyn SecurityPlugin>` and
    /// `Arc<dyn SecurityPlugin>` without the caller knowing the concrete
    /// type — the property the trait's "pluggable" name promises.
    //fusa:test REQ-SEC-017
    #[test]
    fn object_safety() {
        let boxed: Box<dyn SecurityPlugin> = Box::new(NullPlugin);
        assert_eq!(boxed.seal(b"boxed").unwrap(), b"boxed");

        let arced: Arc<dyn SecurityPlugin> = Arc::new(MarkerPlugin);
        let sealed = arced.seal(b"arced").unwrap();
        assert_eq!(arced.open(&sealed).unwrap(), b"arced");
    }

    /// `SecurityPlugin` implementations are usable across concurrent tokio
    /// tasks: a single `Arc<dyn SecurityPlugin>` instance is shared and
    /// called from multiple spawned tasks, mirroring how a real writer and
    /// reader would each hold a clone of the same plugin `Arc`. Compiling
    /// and passing this test is itself the proof of the `Send + Sync`
    /// bound — a type that were not `Send + Sync` could not be captured by
    /// `tokio::spawn`'s `'static` closure across task boundaries.
    //fusa:test REQ-SEC-018
    #[tokio::test]
    async fn plugin_usable_across_concurrent_tasks() {
        let plugin: Arc<dyn SecurityPlugin> = Arc::new(NullPlugin);
        let mut handles = Vec::new();
        for i in 0u8..8 {
            let plugin = Arc::clone(&plugin);
            handles.push(tokio::spawn(async move {
                let payload = vec![i; 4];
                let sealed = plugin.seal(&payload).unwrap();
                assert_eq!(plugin.open(&sealed).unwrap(), payload);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// Compile-time assertion helper: any type satisfying it is `Send +
    /// Sync`. Used below to pin that `NullPlugin` itself (not just a
    /// `Box`/`Arc` around it) meets the bound `SecurityPlugin` requires.
    //fusa:test REQ-SEC-018
    #[test]
    fn null_plugin_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NullPlugin>();
    }
}
