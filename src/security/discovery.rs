// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`DiscoveryPlugin`] and [`HmacDiscoveryPlugin`] — HMAC-SHA-256 SPDP
//! discovery authentication.
//!
//! Direct port of go-DDS's `security.DiscoveryPlugin` interface and
//! `security.HMACDiscoveryPlugin` (`github.com/SoundMatt/go-DDS`,
//! `security/discovery.go`). go-DDS's own doc comment for the interface
//! states the property this port preserves exactly: "`DiscoveryPlugin`
//! signs and verifies SPDP participant-discovery announcements ... Only
//! \[participants\] configured with compatible plugins accept each other's
//! discovery announcements; unauthenticated or wrongly-signed peers are
//! silently discarded at the SPDP layer."
//!
//! This is `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" sixth and
//! final checklist item ("HMAC-SHA-256 discovery authentication"), and the
//! one module in this tree that *is* wired into `crate::rtps`: unlike
//! every other `security` module (whose payload-seal/topic-ACL/anti-replay
//! mechanisms remain deliberately transport-agnostic and unwired, per each
//! of their own module docs), a discovery-authentication plugin is only
//! meaningful attached to an actual SPDP service —
//! [`super::super::rtps::spdp::SpdpConfig::discovery_plugin`] holds an
//! `Option<Arc<dyn DiscoveryPlugin>>`, and
//! [`super::super::rtps::spdp::SpdpService::send_announcement`]/
//! [`super::super::rtps::spdp::SpdpService::handle_packet`] sign/verify
//! through it. See that module's "Discovery authentication" doc section
//! for the wire-format details (`PID_DISCOVERY_TOKEN`, already reserved in
//! `crate::rtps::cdr` ahead of this item landing).
//!
//! # Wire format
//!
//! [`HmacDiscoveryPlugin::sign_discovery`] returns a 32-byte HMAC-SHA-256
//! tag computed over `"go-dds-discovery-v1" || guid_prefix` — identical to
//! go-DDS's `HMACDiscoveryPlugin.sign`'s `mac.Write([]byte(discoveryContext))`
//! then `mac.Write(guidPrefix)` sequence, including the same fixed context
//! string (byte-exact, not just same-length). The tag itself carries no
//! framing (unlike [`super::hmac::HmacPlugin`]'s `plaintext || tag` seal
//! format) — it is a standalone value a caller embeds in its own wire
//! format (here, an SPDP `PL_CDR_LE` parameter, `PID_DISCOVERY_TOKEN`), not
//! a transform over its input.
//!
//! # Scope
//!
//! go-DDS's `security.HMACDiscoveryPlugin` also implements
//! `SignEndpoint`/`VerifyEndpoint` (go-DDS's `rtps.EndpointPlugin`
//! interface), authenticating SEDP endpoint announcements under a second,
//! distinct HMAC context (`"go-dds-endpoint-v1"`). That is a separate
//! mechanism, not part of this milestone's "HMAC-SHA-256 **discovery**
//! authentication" checklist item (SPDP only) — left for a future item,
//! consistent with this crate's own scoping discipline elsewhere in this
//! module tree (e.g. `hmac`'s own doc comment scoping out confidentiality
//! to the later `aes_gcm` item).
//!
//! One correction to an earlier, unverified claim in this module tree:
//! [`super::hmac::HmacPlugin`]'s doc comment speculates that "the separate
//! discovery HMAC plugin ... does enforce a 16-byte minimum" key length.
//! Inspecting a fresh go-DDS clone's actual `NewHMACDiscoveryPlugin`
//! (`security/discovery.go`) shows no such check — like `NewHMACPlugin`, it
//! copies the key unconditionally and accepts any length, including empty.
//! This port matches that verified behaviour, not the earlier speculation.

use std::sync::{Arc, RwLock};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC context string prefixed to every signed guid_prefix, matching
/// go-DDS's unexported `discoveryContext = "go-dds-discovery-v1"` constant
/// byte-for-byte. Distinguishes an SPDP discovery tag from any other
/// HMAC-tagged value (e.g. a future SEDP endpoint tag under a different
/// context string) computed under the same key.
const DISCOVERY_CONTEXT: &[u8] = b"go-dds-discovery-v1";

/// Authenticates SPDP participant-discovery announcements: signs an
/// outbound `guid_prefix` and verifies a received `(guid_prefix, tag)`
/// pair. Direct port of go-DDS's `security.DiscoveryPlugin` interface.
///
/// `Send + Sync` and object-safe (usable as `Box<dyn DiscoveryPlugin>`/
/// `Arc<dyn DiscoveryPlugin>`), matching this crate's established
/// `SecurityPlugin`-family trait shape.
//fusa:req REQ-SEC-028
pub trait DiscoveryPlugin: Send + Sync {
    /// Returns an authentication tag for `guid_prefix` (12 bytes in
    /// practice — an RTPS `GuidPrefix` — but accepted as an arbitrary
    /// byte slice, matching go-DDS's own `[]byte` signature rather than
    /// committing this trait to a fixed length). Embedded in outbound SPDP
    /// announcements as `PID_DISCOVERY_TOKEN`.
    fn sign_discovery(&self, guid_prefix: &[u8]) -> Vec<u8>;

    /// Returns `true` when `tag` is a valid authentication tag for
    /// `guid_prefix`. A `nil`/empty `tag` must return `false` — matches
    /// go-DDS's documented `VerifyDiscovery` contract, so a peer that
    /// simply omits `PID_DISCOVERY_TOKEN` is rejected exactly like one
    /// that supplies a wrong tag, not treated as an unauthenticated pass.
    fn verify_discovery(&self, guid_prefix: &[u8], tag: &[u8]) -> bool;
}

/// An HMAC-SHA-256 [`DiscoveryPlugin`]: [`sign_discovery`](
/// DiscoveryPlugin::sign_discovery) returns a 32-byte tag computed over a
/// fixed context string followed by `guid_prefix`, and
/// [`verify_discovery`](DiscoveryPlugin::verify_discovery) recomputes and
/// compares it in constant time (via [`hmac::Mac::verify_slice`]).
///
/// Direct port of go-DDS's `security.HMACDiscoveryPlugin` /
/// `NewHMACDiscoveryPlugin`. All participants sharing one SPDP discovery
/// group must be constructed with the same key; a peer's announcement is
/// silently discarded at the SPDP layer (never trusted, never stored as a
/// known peer) if its tag does not verify — see
/// `crate::rtps::spdp::SpdpService::handle_packet`'s "Discovery
/// authentication" wiring.
///
/// # Key material
///
/// Any key length is accepted (HMAC's construction pads short keys and
/// hashes long ones internally, per RFC 2104), matching go-DDS's
/// `NewHMACDiscoveryPlugin` — see this module's top-level doc comment for
/// the earlier, unverified claim elsewhere in this crate that this type
/// enforces a minimum length; it does not, on inspection of a fresh go-DDS
/// clone.
///
/// # Rekeying
///
/// [`HmacDiscoveryPlugin::rekey`] atomically replaces the key: any
/// `sign_discovery`/`verify_discovery` call that started before a `rekey`
/// call completes under the old key (or the new one, if it started after);
/// no call ever observes a torn/partial key. Matches go-DDS's `Rekey`.
//fusa:req REQ-SEC-028
//fusa:req REQ-SEC-029
pub struct HmacDiscoveryPlugin {
    key: RwLock<Vec<u8>>,
}

impl HmacDiscoveryPlugin {
    /// Creates an `HmacDiscoveryPlugin` keyed with `key`.
    ///
    /// Unlike go-DDS's `NewHMACDiscoveryPlugin`, which always copies its
    /// input slice (defending against the caller later mutating the
    /// backing array — a real risk for Go's reference-semantics slices),
    /// this constructor relies on Rust's ownership model instead: passing
    /// an owned `Vec<u8>` moves it in (no copy, and the caller cannot
    /// mutate a value it no longer owns); passing a borrowed `&[u8]`
    /// still copies via [`ToOwned`], giving the identical
    /// external-mutation-safety guarantee go-DDS's own always-copy
    /// approach provides, without the redundant copy on the by-value path.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: RwLock::new(key.into()),
        }
    }

    /// Atomically replaces this plugin's key — see the type-level docs'
    /// "Rekeying" section. `new_key` is consumed the same way
    /// [`HmacDiscoveryPlugin::new`]'s `key` is.
    pub fn rekey(&self, new_key: impl Into<Vec<u8>>) {
        let mut guard = self.key.write().unwrap_or_else(|e| e.into_inner());
        *guard = new_key.into();
    }

    /// Builds an `HmacSha256` keyed with this plugin's current key.
    ///
    /// `Hmac::<Sha256>::new_from_slice` only returns `Err` for key
    /// lengths its underlying block cipher rejects; HMAC accepts any key
    /// length (RFC 2104), so this never fails in practice for the
    /// `Vec<u8>` keys this plugin stores. Handled explicitly rather than
    /// `.unwrap()`ed regardless, per this crate's no-`.unwrap()`-on-
    /// user-visible-paths convention (REQ-ASIL-003): a failure here
    /// yields `None`, and callers fail closed (`sign_discovery` returns an
    /// empty tag no `verify_discovery` call could ever accept;
    /// `verify_discovery` itself returns `false`) rather than panicking.
    fn keyed_mac(&self) -> Option<HmacSha256> {
        let key = self.key.read().unwrap_or_else(|e| e.into_inner());
        HmacSha256::new_from_slice(&key).ok()
    }
}

impl DiscoveryPlugin for HmacDiscoveryPlugin {
    /// Matches go-DDS's `HMACDiscoveryPlugin.sign`/`SignDiscovery`: HMAC-
    /// SHA-256 over `DISCOVERY_CONTEXT` followed by `guid_prefix`, keyed
    /// with this plugin's current key.
    fn sign_discovery(&self, guid_prefix: &[u8]) -> Vec<u8> {
        let Some(mut mac) = self.keyed_mac() else {
            return Vec::new();
        };
        mac.update(DISCOVERY_CONTEXT);
        mac.update(guid_prefix);
        mac.finalize().into_bytes().to_vec()
    }

    /// Matches go-DDS's `HMACDiscoveryPlugin.VerifyDiscovery`: rejects an
    /// empty `tag` outright (`nil` in Go; an empty slice serves the same
    /// role here), then recomputes the expected tag and compares in
    /// constant time via [`hmac::Mac::verify_slice`] (go-DDS: `hmac.Equal`).
    fn verify_discovery(&self, guid_prefix: &[u8], tag: &[u8]) -> bool {
        if tag.is_empty() {
            return false;
        }
        let Some(mut mac) = self.keyed_mac() else {
            return false;
        };
        mac.update(DISCOVERY_CONTEXT);
        mac.update(guid_prefix);
        mac.verify_slice(tag).is_ok()
    }
}

/// Compile-time assertion that `Arc<dyn DiscoveryPlugin>`'s `Send + Sync`
/// bound is satisfiable by `HmacDiscoveryPlugin` — exercised for real by
/// [`super::super::rtps::spdp::SpdpConfig::discovery_plugin`], which holds
/// exactly this type.
fn _assert_arc_dyn_discovery_plugin_is_send_sync(_: Arc<dyn DiscoveryPlugin>) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Independently-reproducible reference vectors, generated directly
    /// from a fresh clone of go-DDS's own `security.HMACDiscoveryPlugin`
    /// (not hand-derived): for each `(key, guid_prefix)` pair, `tag_hex`
    /// is exactly go-DDS's `NewHMACDiscoveryPlugin(key).SignDiscovery(guid_prefix)`
    /// output. Pinning these keeps this port byte-exact with the reference
    /// implementation (this crate's established wire-format correctness
    /// bar), not just self-consistent.
    ///
    /// Regenerate by running a small Go program against
    /// `github.com/SoundMatt/go-DDS`'s `security` package:
    ///
    /// ```text
    /// p := security.NewHMACDiscoveryPlugin(key)
    /// tag := p.SignDiscovery(guidPrefix)
    /// fmt.Println(hex.EncodeToString(tag))
    /// ```
    //fusa:test REQ-SEC-028
    #[test]
    fn matches_go_dds_reference_vectors() {
        struct Vector {
            key: &'static [u8],
            guid_prefix: &'static [u8],
            tag_hex: &'static str,
        }

        let vectors = [
            Vector {
                key: &[0x01; 32],
                guid_prefix: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                tag_hex: "7ab1f507f5569b6b80957aae25d59cbfbaa6c231b8cd691faeb7ac25d6937c9d",
            },
            Vector {
                key: b"test-secret-key",
                guid_prefix: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                tag_hex: "070b93245e87ee96306561d7655f3cf7453396be752362d5ddf5f572456f968d",
            },
            Vector {
                key: b"k",
                guid_prefix: &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                tag_hex: "9c30032783c4fbe8e749041e3f149a4eea226c055a0b6a55e7216b6d4db74d7d",
            },
            Vector {
                key: b"super-secret-discovery-key-material!",
                guid_prefix: &[
                    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                ],
                tag_hex: "619df1470829648141afaa292bd68bd423dd6103c9b5e65ec49e368f6761e7f7",
            },
            Vector {
                key: &[],
                guid_prefix: &[9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
                tag_hex: "faa26c1e91a24aba289442513b2d77d0a222e3b36daae58e1e4c7274fd9fd3fd",
            },
        ];

        for v in vectors {
            let plugin = HmacDiscoveryPlugin::new(v.key.to_vec());
            let tag = plugin.sign_discovery(v.guid_prefix);
            let expected = hex::decode(v.tag_hex).expect("reference vector hex must decode");
            assert_eq!(
                tag, expected,
                "HmacDiscoveryPlugin::sign_discovery must match go-DDS's \
                 HMACDiscoveryPlugin.SignDiscovery byte-for-byte"
            );
            assert_eq!(tag.len(), 32);
            assert!(plugin.verify_discovery(v.guid_prefix, &tag));
        }
    }

    /// A further reference vector over a non-12-byte guid_prefix (the
    /// interface accepts an arbitrary-length slice — see the trait's doc
    /// comment), generated the same way against go-DDS's
    /// `HMACDiscoveryPlugin`.
    //fusa:test REQ-SEC-028
    #[test]
    fn matches_go_dds_reference_vector_non_standard_prefix_length() {
        let plugin = HmacDiscoveryPlugin::new(b"0123456789abcdef0123456789abcdef".to_vec());
        let tag = plugin.sign_discovery(&[0xFF; 12]);
        let expected =
            hex::decode("fdd95a1d79c28e538f1b307d5c2a3de6bbbcc617e2f7566aab22297887571a5b")
                .unwrap();
        assert_eq!(tag, expected);
    }

    //fusa:test REQ-SEC-028
    #[test]
    fn sign_then_verify_round_trip() {
        let plugin = HmacDiscoveryPlugin::new(b"a reasonably long test key".to_vec());
        let prefix = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let tag = plugin.sign_discovery(&prefix);
        assert!(!tag.is_empty());
        assert!(plugin.verify_discovery(&prefix, &tag));
    }

    /// Matches go-DDS's `TestHMACDiscoveryPlugin_WrongKey`.
    //fusa:test REQ-SEC-029
    #[test]
    fn verify_rejects_tag_from_a_different_key() {
        let signer = HmacDiscoveryPlugin::new(b"key-a".to_vec());
        let verifier = HmacDiscoveryPlugin::new(b"key-b".to_vec());
        let prefix = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let tag = signer.sign_discovery(&prefix);
        assert!(!verifier.verify_discovery(&prefix, &tag));
    }

    /// Matches go-DDS's `TestHMACDiscoveryPlugin_WrongPrefix`.
    //fusa:test REQ-SEC-029
    #[test]
    fn verify_rejects_tag_for_a_different_prefix() {
        let plugin = HmacDiscoveryPlugin::new(b"shared-key".to_vec());
        let prefix1 = [1u8; 12];
        let prefix2 = [2u8; 12];
        let tag = plugin.sign_discovery(&prefix1);
        assert!(!plugin.verify_discovery(&prefix2, &tag));
    }

    /// Matches go-DDS's `TestHMACDiscoveryPlugin_NilTag`/`_EmptyTag`.
    //fusa:test REQ-SEC-029
    #[test]
    fn verify_rejects_empty_tag() {
        let plugin = HmacDiscoveryPlugin::new(b"key".to_vec());
        let prefix = [0u8; 12];
        assert!(!plugin.verify_discovery(&prefix, &[]));
    }

    /// Matches go-DDS's `TestHMACDiscoveryPlugin_DifferentPrefixesDifferentTags`.
    //fusa:test REQ-SEC-028
    #[test]
    fn different_prefixes_produce_different_tags() {
        let plugin = HmacDiscoveryPlugin::new(b"key".to_vec());
        let p1 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let p2 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        assert_ne!(plugin.sign_discovery(&p1), plugin.sign_discovery(&p2));
    }

    /// A tampered tag (single bit flip) must fail verification — the
    /// discovery-authentication analogue of `hmac::tests::open_detects_tampered_tag`.
    //fusa:test REQ-SEC-029
    #[test]
    fn verify_rejects_tampered_tag() {
        let plugin = HmacDiscoveryPlugin::new(b"integrity key".to_vec());
        let prefix = [7u8; 12];
        let mut tag = plugin.sign_discovery(&prefix);
        let last = tag.len() - 1;
        tag[last] ^= 0xFF;
        assert!(!plugin.verify_discovery(&prefix, &tag));
    }

    /// A truncated (but non-empty) tag must fail verification, not be
    /// treated as a shorter-but-valid prefix match.
    //fusa:test REQ-SEC-029
    #[test]
    fn verify_rejects_truncated_tag() {
        let plugin = HmacDiscoveryPlugin::new(b"integrity key".to_vec());
        let prefix = [7u8; 12];
        let tag = plugin.sign_discovery(&prefix);
        assert!(!plugin.verify_discovery(&prefix, &tag[..tag.len() - 5]));
    }

    /// Two plugins keyed identically produce identical tags for the same
    /// guid_prefix, and either can verify what the other signed — the key,
    /// not plugin identity, determines interoperability. Matches this
    /// crate's `hmac::tests::same_key_interoperates_across_plugin_instances`.
    //fusa:test REQ-SEC-028
    #[test]
    fn same_key_interoperates_across_plugin_instances() {
        let a = HmacDiscoveryPlugin::new(b"shared key".to_vec());
        let b = HmacDiscoveryPlugin::new(b"shared key".to_vec());
        let prefix = [3u8; 12];
        let tag = a.sign_discovery(&prefix);
        assert!(b.verify_discovery(&prefix, &tag));
    }

    /// Any key length is accepted at construction, including empty —
    /// matching go-DDS's `NewHMACDiscoveryPlugin`, which performs no
    /// minimum-length validation (see this module's top-level doc comment
    /// correcting an earlier, unverified claim elsewhere in this crate).
    //fusa:test REQ-SEC-028
    #[test]
    fn accepts_any_key_length() {
        for key in [&b""[..], b"x", &[0u8; 1024][..]] {
            let plugin = HmacDiscoveryPlugin::new(key.to_vec());
            let prefix = [1u8; 12];
            let tag = plugin.sign_discovery(&prefix);
            assert!(plugin.verify_discovery(&prefix, &tag));
        }
    }

    /// Matches go-DDS's `TestHMACDiscoveryPlugin_KeyIsNotShared`: passing
    /// an owned `Vec<u8>` moves it into the plugin, so the caller cannot
    /// mutate it afterward (Rust's ownership model enforces this
    /// statically — see the constructor's doc comment). This test instead
    /// exercises the by-*reference* construction path (`&[u8]` → `.to_vec()`
    /// copy), confirming mutating the original array after construction
    /// does not change the plugin's signed output — the same external
    /// property go-DDS's own always-copy `NewHMACDiscoveryPlugin` provides.
    //fusa:test REQ-SEC-028
    #[test]
    fn key_is_copied_not_shared_when_constructed_from_a_slice() {
        let mut key = *b"mutable-key-material!!";
        let plugin = HmacDiscoveryPlugin::new(&key[..]);
        let prefix = [1u8; 12];
        let tag_before = plugin.sign_discovery(&prefix);

        key[0] = 0xFF;
        assert_eq!(key[0], 0xFF); // confirm the mutation actually happened
        let tag_after = plugin.sign_discovery(&prefix);

        assert_eq!(tag_before, tag_after);
    }

    //fusa:test REQ-SEC-028
    #[test]
    fn rekey_changes_signed_output() {
        let plugin = HmacDiscoveryPlugin::new(b"old-key".to_vec());
        let prefix = [1u8; 12];
        let before = plugin.sign_discovery(&prefix);
        plugin.rekey(b"new-key".to_vec());
        let after = plugin.sign_discovery(&prefix);
        assert_ne!(before, after);
    }

    //fusa:test REQ-SEC-028
    #[test]
    fn rekey_then_verify_with_new_key_succeeds() {
        let plugin = HmacDiscoveryPlugin::new(b"old-key".to_vec());
        plugin.rekey(b"new-key".to_vec());
        let prefix = [1u8; 12];
        let tag = plugin.sign_discovery(&prefix);
        assert!(plugin.verify_discovery(&prefix, &tag));
    }

    //fusa:test REQ-SEC-029
    #[test]
    fn rekey_invalidates_a_tag_signed_under_the_old_key() {
        let plugin = HmacDiscoveryPlugin::new(b"old-key".to_vec());
        let prefix = [1u8; 12];
        let old_tag = plugin.sign_discovery(&prefix);
        plugin.rekey(b"new-key".to_vec());
        assert!(!plugin.verify_discovery(&prefix, &old_tag));
    }

    /// `HmacDiscoveryPlugin` is object-safe: usable as
    /// `Box<dyn DiscoveryPlugin>`/`Arc<dyn DiscoveryPlugin>`, matching this
    /// crate's established `SecurityPlugin`-family object-safety coverage.
    //fusa:test REQ-SEC-028
    #[test]
    fn object_safety() {
        let boxed: Box<dyn DiscoveryPlugin> =
            Box::new(HmacDiscoveryPlugin::new(b"boxed key".to_vec()));
        let prefix = [1u8; 12];
        let tag = boxed.sign_discovery(&prefix);
        assert!(boxed.verify_discovery(&prefix, &tag));

        let arced: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"arced key".to_vec()));
        let tag = arced.sign_discovery(&prefix);
        assert!(arced.verify_discovery(&prefix, &tag));
    }

    /// `HmacDiscoveryPlugin` is usable across concurrent tokio tasks: a
    /// single `Arc<dyn DiscoveryPlugin>` is shared and called from multiple
    /// spawned tasks. Compiling and passing this test is itself proof of
    /// the `Send + Sync` bound, matching this crate's established
    /// concurrency-coverage convention for every other `SecurityPlugin`-
    /// family type.
    //fusa:test REQ-SEC-028
    #[tokio::test]
    async fn plugin_usable_across_concurrent_tasks() {
        let plugin: Arc<dyn DiscoveryPlugin> =
            Arc::new(HmacDiscoveryPlugin::new(b"concurrent-tasks key".to_vec()));
        let mut handles = Vec::new();
        for i in 0u8..8 {
            let plugin = Arc::clone(&plugin);
            handles.push(tokio::spawn(async move {
                let prefix = [i; 12];
                let tag = plugin.sign_discovery(&prefix);
                assert!(plugin.verify_discovery(&prefix, &tag));
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// Compile-time assertion helper mirroring this crate's established
    /// per-`SecurityPlugin`-family-type convention, pinning that
    /// `HmacDiscoveryPlugin` itself (not just a `Box`/`Arc` around it)
    /// meets the `Send + Sync` bound.
    //fusa:test REQ-SEC-028
    #[test]
    fn hmac_discovery_plugin_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HmacDiscoveryPlugin>();
    }
}
