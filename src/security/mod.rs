// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Pluggable payload security — `ROADMAP.md`'s "Planned — v0.5 — Security
//! (Tier 2)" milestone, part of the parity build-out plan's "Tier 2 —
//! Safety (E2E) + Security" (`dds-core::security` in the target workspace
//! architecture; stays in this single crate until the workspace cutover
//! gated on RELAY spec issue #59, per the "Interim structure vs. full
//! cutover" section).
//!
//! Reference: go-DDS's `security` package
//! (`github.com/SoundMatt/go-DDS`, `security/`). This module tree mirrors
//! that package's file-per-concern layout, matching this crate's
//! established `src/rtps/` and `src/shmem/` convention:
//!
//! - [`plugin`] — [`plugin::SecurityPlugin`], the pluggable payload-seal/
//!   -open extension point, and [`plugin::NullPlugin`], its identity-
//!   transform implementation. Direct port of go-DDS's `security.Plugin`
//!   interface and `security.NullPlugin` (both defined in
//!   `security/security.go`). The v0.5 milestone's first checklist item,
//!   "Pluggable payload security trait (`SecurityPlugin`)".
//! - [`hmac`] — [`hmac::HmacPlugin`], an HMAC-SHA-256 message-integrity
//!   `SecurityPlugin` implementation. Direct port of go-DDS's
//!   `security.HMACPlugin` (`security/security.go`). The v0.5 milestone's
//!   second checklist item, "HMAC-SHA-256 integrity plugin". Provides
//!   integrity and authentication, **not** confidentiality — the
//!   plaintext travels unencrypted alongside its appended tag.
//!
//! Not yet landed (later v0.5 checklist items, each its own future
//! module mirroring go-DDS's corresponding file): an AES-256-GCM
//! encryption plugin (go-DDS's `AESGCMPlugin`), a topic ACL
//! (`AccessPolicy`, go-DDS's `security/access.go`), an anti-replay guard
//! (`ReplayGuard`, go-DDS's `security/replay.go`), and HMAC-SHA-256
//! discovery authentication (go-DDS's `security/discovery.go` — per the
//! parity build-out plan's Tier 2 section, this last one plugs into SPDP
//! and is therefore not fully decoupled from `crate::rtps`, unlike
//! everything else in this module tree, which is transport-agnostic).

pub mod hmac;
pub mod plugin;

pub use hmac::HmacPlugin;
pub use plugin::{NullPlugin, SecurityError, SecurityPlugin};
