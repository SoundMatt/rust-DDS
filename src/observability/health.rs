// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The [`HealthProvider`] trait — an optional capability a `Participant`
//! implementation exposes to report its own operational status — and its
//! [`Health`]/[`HealthStatus`] value types.
//!
//! Direct port of go-DDS's `dds.HealthProvider` interface and its
//! `dds.Health`/`dds.HealthStatus` types (`github.com/SoundMatt/go-DDS`,
//! `dds.go`). go-DDS's own doc comment states the intent this port
//! preserves exactly: "`HealthProvider` is implemented by participants
//! that expose health reporting." — a small, optional interface any
//! `dds.Participant` implementation may additionally satisfy, consumed by
//! `observability/monitor`'s `GET /health` endpoint via a Go interface
//! type-assertion. This module ports the trait and its value types only —
//! `ROADMAP.md`'s "Planned — v0.6 — Observability (Tier 5)" milestone's
//! first checklist item, "`HealthProvider` trait" — plus concrete
//! implementations on every participant type this crate already has (see
//! the [`super`] module docs); an HTTP surface analogous to go-DDS's
//! `observability/monitor` is a separate, later concern, not implemented
//! here.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The overall operational status of a participant.
///
/// Direct port of go-DDS's `dds.HealthStatus`, an `int`-backed enum with
/// three values (`HealthOK`, `HealthDegraded`, `HealthDown`) and a
/// `String()` method returning `"ok"`/`"degraded"`/`"down"`. This port
/// mirrors both the three-value set and those exact lowercase string
/// forms — [`fmt::Display`] below and this type's `serde` representation
/// (`#[serde(rename_all = "lowercase")]`) both produce them — so JSON
/// emitted by a future health endpoint matches go-DDS's byte-for-byte.
//fusa:req REQ-MON-001
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// The participant is running normally.
    #[default]
    Ok,
    /// The participant is running with reduced capability.
    Degraded,
    /// The participant has been closed or has failed.
    Down,
}

impl fmt::Display for HealthStatus {
    /// Lowercase, JSON-friendly representation — `"ok"` / `"degraded"` /
    /// `"down"` — matching go-DDS's `HealthStatus.String()` exactly.
    //fusa:req REQ-MON-001
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HealthStatus::Ok => "ok",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Down => "down",
        })
    }
}

/// A point-in-time health snapshot for a participant.
///
/// Direct port of go-DDS's `dds.Health` struct. `details` mirrors go-DDS's
/// `Details string \`json:"details,omitempty"\`` field — an optional
/// human-readable or JSON-encoded string describing per-subsystem state —
/// expressed as `Option<String>` rather than an empty-string sentinel, per
/// this crate's idiomatic-Rust convention; `#[serde(skip_serializing_if =
/// "Option::is_none")]` reproduces go-DDS's `omitempty` behaviour when this
/// type is serialized.
//fusa:req REQ-MON-001
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// The overall health classification.
    pub status: HealthStatus,
    /// Optional human-readable or JSON-encoded per-subsystem detail.
    /// `None` means no details, matching go-DDS's empty-string `omitempty`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl Health {
    /// A healthy snapshot with no details — the common case.
    pub fn ok() -> Self {
        Self {
            status: HealthStatus::Ok,
            details: None,
        }
    }

    /// A degraded snapshot carrying `details`.
    pub fn degraded(details: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            details: Some(details.into()),
        }
    }

    /// A down snapshot carrying `details`.
    pub fn down(details: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Down,
            details: Some(details.into()),
        }
    }
}

/// An optional capability implemented by `Participant`s that expose health
/// reporting.
///
/// Direct port of go-DDS's `dds.HealthProvider` interface (`Health()
/// Health`). Every concrete, public `Participant` implementation this
/// crate has today — [`crate::mock::MockParticipant`],
/// [`crate::shmem::ShmemParticipant`], and
/// [`crate::rtps::dds_participant::RtpsUdpParticipant`] — implements this
/// trait; see each type's own `Health` impl for its specific closed/open
/// semantics.
///
/// # Object safety
///
/// `HealthProvider` has no generic parameters and its one method takes
/// `&self` and returns an owned [`Health`], so the trait is dyn-compatible:
/// a caller that only knows it has *some* participant that reports health
/// can hold it as `Box<dyn HealthProvider>` or `Arc<dyn HealthProvider>`
/// without knowing the concrete participant type — the same pattern this
/// crate already established for [`crate::security::SecurityPlugin`]. See
/// the `object_safety` test below.
///
/// # Concurrency
///
/// Implementations must be `Send + Sync`, so a `HealthProvider` handle can
/// be shared (typically behind an `Arc`) across concurrent tokio tasks —
/// e.g. a future HTTP health-endpoint handler polling it on every request
/// — without the caller adding its own synchronization. go-DDS's
/// `Participant` implementations satisfy the analogous requirement via
/// their own internal `sync.Mutex`-protected state; this port's
/// implementations use `AtomicBool`/`Ordering::SeqCst` for the same
/// closed-flag check, per this crate's established convention (see
/// `crate::mock::MockParticipant`'s `closed` field).
//fusa:req REQ-MON-002
pub trait HealthProvider: Send + Sync {
    /// Returns a point-in-time health snapshot.
    fn health(&self) -> Health;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// `HealthStatus::Default` is `Ok`, matching go-DDS's `HealthOK`
    /// occupying the zero value of its `iota`-based enum (the Go
    /// zero-value convention this port's `#[default]` reproduces).
    //fusa:test REQ-MON-001
    #[test]
    fn health_status_default_is_ok() {
        assert_eq!(HealthStatus::default(), HealthStatus::Ok);
    }

    /// `Display` produces go-DDS's exact lowercase strings for all three
    /// variants.
    //fusa:test REQ-MON-001
    #[test]
    fn health_status_display_matches_go_dds() {
        assert_eq!(HealthStatus::Ok.to_string(), "ok");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Down.to_string(), "down");
    }

    /// `serde` serialization produces the same lowercase strings as
    /// `Display` (and as go-DDS's JSON output), for both the bare enum and
    /// a `Health` wrapping it.
    //fusa:test REQ-MON-001
    #[test]
    fn health_status_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&HealthStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&HealthStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Down).unwrap(),
            "\"down\""
        );
    }

    /// `Health` with no details serializes with the `details` field
    /// omitted entirely, matching go-DDS's `Details string
    /// \`json:"details,omitempty"\`` behaviour for an empty string.
    //fusa:test REQ-MON-001
    #[test]
    fn health_omits_empty_details_when_serialized() {
        let h = Health::ok();
        assert_eq!(serde_json::to_string(&h).unwrap(), r#"{"status":"ok"}"#);
    }

    /// `Health` with details present serializes them, and round-trips
    /// through `serde_json` losslessly.
    //fusa:test REQ-MON-001
    #[test]
    fn health_with_details_serializes_and_round_trips() {
        let h = Health::down(r#"{"state":"closed"}"#);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(
            json,
            r#"{"status":"down","details":"{\"state\":\"closed\"}"}"#
        );
        let back: Health = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    /// `Health::ok`/`degraded`/`down` constructors set the expected status
    /// and details.
    //fusa:test REQ-MON-001
    #[test]
    fn health_constructors() {
        assert_eq!(
            Health::ok(),
            Health {
                status: HealthStatus::Ok,
                details: None
            }
        );
        assert_eq!(
            Health::degraded("half up"),
            Health {
                status: HealthStatus::Degraded,
                details: Some("half up".to_string())
            }
        );
        assert_eq!(
            Health::down("dead"),
            Health {
                status: HealthStatus::Down,
                details: Some("dead".to_string())
            }
        );
    }

    /// A minimal, test-local provider — exercises the trait's basic
    /// contract independent of any real participant implementation.
    struct FixedProvider(Health);

    impl HealthProvider for FixedProvider {
        fn health(&self) -> Health {
            self.0.clone()
        }
    }

    /// `HealthProvider` is object-safe: a provider can be selected at
    /// runtime and stored/called through `Box<dyn HealthProvider>` and
    /// `Arc<dyn HealthProvider>` without the caller knowing the concrete
    /// type.
    //fusa:test REQ-MON-002
    #[test]
    fn object_safety() {
        let boxed: Box<dyn HealthProvider> = Box::new(FixedProvider(Health::ok()));
        assert_eq!(boxed.health().status, HealthStatus::Ok);

        let arced: Arc<dyn HealthProvider> = Arc::new(FixedProvider(Health::down("x")));
        assert_eq!(arced.health().status, HealthStatus::Down);
    }

    /// `HealthProvider` implementations are usable across concurrent tokio
    /// tasks: a single `Arc<dyn HealthProvider>` instance is shared and
    /// called from multiple spawned tasks. Compiling and passing this test
    /// is itself the proof of the `Send + Sync` bound.
    //fusa:test REQ-MON-002
    #[tokio::test]
    async fn provider_usable_across_concurrent_tasks() {
        let provider: Arc<dyn HealthProvider> = Arc::new(FixedProvider(Health::ok()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let provider = Arc::clone(&provider);
            handles.push(tokio::spawn(async move {
                assert_eq!(provider.health().status, HealthStatus::Ok);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// Compile-time assertion helper: any type satisfying it is `Send +
    /// Sync`. Pins that `FixedProvider` itself (not just a `Box`/`Arc`
    /// around it) meets the bound `HealthProvider` requires.
    //fusa:test REQ-MON-002
    #[test]
    fn fixed_provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FixedProvider>();
    }
}
