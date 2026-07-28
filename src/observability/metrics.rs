// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The [`MetricsProvider`] trait — an optional capability a `Participant`
//! implementation exposes to report per-topic write/deliver/drop
//! statistics — and its [`TopicMetrics`] value type.
//!
//! `ROADMAP.md`'s "Planned — v0.6 — Observability (Tier 5)" milestone's
//! second checklist item, `"MetricsProvider` trait (per-topic
//! write/deliver/drop counters)"`.
//!
//! # Naming: this is go-DDS's `TopicMetricsProvider`, not its `MetricsProvider`
//!
//! go-DDS's `dds.go` actually declares *three* related, separately
//! optional root-package interfaces: `MetricsProvider` (`Metrics() Metrics`
//! — cumulative, participant-wide counters, not broken out by topic),
//! `DiscoveryMetricsProvider` (`DiscoveryMetrics() DiscoveryMetrics` —
//! SPDP/SEDP announce/peer/match counters), and `TopicMetricsProvider`
//! (`TopicMetrics() []TopicMetrics` — the same write/deliver/drop/byte
//! shape as the aggregate `Metrics`, but one entry *per observed topic*).
//! This is a real discrepancy worth being explicit about, the same way
//! [`super::health`]'s port documented go-DDS's own doc-comment-vs-behaviour
//! gaps: this milestone's own roadmap checklist entry names the trait
//! `MetricsProvider` and scopes it to `"per-topic write/deliver/drop
//! counters"` — a description that matches go-DDS's `TopicMetrics` shape
//! (per-topic, `WriteCount`/`DeliverCount`/`DropCount` fields) field for
//! field, not go-DDS's aggregate, non-per-topic `Metrics`/`MetricsProvider`.
//! This module therefore ports go-DDS's `TopicMetricsProvider`/
//! `TopicMetrics` — under the Rust trait name `MetricsProvider`, matching
//! the roadmap checklist item's own chosen name rather than go-DDS's.
//! go-DDS's aggregate, participant-wide `Metrics`/`MetricsProvider` and its
//! `DiscoveryMetrics`/`DiscoveryMetricsProvider` are out of scope for this
//! item; a future item may port either as a separate, additional trait
//! without colliding with this one (Rust, unlike this port's chosen name
//! reuse, has no difficulty distinguishing `MetricsProvider` from a
//! hypothetical `AggregateMetricsProvider`/`DiscoveryMetricsProvider` — the
//! collision here is purely with go-DDS's own naming, not a Rust
//! constraint).
//!
//! # Design: object-safe, `Send + Sync`, matching `HealthProvider`
//!
//! Same optional-capability shape as [`super::health::HealthProvider`] and
//! `crate::security::SecurityPlugin`: a plain trait each concrete
//! `Participant` implementation opts into, object-safe
//! (`Box<dyn MetricsProvider>`/`Arc<dyn MetricsProvider>`) and
//! `Send + Sync` so a handle can be shared across concurrent tokio tasks.
//!
//! # Design: atomics, not an `RwLock`-guarded map, for the sync trait method
//!
//! [`super::health::HealthProvider`]'s own port documented a deliberate
//! scope narrowing: `RtpsUdpParticipant`'s live writer/reader counts live
//! behind `tokio::sync::RwLock`, and `HealthProvider::health(&self)` is
//! synchronous (no `.await`), so surfacing that live count was left for a
//! later item rather than adding blocking lock acquisition. Per-topic
//! metrics hit the exact same tension — `MetricsProvider::topic_metrics(&self)`
//! is also synchronous — so every wiring in this crate (`mock::Broker`,
//! `shmem::broker::Broker`, `rtps::participant::RtpsParticipant`) keeps its
//! per-topic counters behind a plain `std::sync::Mutex`-guarded map of
//! atomics (`AtomicU64` per counter), never a `tokio::sync::RwLock`: a
//! `std::sync::Mutex` is locked synchronously (no `.await`), so it can be
//! read from a synchronous trait method exactly like it can from an async
//! one, sidestepping the tension `HealthProvider` deferred entirely rather
//! than working around it.

use serde::{Deserialize, Serialize};

/// Per-topic write/deliver/drop/byte counters for a single DDS topic.
///
/// Direct port of go-DDS's `dds.TopicMetrics` struct (`dds.go`), field for
/// field: `Topic`/`WriteCount`/`DeliverCount`/`DropCount`/`BytesWritten`/
/// `BytesDelivered` become this struct's `topic`/`write_count`/
/// `deliver_count`/`drop_count`/`bytes_written`/`bytes_delivered` under
/// this crate's idiomatic `snake_case` field-naming convention. One
/// deliberate deviation from go-DDS worth noting: go-DDS's `TopicMetrics`
/// carries no `json:"..."` struct tags (unlike its sibling `Health`, which
/// does), so its default Go JSON marshalling emits the raw, capitalized Go
/// field names (`"Topic"`, `"WriteCount"`, …) rather than the
/// `snake_case`/`lowerCamelCase` convention go-DDS otherwise favours
/// elsewhere in `dds.go`; this port does not reproduce that inconsistency
/// and instead serializes with plain `snake_case` keys (`serde`'s default
/// for these field names, no `#[serde(rename...)]` needed), matching this
/// crate's own established JSON convention instead. No HTTP/admin surface
/// consumes this serialization yet (see the [`super::health`] module docs'
/// identical note for `Health`), so the difference is documented, not
/// currently observable.
///
/// `write_count` increments once per successful local
/// [`Publisher::write`](crate::participant::Publisher::write) call on this
/// topic; `deliver_count`/`drop_count` increment once per reader that
/// accepted/rejected the resulting sample, matching go-DDS's own
/// `TopicMetrics` counting granularity (one increment per reader per
/// sample, the same granularity documented on
/// [`crate::rtps::participant::RtpsParticipant::delivers`]'s aggregate
/// counterpart).
//fusa:req REQ-MON-004
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicMetrics {
    /// The topic name these counters apply to.
    pub topic: String,
    /// Cumulative count of successful writes on this topic.
    pub write_count: u64,
    /// Cumulative count of samples successfully delivered to some reader
    /// on this topic (one increment per reader per sample).
    pub deliver_count: u64,
    /// Cumulative count of samples dropped (e.g. a full reader queue under
    /// `DropNewest`, or an unsubscribed/closed reader) on this topic.
    pub drop_count: u64,
    /// Cumulative bytes written on this topic.
    pub bytes_written: u64,
    /// Cumulative bytes delivered to readers on this topic.
    pub bytes_delivered: u64,
}

/// An optional capability implemented by `Participant`s that expose
/// per-topic write/deliver/drop statistics.
///
/// Direct port of go-DDS's `dds.TopicMetricsProvider` interface
/// (`TopicMetrics() []TopicMetrics`) — see this module's own docs for why
/// it is named `MetricsProvider` here rather than `TopicMetricsProvider`.
/// Every concrete, public `Participant` implementation this crate has
/// today — [`crate::mock::MockParticipant`], [`crate::shmem::ShmemParticipant`],
/// and [`crate::rtps::dds_participant::RtpsUdpParticipant`] — implements
/// this trait; see each type's own `MetricsProvider` impl for its specific
/// counting wiring. The returned `Vec` contains one entry per topic this
/// participant has observed a write or a subscriber registration for since
/// construction — an empty `Vec` for a freshly constructed participant
/// that has neither written nor subscribed on any topic yet, matching
/// go-DDS's own `nil`-slice-for-no-topics-yet behaviour.
///
/// # Object safety
///
/// `MetricsProvider` has no generic parameters and its one method takes
/// `&self` and returns an owned `Vec<TopicMetrics>`, so the trait is
/// dyn-compatible: a caller that only knows it has *some* participant that
/// reports metrics can hold it as `Box<dyn MetricsProvider>` or `Arc<dyn
/// MetricsProvider>` without knowing the concrete participant type — the
/// same pattern this crate already established for
/// [`super::health::HealthProvider`]. See the `object_safety` test below.
///
/// # Concurrency
///
/// Implementations must be `Send + Sync`, so a `MetricsProvider` handle can
/// be shared (typically behind an `Arc`) across concurrent tokio tasks —
/// e.g. a future HTTP metrics-endpoint handler polling it on every request
/// — without the caller adding its own synchronization. This port's
/// implementations use `AtomicU64` counters behind a `std::sync::Mutex`-
/// guarded per-topic map, per this module's own "Design" docs above.
//fusa:req REQ-MON-005
pub trait MetricsProvider: Send + Sync {
    /// Returns a point-in-time snapshot of per-topic write/deliver/drop/
    /// byte counters, one entry per topic observed so far.
    fn topic_metrics(&self) -> Vec<TopicMetrics>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// `TopicMetrics::default()` is the all-zero, empty-topic value —
    /// matching go-DDS's `TopicMetrics{}` zero value.
    //fusa:test REQ-MON-004
    #[test]
    fn topic_metrics_default_is_zeroed() {
        let m = TopicMetrics::default();
        assert_eq!(m.topic, "");
        assert_eq!(m.write_count, 0);
        assert_eq!(m.deliver_count, 0);
        assert_eq!(m.drop_count, 0);
        assert_eq!(m.bytes_written, 0);
        assert_eq!(m.bytes_delivered, 0);
    }

    /// `TopicMetrics` serializes with plain `snake_case` keys and
    /// round-trips losslessly through `serde_json` — see this module's
    /// docs for why this deliberately does not reproduce go-DDS's own
    /// untagged, capitalized-field JSON output.
    //fusa:test REQ-MON-004
    #[test]
    fn topic_metrics_serializes_snake_case_and_round_trips() {
        let m = TopicMetrics {
            topic: "vehicle/speed".to_string(),
            write_count: 3,
            deliver_count: 5,
            drop_count: 1,
            bytes_written: 30,
            bytes_delivered: 50,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            r#"{"topic":"vehicle/speed","write_count":3,"deliver_count":5,"drop_count":1,"bytes_written":30,"bytes_delivered":50}"#
        );
        let back: TopicMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    /// A minimal, test-local provider backed by a `Mutex<Vec<TopicMetrics>>`
    /// — exercises the trait's basic contract independent of any real
    /// participant implementation, and independent of the atomics-based
    /// storage every real implementation in this crate happens to use.
    struct FixedProvider(Mutex<Vec<TopicMetrics>>);

    impl MetricsProvider for FixedProvider {
        fn topic_metrics(&self) -> Vec<TopicMetrics> {
            self.0.lock().unwrap().clone()
        }
    }

    /// `MetricsProvider` is object-safe: a provider can be selected at
    /// runtime and stored/called through `Box<dyn MetricsProvider>` and
    /// `Arc<dyn MetricsProvider>` without the caller knowing the concrete
    /// type.
    //fusa:test REQ-MON-005
    #[test]
    fn object_safety() {
        let sample = vec![TopicMetrics {
            topic: "t".to_string(),
            write_count: 1,
            ..Default::default()
        }];

        let boxed: Box<dyn MetricsProvider> = Box::new(FixedProvider(Mutex::new(sample.clone())));
        assert_eq!(boxed.topic_metrics(), sample);

        let arced: Arc<dyn MetricsProvider> = Arc::new(FixedProvider(Mutex::new(sample.clone())));
        assert_eq!(arced.topic_metrics(), sample);
    }

    /// `MetricsProvider` implementations are usable across concurrent
    /// tokio tasks, each incrementing an atomic counter behind the
    /// provider and reading a consistent snapshot back — the same
    /// concurrent-access shape every real wiring in this crate uses
    /// internally (a `std::sync::Mutex`-guarded map of `AtomicU64`
    /// counters). Compiling and passing this test is itself proof of the
    /// `Send + Sync` bound; the final assertion additionally proves no
    /// increment was lost to a data race.
    //fusa:test REQ-MON-005
    #[tokio::test]
    async fn provider_usable_across_concurrent_tasks() {
        struct CountingProvider(AtomicU64);
        impl MetricsProvider for CountingProvider {
            fn topic_metrics(&self) -> Vec<TopicMetrics> {
                vec![TopicMetrics {
                    topic: "t".to_string(),
                    write_count: self.0.load(Ordering::SeqCst),
                    ..Default::default()
                }]
            }
        }

        let provider: Arc<dyn MetricsProvider> = {
            // Constructed via a concrete type first so `fetch_add` below can
            // reach the counter directly through a second `Arc`, then
            // upcast to the trait object for the concurrent-task loop.
            let concrete = Arc::new(CountingProvider(AtomicU64::new(0)));
            let counter = Arc::clone(&concrete);
            let mut handles = Vec::new();
            for _ in 0..8 {
                let counter = Arc::clone(&counter);
                handles.push(tokio::spawn(async move {
                    counter.0.fetch_add(1, Ordering::SeqCst);
                }));
            }
            for handle in handles {
                handle.await.unwrap();
            }
            concrete
        };
        assert_eq!(provider.topic_metrics()[0].write_count, 8);
    }

    /// Compile-time assertion helper: any type satisfying it is `Send +
    /// Sync`. Pins that `FixedProvider` itself (not just a `Box`/`Arc`
    /// around it) meets the bound `MetricsProvider` requires.
    //fusa:test REQ-MON-005
    #[test]
    fn fixed_provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FixedProvider>();
    }
}
