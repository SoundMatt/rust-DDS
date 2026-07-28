// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Observability — `ROADMAP.md`'s "Planned — v0.6 — Observability (Tier 5)"
//! milestone, part of the parity build-out plan's Tier 5 group (the
//! `dds-observability` crate in the target workspace architecture; stays in
//! this single crate until the workspace cutover gated on RELAY spec issue
//! #59, per the "Interim structure vs. full cutover" section — though
//! unlike Tiers 1–4, Tier 5's module names are explicitly left
//! unconstrained by RELAY#59, so there is no naming-ratification blocker
//! for this tier at all).
//!
//! Reference: go-DDS's `observability` group
//! (`github.com/SoundMatt/go-DDS`) — `otel`/`admin`/`monitor`/`record`/
//! `services`, 1,391 LOC total, the smallest of the five parity groups but
//! with broad surface area. The provider traits under this module
//! (`HealthProvider`, `MetricsProvider`) are ported from go-DDS's *root*
//! package (`github.com/SoundMatt/go-DDS`, `dds.go`) rather than from any
//! single `observability/*` subpackage: go-DDS defines `HealthProvider`,
//! `MetricsProvider`, `DiscoveryMetricsProvider`, and `TopicMetricsProvider`
//! as small root-package interfaces that any `dds.Participant`
//! implementation may optionally satisfy, and `observability/monitor`
//! consumes them via a Go interface type-assertion
//! (`if hp, ok := p.(dds.HealthProvider); ok { ... }`) — the "optional
//! capability" pattern this module tree's [`health`]/[`metrics`] submodules
//! mirror in Rust as a plain trait each participant implementation opts
//! into, matching this crate's established `src/security/plugin.rs` shape
//! (object-safe, `Send + Sync`, no blanket downcasting machinery — a
//! caller that wants optional-trait dispatch stores the concrete type or a
//! `dyn HealthProvider`/`dyn MetricsProvider` handle explicitly, since Rust
//! trait objects do not support runtime interface discovery the way Go's
//! does).
//!
//! - [`health`] — [`health::HealthProvider`], [`health::Health`], and
//!   [`health::HealthStatus`]. Direct port of go-DDS's `dds.HealthProvider`
//!   interface and its `dds.Health`/`dds.HealthStatus` types (`dds.go`).
//!   This milestone's first checklist item, "`HealthProvider` trait".
//!   Implemented by [`crate::mock::MockParticipant`],
//!   [`crate::shmem::ShmemParticipant`], and
//!   [`crate::rtps::dds_participant::RtpsUdpParticipant`] — every
//!   concrete, public `Participant` implementation this crate has today —
//!   matching go-DDS's `mock`, `shmem`, and `rtps` packages, which each
//!   implement `dds.HealthProvider` on their own participant type with an
//!   identical `closed` → [`health::HealthStatus::Down`] / otherwise →
//!   [`health::HealthStatus::Ok`] shape. Wiring `HealthProvider` into an
//!   HTTP/admin surface analogous to go-DDS's `observability/monitor`
//!   (`GET /health`) is out of scope here — no such surface exists in this
//!   crate yet — and is left for a future item under this milestone or
//!   "Planned — v0.9 — Enterprise"'s "HTTP admin API".
//! - [`metrics`] — [`metrics::MetricsProvider`] and [`metrics::TopicMetrics`].
//!   This milestone's second checklist item, "`MetricsProvider` trait
//!   (per-topic write/deliver/drop counters)". Despite the shared trait
//!   name, this is a port of go-DDS's `dds.TopicMetricsProvider`/
//!   `dds.TopicMetrics` (per-topic counters), not go-DDS's own aggregate,
//!   participant-wide `dds.MetricsProvider`/`dds.Metrics` — see
//!   [`metrics`]'s own module docs for why. Implemented by every concrete,
//!   public `Participant` implementation this crate has today, each
//!   counting writes/delivers/drops/bytes with `AtomicU64` counters behind
//!   a `std::sync::Mutex`-guarded per-topic map (never a `tokio::sync::RwLock`
//!   — see [`metrics`]'s docs for why that specific choice matters for a
//!   synchronous trait method).

pub mod health;
pub mod metrics;

pub use health::{Health, HealthProvider, HealthStatus};
pub use metrics::{MetricsProvider, TopicMetrics};
