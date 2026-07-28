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
//! (`HealthProvider` today; `MetricsProvider` is the milestone's next
//! checklist item) are ported from go-DDS's *root* package
//! (`github.com/SoundMatt/go-DDS`, `dds.go`) rather than from any single
//! `observability/*` subpackage: go-DDS defines `HealthProvider`,
//! `MetricsProvider`, `DiscoveryMetricsProvider`, and `TopicMetricsProvider`
//! as small root-package interfaces that any `dds.Participant`
//! implementation may optionally satisfy, and `observability/monitor`
//! consumes them via a Go interface type-assertion
//! (`if hp, ok := p.(dds.HealthProvider); ok { ... }`) — the "optional
//! capability" pattern this module tree's [`health`] submodule mirrors in
//! Rust as a plain trait each participant implementation opts into,
//! matching this crate's established `src/security/plugin.rs` shape
//! (object-safe, `Send + Sync`, no blanket downcasting machinery — a
//! caller that wants optional-trait dispatch stores the concrete type or a
//! `dyn HealthProvider` handle explicitly, since Rust trait objects do not
//! support runtime interface discovery the way Go's does).
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

pub mod health;

pub use health::{Health, HealthProvider, HealthStatus};
