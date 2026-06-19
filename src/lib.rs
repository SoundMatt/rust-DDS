// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! rust-DDS — DDS (Data Distribution Service) publish/subscribe for Rust.
//!
//! Works in any domain: IoT, robotics, industrial control, vehicle networks,
//! simulation, and more. Conforms to RELAY spec v1.10.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rust_dds::{
//!     mock::MockParticipant,
//!     participant::Participant,
//!     types::{Domain, QoS},
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let p = MockParticipant::new(Domain(0)).unwrap();
//!
//!     let (rx, _sub) = p.new_subscriber("sensors/temperature", QoS::default()).await.unwrap();
//!     let pub_ = p.new_publisher("sensors/temperature", QoS::default()).await.unwrap();
//!
//!     pub_.write(b"{\"value\": 21.5}".to_vec()).await.unwrap();
//!
//!     let sample = rx.recv().await.unwrap();
//!     println!("{}", String::from_utf8_lossy(&sample.payload));
//! }
//! ```
//!
//! # Switching implementations
//!
//! Application code programs against the `Participant` trait. Swap at the call site:
//!
//! ```rust,no_run
//! // Development / tests — no system library needed:
//! use rust_dds::mock::MockParticipant;
//! use rust_dds::types::Domain;
//!
//! let p = MockParticipant::new(Domain(0)).unwrap();
//! ```
//!
//! Additional transports (RTPS/UDP, shared-memory) are planned for later milestones.
//!
//! # RELAY adapter
//!
//! Wrap any `Participant` as a `relay::Node` for protocol-agnostic tooling:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rust_dds::{adapt, mock::MockParticipant, participant::Participant, types::Domain};
//! use rust_dds::relay::{with_topic, Context, Message, Protocol};
//!
//! # #[tokio::main]
//! # async fn main() {
//! let p = MockParticipant::new(Domain(0)).unwrap();
//! let node = adapt(p as Arc<dyn Participant>);
//!
//! let mut rx = node.subscribe(with_topic("vehicle/speed")).await.unwrap();
//! node.send(Context::background(), Message::new(Protocol::Dds, "vehicle/speed", b"{\"kmh\":80}".to_vec())).await.unwrap();
//! let msg = rx.recv().await.unwrap();
//! println!("Received: {:?}", msg.payload);
//! # }
//! ```

pub mod adapt;
pub mod error;
pub mod mock;
pub mod participant;
pub mod relay;
pub mod types;

pub use adapt::{adapt, from_message, to_message};
pub use error::Error;
pub use participant::{Participant, Publisher, SampleReceiver, Subscriber};
pub use types::{
    validate_domain, Domain, DurabilityKind, Guid, QoS, ReliabilityKind, Sample, DEFAULT_QOS,
    RELIABLE_QOS,
};

// ── Module-level process requirements ────────────────────────────────────────
// The following requirements are enforced by design across the entire crate
// and are anchored here for traceability. They are verified by CI gates rather
// than by individual function tests.
//
//fusa:req REQ-ASIL-002 — no unsafe blocks exist anywhere in this crate
//fusa:req REQ-ASIL-003 — all public entry points propagate errors via Result; no .unwrap() on user-visible paths
//fusa:req REQ-ASIL-004 — every requirement has a //fusa:test annotation; verified by the fusa-trace CI job
//fusa:req REQ-ASIL-009 — all public APIs documented with Rustdoc including safety pre/post-conditions
//fusa:req REQ-IEC-003 — bidirectional traceability enforced by the fusa-trace CI job
//fusa:req REQ-IEC-004 — test completeness gate: fusa-trace CI blocks on any untested requirement
//fusa:req REQ-DO-001 — bidirectional traceability per DO-178C: fusa-trace CI enforces req → code → test
//fusa:req REQ-DO-002 — no dead code: cargo clippy -D warnings catches dead_code; enforced by lint CI job
//fusa:req REQ-DO-003 — decision coverage: all conditional branches exercised by tests across the suite
//fusa:req REQ-DO-004 — documented assumptions: see inline comments in participant.rs and adapt.rs
//fusa:req REQ-MEM-001 — no unsafe Rust in any module; verified by absence of unsafe blocks
//fusa:req REQ-MEM-005 — no Arc cycles: Arc<SubInner> is held by SampleReceiver + broker, not back-referenced
//fusa:req REQ-SEC-005 — error messages contain no addresses, counters, or internal state
//fusa:req REQ-SEC-006 — dependency CVE audit: cargo audit runs in the security-audit CI job

/// The RELAY spec version this implementation targets.
//fusa:req REQ-RELAY-004
//fusa:req REQ-RELAY-005
//fusa:req REQ-RELAY-006
//fusa:req REQ-DO-005
pub const RELAY_SPEC_VERSION: &str = "1.10";

/// Alias for `RELAY_SPEC_VERSION` for CLI and conformance contexts.
pub const SPEC_VERSION: &str = RELAY_SPEC_VERSION;
