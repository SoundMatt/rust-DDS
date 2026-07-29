// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RELAY protocol types bundled locally until a relay-rs crate is published.
//!
//! These types mirror the RELAY spec v1.11 definitions for Rust (§18.3).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Protocol identifiers per RELAY spec §3.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "i32", try_from = "i32")]
pub enum Protocol {
    Can = 1,
    Dds = 2,
    Lin = 3,
    Mqtt = 4,
    Rcp = 5,
    Someip = 6,
}

impl From<Protocol> for i32 {
    fn from(p: Protocol) -> i32 {
        p as i32
    }
}

impl TryFrom<i32> for Protocol {
    type Error = String;
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Protocol::Can),
            2 => Ok(Protocol::Dds),
            3 => Ok(Protocol::Lin),
            4 => Ok(Protocol::Mqtt),
            5 => Ok(Protocol::Rcp),
            6 => Ok(Protocol::Someip),
            _ => Err(format!("unknown protocol: {v}")),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::Can => "CAN",
            Protocol::Dds => "DDS",
            Protocol::Lin => "LIN",
            Protocol::Mqtt => "MQTT",
            Protocol::Rcp => "RCP",
            Protocol::Someip => "SOMEIP",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Semantic version triplet per RELAY spec §4.1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub major: i32,
    pub minor: i32,
    pub patch: i32,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// Universal message envelope per RELAY spec §4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub protocol: Protocol,
    pub version: Version,
    pub id: String,
    // §4/relay-message.json requires `payload` to be a base64-encoded JSON
    // string, matching every canonical protocol type's own `payload` field
    // (e.g. `dds.Sample.payload`, `types::Sample::payload`) — not a bare
    // `#[derive]`d JSON array of byte values, which the schema forbids and
    // which other RELAY implementations (and `relay interop`'s JSON decoder)
    // cannot parse as a `relay.Message`.
    #[serde(with = "crate::types::base64_serde")]
    pub payload: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub seq: u64,
    // §18.3 specifies BTreeMap for deterministic key ordering in byte-identical comparisons.
    //fusa:req REQ-INT-001
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl Message {
    pub fn new(protocol: Protocol, id: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            protocol,
            version: Version::default(),
            id: id.into(),
            payload,
            timestamp: Utc::now(),
            seq: 0,
            meta: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Back-pressure
// ---------------------------------------------------------------------------

/// Back-pressure policy for subscriber channels per RELAY spec §14.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BackPressurePolicy {
    /// Drop the arriving message when the channel is full (default).
    #[default]
    DropNewest,
    /// Drop the oldest buffered message to make room.
    DropOldest,
    /// Block until space is available.
    Block,
}

// ---------------------------------------------------------------------------
// Deadline QoS callback
// ---------------------------------------------------------------------------

/// Callback invoked when Deadline QoS enforcement detects a missed deadline.
///
/// Fires when a reader's `QoS::deadline_ns` interval elapses with no new
/// sample delivered on that reader; disabled (never fires) when
/// `QoS::deadline_ns == 0` or when no callback is registered via
/// [`with_deadline_callback`] / [`SubscriberOptions::deadline_missed`]. The
/// callback re-arms after firing and fires again for each subsequent
/// interval that elapses without a sample, matching go-DDS's
/// `SubscriberConfig.DeadlineMissedCallback` (`WithDeadlineMissed`) —
/// the behavioral reference this API shape follows for ecosystem
/// consistency.
///
/// A newtype around `Arc<dyn Fn() + Send + Sync>` rather than a bare trait
/// object: `Arc` makes it cheaply `Clone`, and the manual [`std::fmt::Debug`]
/// impl below lets it live inside `SubscriberOptions`, which derives `Debug`
/// (raw `dyn Fn` does not implement `Debug`).
#[derive(Clone)]
pub struct DeadlineCallback(pub(crate) Arc<dyn Fn() + Send + Sync>);

impl DeadlineCallback {
    /// Wrap `f` as a Deadline-missed callback.
    pub fn new(f: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Invoke the callback.
    pub(crate) fn fire(&self) {
        (self.0)()
    }
}

impl std::fmt::Debug for DeadlineCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeadlineCallback(..)")
    }
}

// ---------------------------------------------------------------------------
// SubscriberOptions
// ---------------------------------------------------------------------------

/// Options for subscriber channel configuration per RELAY spec §14.
#[derive(Clone, Debug, Default)]
pub struct SubscriberOptions {
    /// Buffer depth; 0 means use the implementation default (64).
    pub channel_depth: usize,
    /// Back-pressure policy applied when the channel is full.
    pub back_pressure: BackPressurePolicy,
    /// Topic filter for the RELAY Node adapter (DDS-specific §14.1).
    ///
    /// Set via [`with_topic`] when subscribing through a `relay::Node` adapter.
    pub topic: Option<String>,
    /// Deadline QoS callback (`QoS::deadline_ns`, §15.2).
    ///
    /// Set via [`with_deadline_callback`]. `None` disables Deadline
    /// enforcement for this reader regardless of `QoS::deadline_ns`, so a
    /// non-zero deadline with no registered callback is a documented no-op
    /// (matches go-DDS: `cfg.DeadlineMissedCallback == nil` skips arming the
    /// timer entirely) rather than a silent panic or error.
    pub deadline_missed: Option<DeadlineCallback>,
}

impl SubscriberOptions {
    /// Resolve the effective channel depth, falling back to `default_depth` when zero.
    pub fn chan_depth(&self, default_depth: usize) -> usize {
        if self.channel_depth > 0 {
            self.channel_depth
        } else {
            default_depth
        }
    }
}

/// Construct `SubscriberOptions` with a topic filter (required by the DDS Node adapter).
pub fn with_topic(topic: impl Into<String>) -> SubscriberOptions {
    SubscriberOptions {
        topic: Some(topic.into()),
        ..Default::default()
    }
}

/// Construct `SubscriberOptions` with a Deadline QoS callback registered.
///
/// Has effect only when combined with a non-zero `QoS::deadline_ns` on the
/// same `new_subscriber` call — see [`DeadlineCallback`].
pub fn with_deadline_callback(f: impl Fn() + Send + Sync + 'static) -> SubscriberOptions {
    SubscriberOptions {
        deadline_missed: Some(DeadlineCallback::new(f)),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// The four mandatory RELAY error sentinels per §5.1.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("relay: closed")]
    Closed,
    #[error("relay: not connected")]
    NotConnected,
    #[error("relay: timeout")]
    Timeout,
    #[error("relay: payload too large")]
    PayloadTooLarge,
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Lightweight context carrying an optional deadline per RELAY spec §18.3.
#[derive(Clone, Debug)]
pub struct Context {
    pub deadline: Option<Instant>,
}

impl Context {
    pub fn background() -> Self {
        Self { deadline: None }
    }

    pub fn with_timeout(d: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + d),
        }
    }

    pub fn done(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::background()
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// Node health status per RELAY spec §9.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Ok = 0,
    Degraded = 1,
    Down = 2,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Ok => write!(f, "ok"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Down => write!(f, "down"),
        }
    }
}

/// Health snapshot for a node per RELAY spec §9.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub status: HealthStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub details: String,
}

impl Health {
    pub fn ok() -> Self {
        Self {
            status: HealthStatus::Ok,
            details: String::new(),
        }
    }

    pub fn degraded(details: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            details: details.into(),
        }
    }

    pub fn down(details: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Down,
            details: details.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Runtime counters for a node per RELAY spec §9.1.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub write_count: u64,
    pub deliver_count: u64,
    pub drop_count: u64,
    pub bytes_written: u64,
    pub bytes_delivered: u64,
    pub error_count: u64,
}

// ---------------------------------------------------------------------------
// Node and Caller traits
// ---------------------------------------------------------------------------

/// Protocol-agnostic pub/sub interface per RELAY spec §10.1.
#[async_trait]
pub trait Node: Send + Sync {
    fn protocol(&self) -> Protocol;
    async fn send(&self, ctx: Context, msg: Message) -> Result<(), Error>;
    async fn subscribe(&self, opts: SubscriberOptions) -> Result<mpsc::Receiver<Message>, Error>;
    async fn close(&self) -> Result<(), Error>;
}

/// Extends Node with request/response semantics per RELAY spec §10.2.
#[async_trait]
pub trait Caller: Node {
    async fn call(&self, ctx: Context, req: Message) -> Result<Message, Error>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-RELAY-001
    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Can.to_string(), "CAN");
        assert_eq!(Protocol::Dds.to_string(), "DDS");
        assert_eq!(Protocol::Lin.to_string(), "LIN");
        assert_eq!(Protocol::Someip.to_string(), "SOMEIP");
    }

    //fusa:test REQ-RELAY-001
    #[test]
    fn protocol_serde_roundtrip() {
        let p = Protocol::Dds;
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "2");
        let p2: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    //fusa:test REQ-RELAY-001
    #[test]
    fn message_payload_serializes_as_base64_string_per_schema() {
        // relay-message.json's `payload` field is `{"type": "string",
        // "contentEncoding": "base64"}`, matching every canonical protocol
        // type's own payload field (e.g. `types::Sample::payload`). A bare
        // `#[derive]`d `Vec<u8>` would serialize as a JSON array of byte
        // values instead, which other RELAY implementations (and `relay
        // interop`'s JSON decoder) cannot parse as a `relay.Message`.
        let m = Message::new(Protocol::Dds, "rt/chatter", b"hello dds".to_vec());
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["payload"], serde_json::json!("aGVsbG8gZGRz"));

        let back: Message = serde_json::from_value(json).unwrap();
        assert_eq!(back.payload, b"hello dds");
    }

    //fusa:test REQ-RELAY-004
    //fusa:test REQ-DO-005
    #[test]
    fn version_display() {
        let v = Version {
            major: 1,
            minor: 7,
            patch: 0,
        };
        assert_eq!(v.to_string(), "1.7.0");
    }

    //fusa:test REQ-ASIL-010
    #[test]
    fn context_background_not_done() {
        let ctx = Context::background();
        assert!(!ctx.done());
    }

    //fusa:test REQ-PUB-003
    #[test]
    fn context_expired() {
        let ctx = Context::with_timeout(Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(1));
        assert!(ctx.done());
    }

    //fusa:test REQ-QOS-006
    #[test]
    fn subscriber_options_chan_depth() {
        let opts = SubscriberOptions::default();
        assert_eq!(opts.chan_depth(64), 64);
        let opts2 = SubscriberOptions {
            channel_depth: 128,
            ..Default::default()
        };
        assert_eq!(opts2.chan_depth(64), 128);
    }

    //fusa:test REQ-RELAY-003
    #[test]
    fn with_topic_sets_topic() {
        let opts = with_topic("vehicle/speed");
        assert_eq!(opts.topic.as_deref(), Some("vehicle/speed"));
    }

    //fusa:test REQ-DO-005
    #[test]
    fn health_ok() {
        let h = Health::ok();
        assert_eq!(h.status, HealthStatus::Ok);
        assert!(h.details.is_empty());
    }
}
