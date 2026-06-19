// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Core DDS types: Domain, GUID, Sample, and QoS.
//!
//! Canonical definitions per RELAY spec §15.7 and go-DDS interface.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::relay::{Message, Protocol, Version};

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// DDS domain identifier — MUST be in the range 0–232 inclusive.
///
/// Domains partition the DDS communication space. Participants in different
/// domains do not communicate.
//fusa:req REQ-PART-001
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Domain(pub i32);

impl Domain {
    pub fn new(id: i32) -> Result<Self, Error> {
        let d = Domain(id);
        validate_domain(d)?;
        Ok(d)
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validate that the domain is within the allowed range [0, 232].
///
/// Returns `Error::DomainOutOfRange` for values outside this range,
/// consistent with RELAY spec §15.7 and the mandatory sentinel mapping.
//fusa:req REQ-PART-001
pub fn validate_domain(d: Domain) -> Result<(), Error> {
    if d.0 < 0 || d.0 > 232 {
        return Err(Error::DomainOutOfRange);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------

/// 16-byte globally unique identifier for a DDS endpoint.
///
/// Bytes 0–11 are the GuidPrefix; bytes 12–15 are the EntityId.
/// The zero value indicates "not set".
//fusa:req REQ-SUB-002
pub type Guid = [u8; 16];

// ---------------------------------------------------------------------------
// Sample
// ---------------------------------------------------------------------------

/// A single data sample delivered to a Subscriber.
///
/// `timestamp` is the source time of the write; zero (Unix epoch) means
/// no timestamp was provided by the transport.
/// `sequence_number` is a monotonically increasing per-writer counter; 0 means not set.
/// `writer_guid` identifies the publishing endpoint; all-zeros means not set.
//fusa:req REQ-SUB-001
//fusa:req REQ-SUB-002
//fusa:req REQ-SUB-003
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub topic: String,
    #[serde(with = "base64_serde")]
    pub payload: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "seq")]
    pub sequence_number: u64,
    pub writer_guid: Guid,
}

impl Sample {
    /// Convert this Sample to a RELAY Message envelope per spec §15.7.2.
    //fusa:req REQ-RELAY-001
    pub fn to_message(&self) -> Message {
        let mut meta = std::collections::HashMap::new();
        meta.insert("dds.writer_guid".into(), hex::encode(self.writer_guid));
        Message {
            protocol: Protocol::Dds,
            version: Version::default(),
            id: self.topic.clone(),
            payload: self.payload.clone(),
            timestamp: self.timestamp,
            seq: self.sequence_number,
            meta,
        }
    }

    /// Convert a RELAY Message envelope back to a Sample per spec §15.7.2.
    //fusa:req REQ-RELAY-001
    pub fn from_message(m: &Message) -> Result<Self, Error> {
        let mut writer_guid = Guid::default();
        if let Some(g) = m.meta.get("dds.writer_guid") {
            let bytes = hex::decode(g)
                .map_err(|_| Error::Other(format!("invalid dds.writer_guid hex: {g}")))?;
            if bytes.len() != 16 {
                return Err(Error::Other(format!(
                    "dds.writer_guid must be 32 hex chars, got {}",
                    g.len()
                )));
            }
            writer_guid.copy_from_slice(&bytes);
        }
        Ok(Sample {
            topic: m.id.clone(),
            payload: m.payload.clone(),
            timestamp: m.timestamp,
            sequence_number: m.seq,
            writer_guid,
        })
    }
}

// ---------------------------------------------------------------------------
// QoS
// ---------------------------------------------------------------------------

/// Reliability guarantee for a topic endpoint.
///
/// `BestEffort` — no retransmission; suitable for high-frequency sensor data.
/// `Reliable` — retransmits until acknowledged; required for commands.
//fusa:req REQ-QOS-001
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReliabilityKind {
    #[default]
    BestEffort = 0,
    Reliable = 1,
}

/// Durability — whether late-joining subscribers see historical samples.
///
/// `Volatile` — no history cached; late joiners start fresh.
/// `TransientLocal` — last `history_depth` samples cached per publisher.
//fusa:req REQ-QOS-002
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurabilityKind {
    #[default]
    Volatile = 0,
    TransientLocal = 1,
}

/// Quality-of-Service settings for a publisher or subscriber endpoint.
///
/// `DefaultQoS` is BestEffort + Volatile with history depth 1.
/// `ReliableQoS` is Reliable + TransientLocal with history depth 1.
//fusa:req REQ-QOS-001
//fusa:req REQ-QOS-002
//fusa:req REQ-QOS-003
//fusa:req REQ-QOS-004
//fusa:req REQ-QOS-005
//fusa:req REQ-QOS-006
//fusa:req REQ-QOS-007
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QoS {
    pub reliability: ReliabilityKind,
    pub durability: DurabilityKind,
    /// How many historical samples to retain (0 → implementation default of 1).
    pub history_depth: i32,
    /// Maximum subscriber channel depth (0 → implementation default of 64).
    pub channel_depth: usize,
    /// Maximum acceptable age of a sample in nanoseconds; 0 = disabled.
    pub deadline_ns: u64,
    /// Back-pressure policy when the subscriber channel is full.
    pub back_pressure: crate::relay::BackPressurePolicy,
}

impl Default for QoS {
    fn default() -> Self {
        Self {
            reliability: ReliabilityKind::BestEffort,
            durability: DurabilityKind::Volatile,
            history_depth: 1,
            channel_depth: 0,
            deadline_ns: 0,
            back_pressure: crate::relay::BackPressurePolicy::DropNewest,
        }
    }
}

/// BestEffort + Volatile — the default for sensor / telemetry topics.
pub const DEFAULT_QOS: QoS = QoS {
    reliability: ReliabilityKind::BestEffort,
    durability: DurabilityKind::Volatile,
    history_depth: 1,
    channel_depth: 0,
    deadline_ns: 0,
    back_pressure: crate::relay::BackPressurePolicy::DropNewest,
};

/// Reliable + TransientLocal — for command / actuator topics where
/// late-joining subscribers must receive the current value.
pub const RELIABLE_QOS: QoS = QoS {
    reliability: ReliabilityKind::Reliable,
    durability: DurabilityKind::TransientLocal,
    history_depth: 1,
    channel_depth: 0,
    deadline_ns: 0,
    back_pressure: crate::relay::BackPressurePolicy::DropNewest,
};

// ---------------------------------------------------------------------------
// base64 serde helper
// ---------------------------------------------------------------------------

mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn validate_domain_valid() {
        assert!(validate_domain(Domain(0)).is_ok());
        assert!(validate_domain(Domain(1)).is_ok());
        assert!(validate_domain(Domain(232)).is_ok());
    }

    #[test]
    fn validate_domain_invalid() {
        assert!(matches!(
            validate_domain(Domain(-1)),
            Err(Error::DomainOutOfRange)
        ));
        assert!(matches!(
            validate_domain(Domain(233)),
            Err(Error::DomainOutOfRange)
        ));
        assert!(matches!(
            validate_domain(Domain(1000)),
            Err(Error::DomainOutOfRange)
        ));
    }

    #[test]
    fn sample_to_message_golden_vector() {
        let mut guid = Guid::default();
        for (i, b) in guid.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let ts = Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap();
        let s = Sample {
            topic: "rt/chatter".into(),
            payload: b"hello dds".to_vec(),
            timestamp: ts,
            sequence_number: 7,
            writer_guid: guid,
        };
        let m = s.to_message();
        assert_eq!(m.protocol, Protocol::Dds);
        assert_eq!(m.id, "rt/chatter");
        assert_eq!(m.payload, b"hello dds");
        assert_eq!(m.seq, 7);
        assert_eq!(
            m.meta["dds.writer_guid"],
            "0102030405060708090a0b0c0d0e0f10"
        );
    }

    #[test]
    fn sample_round_trip() {
        let mut guid = Guid::default();
        for (i, b) in guid.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let orig = Sample {
            topic: "rt/chatter".into(),
            payload: b"hello dds".to_vec(),
            timestamp: Utc::now(),
            sequence_number: 7,
            writer_guid: guid,
        };
        let msg = orig.to_message();
        let back = Sample::from_message(&msg).unwrap();
        assert_eq!(back.topic, orig.topic);
        assert_eq!(back.payload, orig.payload);
        assert_eq!(back.sequence_number, orig.sequence_number);
        assert_eq!(back.writer_guid, orig.writer_guid);
    }

    #[test]
    fn default_qos_best_effort_volatile() {
        let q = QoS::default();
        assert_eq!(q.reliability, ReliabilityKind::BestEffort);
        assert_eq!(q.durability, DurabilityKind::Volatile);
        assert_eq!(q.history_depth, 1);
    }

    #[test]
    fn reliable_qos_reliable_transient_local() {
        assert_eq!(RELIABLE_QOS.reliability, ReliabilityKind::Reliable);
        assert_eq!(RELIABLE_QOS.durability, DurabilityKind::TransientLocal);
    }
}
