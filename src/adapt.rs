// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RELAY adapter — wraps a DDS Participant as a relay::Node.
//!
//! Implements §10.3, §10.4, §10.5, and §15.7.2 of the RELAY spec.
//!
//! Use [`adapt`] to wrap any `Participant` as a `relay::Node`:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rust_dds::{adapt, mock::MockParticipant, types::Domain};
//!
//! # #[tokio::main]
//! # async fn main() {
//! let p = MockParticipant::new(Domain(0)).unwrap();
//! let node = adapt(p as Arc<dyn rust_dds::participant::Participant>);
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

use crate::error::Error as DdsError;
use crate::participant::Participant;
use crate::relay::{self, Context, Message, Protocol, SubscriberOptions};
use crate::types::{QoS, Sample};

// ---------------------------------------------------------------------------
// to_message / from_message
// ---------------------------------------------------------------------------

/// Convert a DDS Sample to a relay::Message per RELAY spec §15.7.2.
//fusa:req REQ-RELAY-001
pub fn to_message(s: &Sample) -> Message {
    s.to_message()
}

/// Convert a relay::Message back to a DDS Sample per RELAY spec §15.7.2.
//fusa:req REQ-RELAY-001
pub fn from_message(m: &Message) -> Result<Sample, DdsError> {
    Sample::from_message(m)
}

// ---------------------------------------------------------------------------
// DdsNode adapter
// ---------------------------------------------------------------------------

struct DdsNode {
    participant: Arc<dyn Participant>,
    publishers: Mutex<HashMap<String, Box<dyn crate::participant::Publisher>>>,
    closed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl relay::Node for DdsNode {
    fn protocol(&self) -> Protocol {
        Protocol::Dds
    }

    async fn send(&self, ctx: Context, msg: Message) -> Result<(), relay::Error> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(relay::Error::Closed);
        }
        if ctx.done() {
            return Err(relay::Error::Timeout);
        }
        let topic = &msg.id;
        let mut pubs = self.publishers.lock().await;
        if !pubs.contains_key(topic) {
            let qos = QoS::default();
            let pub_ = self
                .participant
                .new_publisher(topic, qos)
                .await
                .map_err(|e| e.as_relay().unwrap_or(relay::Error::NotConnected))?;
            pubs.insert(topic.clone(), pub_);
        }
        let pub_ = pubs.get(topic).unwrap();
        pub_.write(msg.payload)
            .await
            .map_err(|e| e.as_relay().unwrap_or(relay::Error::NotConnected))
    }

    async fn subscribe(
        &self,
        opts: SubscriberOptions,
    ) -> Result<mpsc::Receiver<Message>, relay::Error> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(relay::Error::Closed);
        }
        let depth = opts.chan_depth(64);
        let topic = opts.topic.ok_or(relay::Error::NotConnected)?;
        let qos = QoS {
            channel_depth: depth,
            back_pressure: opts.back_pressure,
            ..QoS::default()
        };

        let (rx, _sub) = self
            .participant
            .new_subscriber(&topic, qos)
            .await
            .map_err(|e| e.as_relay().unwrap_or(relay::Error::NotConnected))?;

        let (tx, out_rx) = mpsc::channel::<Message>(depth.max(1));

        tokio::spawn(async move {
            while let Some(sample) = rx.recv().await {
                let msg = sample.to_message();
                if tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        Ok(out_rx)
    }

    async fn close(&self) -> Result<(), relay::Error> {
        if self
            .closed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            return Ok(());
        }
        self.participant
            .close()
            .await
            .map_err(|e| e.as_relay().unwrap_or(relay::Error::Closed))
    }
}

/// Wrap a `Participant` as a `relay::Node`.
///
/// The returned node routes `send()` calls to per-topic DDS publishers
/// (created on demand), and `subscribe()` calls to DDS subscribers
/// forwarding samples as `relay::Message` envelopes.
///
/// Requires `opts.topic` to be set (use [`relay::with_topic`] to construct
/// `SubscriberOptions` with a topic).
//fusa:req REQ-RELAY-002
pub fn adapt(participant: Arc<dyn Participant>) -> Box<dyn relay::Node> {
    Box::new(DdsNode {
        participant,
        publishers: Mutex::new(HashMap::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockParticipant;
    use crate::relay::with_topic;
    use crate::types::Domain;
    use std::time::Duration;

    #[tokio::test]
    async fn adapt_send_and_subscribe() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);

        let mut rx = node
            .subscribe(with_topic("conformance/topic"))
            .await
            .unwrap();

        node.send(
            Context::background(),
            Message::new(Protocol::Dds, "conformance/topic", b"ping".to_vec()),
        )
        .await
        .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.payload, b"ping");
        assert_eq!(msg.id, "conformance/topic");
        assert_eq!(msg.protocol, Protocol::Dds);
    }

    #[tokio::test]
    async fn subscribe_without_topic_returns_not_connected() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        let err = node
            .subscribe(SubscriberOptions::default())
            .await
            .unwrap_err();
        assert_eq!(err, relay::Error::NotConnected);
    }

    #[tokio::test]
    async fn subscribe_after_close_returns_closed() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        node.close().await.unwrap();
        let err = node.subscribe(with_topic("x")).await.unwrap_err();
        assert_eq!(err, relay::Error::Closed);
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        node.close().await.unwrap();
        node.close().await.unwrap();
    }

    #[tokio::test]
    async fn protocol_is_dds() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        assert_eq!(node.protocol(), Protocol::Dds);
    }

    #[tokio::test]
    async fn to_message_round_trip() {
        let mut guid = crate::types::Guid::default();
        for (i, b) in guid.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let sample = Sample {
            topic: "rt/chatter".into(),
            payload: b"hello dds".to_vec(),
            timestamp: chrono::Utc::now(),
            sequence_number: 7,
            writer_guid: guid,
        };
        let msg = to_message(&sample);
        let back = from_message(&msg).unwrap();
        assert_eq!(back.topic, sample.topic);
        assert_eq!(back.payload, sample.payload);
        assert_eq!(back.sequence_number, sample.sequence_number);
        assert_eq!(back.writer_guid, sample.writer_guid);
    }
}
