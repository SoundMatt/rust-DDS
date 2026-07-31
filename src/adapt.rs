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

//fusa:req REQ-RELAY-002
//fusa:req REQ-CONC-001
//fusa:req REQ-SEC-012
struct DdsNode {
    participant: Arc<dyn Participant>,
    publishers: Mutex<HashMap<String, Arc<dyn crate::participant::Publisher>>>,
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
        // Acquire the publisher, creating it on first use. The lock is released
        // before write() is called so concurrent senders on different topics
        // are not serialised by a single slow write.
        let pub_ = {
            let mut pubs = self.publishers.lock().await;
            if !pubs.contains_key(topic) {
                let qos = QoS::default();
                let p = self
                    .participant
                    .new_publisher(topic, qos)
                    .await
                    .map_err(|e| e.as_relay().unwrap_or(relay::Error::NotConnected))?;
                pubs.insert(topic.clone(), Arc::from(p));
            }
            Arc::clone(pubs.get(topic).unwrap())
        }; // lock released here — write() runs without holding the map lock
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
        let policy = opts.back_pressure;
        //fusa:req REQ-RELAY-003
        let topic = opts.topic.ok_or(relay::Error::NotConnected)?;
        // Channel depth / back-pressure are §14 channel options, not QoS (§8.2) —
        // pass them via SubscriberOptions, not folded into QoS.
        let sub_opts = SubscriberOptions {
            channel_depth: depth,
            back_pressure: policy,
            topic: None,
            deadline_missed: None,
        };

        let (rx, sub) = self
            .participant
            .new_subscriber(&topic, QoS::default(), sub_opts)
            .await
            .map_err(|e| e.as_relay().unwrap_or(relay::Error::NotConnected))?;

        // §10.5 rule 3 / §14 step 3: DropOldest must "drain one message from
        // the channel, then enqueue the new one" — i.e. evict the *head* of
        // the queue, not the arriving message. A plain `tokio::sync::mpsc`
        // channel can't do that from the sender side: only the `Receiver`
        // half (owned by the caller, not this task) can dequeue, so a
        // `try_send` on a full channel has no way to reach in and pop the
        // oldest buffered item.
        //
        // To give DropOldest real head-eviction semantics we keep our own
        // depth-bounded backlog (a plain `VecDeque`) as the actual §14
        // queue for this policy, and use a 1-slot `tx`/`out_rx` pair purely
        // as the handoff pipe to the caller. Eviction happens against the
        // backlog we control, so it is always the oldest *unsent* message
        // that is dropped — never the newly arriving one — which is
        // observably different from DropNewest (see
        // `drop_oldest_evicts_head_not_arriving_message` below).
        //
        // DropNewest and Block are untouched: `try_send`/discard-on-Full
        // already gives DropNewest correct semantics, and a plain blocking
        // `send` already gives Block correct semantics, directly against
        // the channel's own buffer.
        //fusa:req REQ-SEC-012
        if matches!(policy, relay::BackPressurePolicy::DropOldest) {
            let (tx, out_rx) = mpsc::channel::<Message>(1);
            let backlog_depth = depth.max(1);
            tokio::spawn(async move {
                let _sub = sub;
                let mut backlog: std::collections::VecDeque<Message> =
                    std::collections::VecDeque::with_capacity(backlog_depth);
                loop {
                    tokio::select! {
                        permit = tx.reserve(), if !backlog.is_empty() => {
                            match permit {
                                Ok(permit) => {
                                    if let Some(msg) = backlog.pop_front() {
                                        permit.send(msg);
                                    }
                                }
                                Err(_) => break, // caller dropped the receiver
                            }
                        }
                        sample = rx.recv() => {
                            match sample {
                                Some(sample) => {
                                    let msg = sample.to_message();
                                    if backlog.len() >= backlog_depth {
                                        // §14 step 3: evict the oldest queued
                                        // message to make room for the new one.
                                        backlog.pop_front();
                                    }
                                    backlog.push_back(msg);
                                }
                                None => break,
                            }
                        }
                    }
                }
            });
            return Ok(out_rx);
        }

        let (tx, out_rx) = mpsc::channel::<Message>(depth.max(1));

        // Move `sub` into the task so it stays alive (and the subscription
        // remains registered) for the entire lifetime of the forwarding loop.
        // When the mpsc sender is dropped (receiver closed), the task exits
        // and `sub` is dropped, releasing the subscription.
        //fusa:req REQ-SEC-012
        tokio::spawn(async move {
            let _sub = sub;
            while let Some(sample) = rx.recv().await {
                let msg = sample.to_message();
                match policy {
                    relay::BackPressurePolicy::DropNewest => {
                        match tx.try_send(msg) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {} // discard newest
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    relay::BackPressurePolicy::DropOldest => {
                        unreachable!("DropOldest is handled by the dedicated backlog path above")
                    }
                    relay::BackPressurePolicy::Block => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
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

    //fusa:test REQ-RELAY-002
    //fusa:test REQ-PUB-002
    //fusa:test REQ-DO-008
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

    //fusa:test REQ-RELAY-003
    //fusa:test REQ-IEC-002
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

    //fusa:test REQ-ERR-001
    //fusa:test REQ-PART-006
    #[tokio::test]
    async fn subscribe_after_close_returns_closed() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        node.close().await.unwrap();
        let err = node.subscribe(with_topic("x")).await.unwrap_err();
        assert_eq!(err, relay::Error::Closed);
    }

    //fusa:test REQ-PART-005
    //fusa:test REQ-IEC-010
    #[tokio::test]
    async fn close_is_idempotent() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        node.close().await.unwrap();
        node.close().await.unwrap();
    }

    // §10.5 rule 3 / §14 step 3 / REQ-QOS-007 regression: prior to this fix,
    // the relay-level mpsc forwarding in `subscribe()` applied DropOldest
    // identically to DropNewest (both simply discarded the arriving sample
    // via `try_send` on a full channel), so DropOldest never evicted the
    // head of its own queue at this layer. This reproduces exactly that
    // scenario — a 1-slot channel with three writes racing ahead of the
    // reader — and asserts the middle message ("b") is evicted in favor of
    // the newer one ("c"), not the other way around.
    //fusa:test REQ-QOS-007
    //fusa:test REQ-RELAY-003
    #[tokio::test]
    async fn drop_oldest_evicts_head_not_arriving_message() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);

        let opts = SubscriberOptions {
            channel_depth: 1,
            back_pressure: relay::BackPressurePolicy::DropOldest,
            topic: Some("conformance/drop-oldest".into()),
            ..SubscriberOptions::default()
        };
        let mut rx = node.subscribe(opts).await.unwrap();

        for payload in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
            node.send(
                Context::background(),
                Message::new(Protocol::Dds, "conformance/drop-oldest", payload),
            )
            .await
            .unwrap();
            // Give the background forwarding task a chance to pop the
            // sample out of the DDS-layer queue and apply the relay-level
            // DropOldest policy before the next write lands.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.payload, b"a");
        assert_eq!(second.payload, b"c");

        // "b" was evicted from the backlog, not delivered — no third message.
        let third = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        assert!(third.is_err(), "expected no third message (b was evicted)");
    }

    // Companion to `drop_oldest_evicts_head_not_arriving_message`: the exact
    // same write sequence under DropNewest must produce *different* channel
    // contents ("a" only — both later arrivals discarded), proving the two
    // policies are no longer byte-identical at the relay-level channel.
    //fusa:test REQ-QOS-006
    #[tokio::test]
    async fn drop_newest_differs_from_drop_oldest_under_same_load() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);

        let opts = SubscriberOptions {
            channel_depth: 1,
            back_pressure: relay::BackPressurePolicy::DropNewest,
            topic: Some("conformance/drop-newest".into()),
            ..SubscriberOptions::default()
        };
        let mut rx = node.subscribe(opts).await.unwrap();

        for payload in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
            node.send(
                Context::background(),
                Message::new(Protocol::Dds, "conformance/drop-newest", payload),
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.payload, b"a");

        // Under DropNewest both "b" and "c" were discarded on arrival
        // (unlike DropOldest, which delivers "c").
        let second = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        assert!(
            second.is_err(),
            "expected no second message under DropNewest"
        );
    }

    //fusa:test REQ-RELAY-002
    //fusa:test REQ-RELAY-004
    #[tokio::test]
    async fn protocol_is_dds() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let node = adapt(p as Arc<dyn Participant>);
        assert_eq!(node.protocol(), Protocol::Dds);
    }

    //fusa:test REQ-RELAY-001
    //fusa:test REQ-DO-007
    #[tokio::test]
    async fn to_message_round_trip() {
        let mut guid = crate::types::Guid::default();
        for (i, b) in guid.iter_mut().enumerate() {
            *b = (i + 1) as u8; // safe: i in [0,15] from enumerate on [u8;16], (i+1) in [1,16] fits u8
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
