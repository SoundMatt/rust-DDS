// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! In-process DDS broker for unit testing and development.
//!
//! Zero dependencies beyond the crate itself. Provides `MockParticipant` which
//! routes samples between publishers and subscribers in-process with full
//! QoS semantics (TransientLocal last-value cache, back-pressure policies).

use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use chrono::Utc;

use crate::error::Error;
use crate::participant::{Participant, Publisher, SampleReceiver, SubInner, Subscriber};
use crate::relay::Context;

type WriteLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
use crate::types::{validate_domain, Domain, DurabilityKind, Guid, QoS, Sample};

// ---------------------------------------------------------------------------
// Broker — shared routing table
// ---------------------------------------------------------------------------

struct TopicState {
    subscribers: Vec<Arc<SubInner>>,
    /// TransientLocal cache: last `history_depth` samples.
    cache: VecDeque<Sample>,
    history_depth: usize,
}

impl TopicState {
    fn new(history_depth: usize) -> Self {
        Self {
            subscribers: Vec::new(),
            cache: VecDeque::with_capacity(history_depth.max(1)),
            history_depth,
        }
    }

    fn push_to_cache(&mut self, sample: Sample) {
        if self.history_depth > 0 {
            if self.cache.len() >= self.history_depth {
                self.cache.pop_front();
            }
            self.cache.push_back(sample);
        }
    }
}

struct Broker {
    topics: Mutex<HashMap<String, TopicState>>,
}

impl Broker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            topics: Mutex::new(HashMap::new()),
        })
    }

    fn publish(&self, topic: &str, sample: Sample, qos: &QoS) {
        let mut topics = self.topics.lock().unwrap();
        let state = topics
            .entry(topic.to_string())
            .or_insert_with(|| TopicState::new(qos.history_depth.max(1) as usize));

        if qos.durability == DurabilityKind::TransientLocal {
            state.push_to_cache(sample.clone());
        }

        state
            .subscribers
            .retain(|sub| !sub.closed.load(Ordering::SeqCst));
        for sub in &state.subscribers {
            sub.push(sample.clone());
        }
    }

    fn subscribe(&self, topic: &str, qos: &QoS) -> Arc<SubInner> {
        let depth = if qos.channel_depth > 0 {
            qos.channel_depth
        } else {
            64
        };
        let inner = Arc::new(SubInner::new(depth, qos.back_pressure));

        let mut topics = self.topics.lock().unwrap();
        let state = topics
            .entry(topic.to_string())
            .or_insert_with(|| TopicState::new(qos.history_depth.max(1) as usize));

        // Deliver cached samples to late-joining TransientLocal subscribers.
        if qos.durability == DurabilityKind::TransientLocal {
            for cached in &state.cache {
                inner.push(cached.clone());
            }
        }

        state.subscribers.push(inner.clone());
        inner
    }
}

// ---------------------------------------------------------------------------
// MockPublisher
// ---------------------------------------------------------------------------

struct MockPublisher {
    topic: String,
    qos: QoS,
    broker: Arc<Broker>,
    writer_guid: Guid,
    seq: AtomicU64,
    closed: AtomicBool,
}

#[async_trait]
impl Publisher for MockPublisher {
    async fn write(&self, payload: Vec<u8>) -> Result<(), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let sample = Sample {
            topic: self.topic.clone(),
            payload,
            timestamp: Utc::now(),
            sequence_number: seq,
            writer_guid: self.writer_guid,
        };
        self.broker.publish(&self.topic, sample, &self.qos);
        Ok(())
    }

    async fn write_ctx(&self, ctx: Context, payload: Vec<u8>) -> Result<(), Error> {
        if ctx.done() {
            return Err(Error::Timeout);
        }
        self.write(payload).await
    }

    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockSubscriber
// ---------------------------------------------------------------------------

struct MockSubscriber {
    inner: Arc<SubInner>,
    broker_inner: Arc<SubInner>,
}

#[async_trait]
impl Subscriber for MockSubscriber {
    fn unsubscribe(&self) {
        self.broker_inner.unsubscribe();
    }

    async fn close(&self) -> Result<(), Error> {
        self.inner.close();
        self.broker_inner.close();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockParticipant
// ---------------------------------------------------------------------------

/// In-process DDS participant — zero network dependencies.
///
/// Suitable for unit tests, integration tests, and development workflows.
/// All pub/sub routing is in-process; samples are delivered synchronously
/// on `Publisher::write`.
///
/// Create via `MockParticipant::new(Domain(0))`.
//fusa:req REQ-MOCK-001
//fusa:req REQ-MOCK-002
//fusa:req REQ-MOCK-003
pub struct MockParticipant {
    domain: Domain,
    broker: Arc<Broker>,
    closed: AtomicBool,
    /// GUID prefix for all publishers created by this participant.
    guid_prefix: [u8; 12],
    pub_counter: AtomicU64,
    written_payloads: WriteLog,
}

impl MockParticipant {
    /// Create a new in-process participant on the given domain.
    ///
    /// Returns `Error::DomainOutOfRange` if `domain` is outside [0, 232].
    //fusa:req REQ-MOCK-001
    pub fn new(domain: Domain) -> Result<Arc<Self>, Error> {
        validate_domain(domain)?;
        let mut prefix = [0u8; 12];
        prefix[0] = domain.0 as u8;
        Ok(Arc::new(Self {
            domain,
            broker: Broker::new(),
            closed: AtomicBool::new(false),
            guid_prefix: prefix,
            pub_counter: AtomicU64::new(0),
            written_payloads: Arc::new(Mutex::new(Vec::new())),
        }))
    }

    /// Return all payloads written through publishers on this participant.
    ///
    /// Useful for assertion in unit tests. Returns `(topic, payload)` pairs
    /// in write order.
    pub fn written_payloads(&self) -> Vec<(String, Vec<u8>)> {
        self.written_payloads.lock().unwrap().clone()
    }

    /// Drain the written-payloads log.
    pub fn reset(&self) {
        self.written_payloads.lock().unwrap().clear();
    }

    /// Construct a writer GUID from the participant prefix and a publisher counter.
    fn make_guid(&self, id: u64) -> Guid {
        let mut guid = Guid::default();
        guid[..12].copy_from_slice(&self.guid_prefix);
        guid[12..].copy_from_slice(&(id as u32).to_be_bytes());
        guid
    }
}

#[async_trait]
impl Participant for MockParticipant {
    async fn new_publisher(&self, topic: &str, qos: QoS) -> Result<Box<dyn Publisher>, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if topic.is_empty() {
            return Err(Error::TopicEmpty);
        }
        let id = self.pub_counter.fetch_add(1, Ordering::SeqCst);
        let guid = self.make_guid(id);
        let written = Arc::clone(&self.written_payloads);
        let topic_str = topic.to_string();
        let broker = self.broker.clone();
        let qos_clone = qos.clone();

        Ok(Box::new(RecordingPublisher {
            inner: MockPublisher {
                topic: topic_str.clone(),
                qos: qos_clone,
                broker,
                writer_guid: guid,
                seq: AtomicU64::new(0),
                closed: AtomicBool::new(false),
            },
            log: written,
            topic: topic_str,
        }))
    }

    async fn new_subscriber(
        &self,
        topic: &str,
        qos: QoS,
    ) -> Result<(SampleReceiver, Box<dyn Subscriber>), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if topic.is_empty() {
            return Err(Error::TopicEmpty);
        }
        let inner = self.broker.subscribe(topic, &qos);
        let receiver = SampleReceiver {
            inner: inner.clone(),
        };
        let sub = MockSubscriber {
            inner: inner.clone(),
            broker_inner: inner,
        };
        Ok((receiver, Box::new(sub)))
    }

    fn domain(&self) -> Domain {
        self.domain
    }

    async fn close(&self) -> Result<(), Error> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }
        let topics = self.broker.topics.lock().unwrap();
        for state in topics.values() {
            for sub in &state.subscribers {
                sub.close();
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RecordingPublisher — wraps MockPublisher and logs writes
// ---------------------------------------------------------------------------

struct RecordingPublisher {
    inner: MockPublisher,
    log: WriteLog,
    topic: String,
}

#[async_trait]
impl Publisher for RecordingPublisher {
    async fn write(&self, payload: Vec<u8>) -> Result<(), Error> {
        self.log
            .lock()
            .unwrap()
            .push((self.topic.clone(), payload.clone()));
        self.inner.write(payload).await
    }

    async fn write_ctx(&self, ctx: Context, payload: Vec<u8>) -> Result<(), Error> {
        if ctx.done() {
            return Err(Error::Timeout);
        }
        self.write(payload).await
    }

    async fn close(&self) -> Result<(), Error> {
        self.inner.close().await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn basic_pubsub() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let (rx, _sub) = p
            .new_subscriber("sensors/temp", QoS::default())
            .await
            .unwrap();
        let pub_ = p
            .new_publisher("sensors/temp", QoS::default())
            .await
            .unwrap();

        pub_.write(b"hello".to_vec()).await.unwrap();
        let sample = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sample.payload, b"hello");
        assert_eq!(sample.topic, "sensors/temp");
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_sample() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let (rx1, _) = p.new_subscriber("t/x", QoS::default()).await.unwrap();
        let (rx2, _) = p.new_subscriber("t/x", QoS::default()).await.unwrap();
        let pub_ = p.new_publisher("t/x", QoS::default()).await.unwrap();

        pub_.write(b"broadcast".to_vec()).await.unwrap();
        let s1 = tokio::time::timeout(Duration::from_secs(1), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        let s2 = tokio::time::timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(s1.payload, b"broadcast");
        assert_eq!(s2.payload, b"broadcast");
    }

    #[tokio::test]
    async fn transient_local_delivers_cache_to_late_joiner() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let pub_ = p
            .new_publisher("t/cached", crate::types::RELIABLE_QOS.clone())
            .await
            .unwrap();
        pub_.write(b"cached-value".to_vec()).await.unwrap();

        let (rx, _) = p
            .new_subscriber("t/cached", crate::types::RELIABLE_QOS.clone())
            .await
            .unwrap();
        let sample = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sample.payload, b"cached-value");
    }

    #[tokio::test]
    async fn domain_out_of_range() {
        assert!(matches!(
            MockParticipant::new(Domain(-1)),
            Err(Error::DomainOutOfRange)
        ));
        assert!(matches!(
            MockParticipant::new(Domain(233)),
            Err(Error::DomainOutOfRange)
        ));
    }

    #[tokio::test]
    async fn empty_topic_rejected() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        assert!(matches!(
            p.new_publisher("", QoS::default()).await,
            Err(Error::TopicEmpty)
        ));
        assert!(matches!(
            p.new_subscriber("", QoS::default()).await,
            Err(Error::TopicEmpty)
        ));
    }

    #[tokio::test]
    async fn write_after_close_returns_closed() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let pub_ = p.new_publisher("t", QoS::default()).await.unwrap();
        pub_.close().await.unwrap();
        assert!(matches!(
            pub_.write(b"x".to_vec()).await,
            Err(Error::Closed)
        ));
    }

    #[tokio::test]
    async fn participant_close_is_idempotent() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        p.close().await.unwrap();
        p.close().await.unwrap();
    }

    #[tokio::test]
    async fn new_publisher_after_close_returns_closed() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        p.close().await.unwrap();
        assert!(matches!(
            p.new_publisher("t", QoS::default()).await,
            Err(Error::Closed)
        ));
    }

    #[tokio::test]
    async fn try_recv_non_blocking() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let (rx, _) = p.new_subscriber("t", QoS::default()).await.unwrap();
        assert!(rx.try_recv().is_none());
        let pub_ = p.new_publisher("t", QoS::default()).await.unwrap();
        pub_.write(b"val".to_vec()).await.unwrap();
        assert_eq!(rx.try_recv().unwrap().payload, b"val");
    }

    #[tokio::test]
    async fn unsubscribe_stops_delivery() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let (rx, sub) = p.new_subscriber("t/u", QoS::default()).await.unwrap();
        sub.unsubscribe();
        let pub_ = p.new_publisher("t/u", QoS::default()).await.unwrap();
        pub_.write(b"after-unsub".to_vec()).await.unwrap();
        assert!(rx.try_recv().is_none());
    }

    #[tokio::test]
    async fn sequence_numbers_monotonic() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let (rx, _) = p.new_subscriber("t/seq", QoS::default()).await.unwrap();
        let pub_ = p.new_publisher("t/seq", QoS::default()).await.unwrap();
        for _ in 0..3 {
            pub_.write(b"x".to_vec()).await.unwrap();
        }
        let s1 = rx.try_recv().unwrap();
        let s2 = rx.try_recv().unwrap();
        let s3 = rx.try_recv().unwrap();
        assert!(s1.sequence_number < s2.sequence_number);
        assert!(s2.sequence_number < s3.sequence_number);
    }

    #[tokio::test]
    async fn written_payloads_log() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let pub_ = p.new_publisher("t/log", QoS::default()).await.unwrap();
        pub_.write(b"a".to_vec()).await.unwrap();
        pub_.write(b"b".to_vec()).await.unwrap();
        let log = p.written_payloads();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].1, b"a");
        assert_eq!(log[1].1, b"b");
        p.reset();
        assert!(p.written_payloads().is_empty());
    }

    #[tokio::test]
    async fn write_ctx_timeout() {
        let p = MockParticipant::new(Domain(0)).unwrap();
        let pub_ = p.new_publisher("t/ctx", QoS::default()).await.unwrap();
        let ctx = Context::with_timeout(std::time::Duration::from_nanos(1));
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(matches!(
            pub_.write_ctx(ctx, b"x".to_vec()).await,
            Err(Error::Timeout)
        ));
    }

    #[tokio::test]
    async fn domain_accessor() {
        let p = MockParticipant::new(Domain(42)).unwrap();
        assert_eq!(p.domain(), Domain(42));
    }
}
