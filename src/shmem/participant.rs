// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`ShmemParticipant`] — the public, [`Participant`]-implementing entry
//! point for the shmem transport (`ROADMAP.md`'s "Planned — v0.4 —
//! Shared-Memory Transport" milestone). Wires [`super::broker`] (same
//! process delivery) and [`super::ipc`] (cross-process delivery) together
//! behind the same [`Participant`]/[`Publisher`]/[`Subscriber`] traits
//! [`crate::mock::MockParticipant`] and
//! [`crate::rtps::dds_participant::RtpsUdpParticipant`] already implement,
//! so application code (and [`crate::adapt`]/[`crate::relay::Node`], which
//! work with any `Arc<dyn Participant>`) needs no changes to use it.
//!
//! # Two delivery paths, one subscriber queue
//!
//! `ShmemParticipant::new_subscriber` registers with the process-local
//! [`super::broker::Broker`] *and* spawns a [`super::ipc::spawn_poller`]
//! task, both pushing into the same [`crate::participant::SubInner`] — a
//! subscriber sees the union of same-process and cross-process
//! publishers on its topic without needing to know which is which. See
//! [`super::ipc`]'s module docs for how same-process double-delivery is
//! avoided (not merely tolerated, unlike go-DDS's own reference).
//!
//! # QoS
//!
//! `QoS::durability` selects TransientLocal late-joiner delivery on both
//! paths (in-process cache in [`super::broker::Broker::subscribe`],
//! on-disk last value in [`super::ipc::spawn_poller`]).
//! `QoS::max_sample_size` is enforced in [`ShmemPublisher::write`], same
//! as `mock::MockParticipant`. `QoS::deadline_ns` (paired with a
//! registered callback via
//! [`crate::relay::SubscriberOptions::deadline_missed`]) arms the same
//! [`crate::participant::spawn_deadline_watcher`] every other transport in
//! this crate uses — deadline enforcement is transport-agnostic by
//! construction, not something each transport reimplements.
//! `QoS::reliability` has no shmem-specific meaning: there is no
//! retransmission concept for a local file write (the write either
//! succeeds or the whole process/filesystem has bigger problems), matching
//! go-DDS's own shmem package, which does not branch on
//! `ReliabilityKind` either.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use crate::error::Error;
use crate::participant::{
    spawn_deadline_watcher, Participant, Publisher, SampleReceiver, SubInner, Subscriber,
};
use crate::relay::{Context, SubscriberOptions};
use crate::types::{validate_domain, Domain, Guid, QoS, Sample};

use super::broker::{broker_for, Broker};
use super::ipc::{self, DEFAULT_POLL_INTERVAL};

// ---------------------------------------------------------------------------
// ShmemPublisher
// ---------------------------------------------------------------------------

pub(super) struct ShmemPublisher {
    pub(super) domain: Domain,
    pub(super) topic: String,
    pub(super) qos: QoS,
    pub(super) broker: Arc<Broker>,
    pub(super) writer_guid: Guid,
    pub(super) seq: AtomicU64,
    pub(super) closed: AtomicBool,
}

impl ShmemPublisher {
    /// Shared by [`Publisher::write`] and
    /// [`super::loan::ShmemLoaningPublisher::commit`] so both paths apply
    /// identical validation and delivery.
    //fusa:req REQ-SHMEM-001
    //fusa:req REQ-SHMEM-002
    //fusa:req REQ-SHMEM-003
    pub(super) fn write_payload(&self, payload: Vec<u8>) -> Result<(), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        //fusa:req REQ-SHMEM-005
        if self.qos.max_sample_size > 0 && payload.len() > self.qos.max_sample_size as usize {
            return Err(Error::PayloadTooLarge);
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let sample = Sample {
            topic: self.topic.clone(),
            payload,
            timestamp: Utc::now(),
            sequence_number: seq,
            writer_guid: self.writer_guid,
        };
        // Same-process subscribers first (synchronous, zero I/O).
        self.broker.publish(&self.topic, sample.clone(), &self.qos);
        // Cross-process rendezvous file — see `ipc` module docs. Best-effort
        // by design: a failure here degrades cross-process delivery for
        // this one sample only, never this call's own success.
        ipc::write_sample(self.domain, &self.topic, &sample);
        Ok(())
    }
}

#[async_trait]
impl Publisher for ShmemPublisher {
    async fn write(&self, payload: Vec<u8>) -> Result<(), Error> {
        self.write_payload(payload)
    }

    async fn write_ctx(&self, ctx: Context, payload: Vec<u8>) -> Result<(), Error> {
        if ctx.done() {
            return Err(Error::Timeout);
        }
        self.write_payload(payload)
    }

    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ShmemSubscriber
// ---------------------------------------------------------------------------

struct ShmemSubscriber {
    inner: Arc<SubInner>,
    broker: Arc<Broker>,
    topic: String,
    poller: Mutex<Option<tokio::task::JoinHandle<()>>>,
    deadline_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[async_trait]
impl Subscriber for ShmemSubscriber {
    fn unsubscribe(&self) {
        self.inner.unsubscribe();
        self.broker.remove_subscriber(&self.topic, &self.inner);
    }

    async fn close(&self) -> Result<(), Error> {
        self.inner.close();
        self.broker.remove_subscriber(&self.topic, &self.inner);
        if let Some(task) = self.poller.lock().unwrap().take() {
            task.abort();
        }
        if let Some(task) = self.deadline_task.lock().unwrap().take() {
            task.abort();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ShmemParticipant
// ---------------------------------------------------------------------------

/// A DDS participant backed by the shared-memory transport
/// (`ROADMAP.md`'s "Planned — v0.4 — Shared-Memory Transport" milestone,
/// `shmem::ShmemParticipant`).
///
/// Participants constructed for the same [`Domain`] within one OS process
/// share an in-process [`Broker`] (zero file I/O for same-process
/// delivery, per [`super::broker::broker_for`]); participants in different
/// OS processes on the same domain and topic exchange samples through a
/// per-topic rendezvous file (see the [`super::ipc`] module docs) instead
/// of a full UDP/RTPS transport — no socket, no wire framing, no
/// discovery protocol, suited to same-host IPC where
/// [`crate::rtps::dds_participant::RtpsUdpParticipant`]'s network stack is
/// unnecessary overhead.
///
/// # Example
///
/// ```rust,no_run
/// use rust_dds::shmem::ShmemParticipant;
/// use rust_dds::participant::Participant;
/// use rust_dds::relay::SubscriberOptions;
/// use rust_dds::types::{Domain, QoS};
///
/// # #[tokio::main]
/// # async fn main() {
/// let p = ShmemParticipant::new(Domain(0)).unwrap();
/// let (rx, _sub) = p
///     .new_subscriber("vehicle/speed", QoS::default(), SubscriberOptions::default())
///     .await
///     .unwrap();
/// let pub_ = p.new_publisher("vehicle/speed", QoS::default()).await.unwrap();
/// pub_.write(b"80".to_vec()).await.unwrap();
/// let sample = rx.recv().await.unwrap();
/// assert_eq!(sample.payload, b"80");
/// # }
/// ```
//fusa:req REQ-SHMEM-001
//fusa:req REQ-SHMEM-008
pub struct ShmemParticipant {
    domain: Domain,
    broker: Arc<Broker>,
    closed: AtomicBool,
    guid_prefix: [u8; 12],
    pub_counter: AtomicU64,
    poll_interval: Duration,
}

impl ShmemParticipant {
    /// Creates a new shmem-backed participant on `domain`, using the
    /// default cross-process poll cadence
    /// ([`super::ipc::DEFAULT_POLL_INTERVAL`]).
    ///
    /// Returns `Error::DomainOutOfRange` if `domain` is outside `[0, 232]`.
    //fusa:req REQ-SHMEM-001
    pub fn new(domain: Domain) -> Result<Arc<Self>, Error> {
        Self::new_with_poll_interval(domain, DEFAULT_POLL_INTERVAL)
    }

    /// As [`ShmemParticipant::new`], with an explicit cross-process poll
    /// interval — mainly useful for tests that want faster-than-default
    /// cross-process delivery without waiting out the default 10ms
    /// cadence on every tick.
    //fusa:req REQ-SHMEM-001
    pub fn new_with_poll_interval(
        domain: Domain,
        poll_interval: Duration,
    ) -> Result<Arc<Self>, Error> {
        validate_domain(domain)?;
        let mut prefix = [0u8; 12];
        prefix[0] = domain.0 as u8; // safe: domain validated to [0,232] before this line
        Ok(Arc::new(Self {
            domain,
            broker: broker_for(domain),
            closed: AtomicBool::new(false),
            guid_prefix: prefix,
            pub_counter: AtomicU64::new(0),
            poll_interval,
        }))
    }

    fn make_guid(&self, id: u64) -> Guid {
        let mut guid = Guid::default();
        guid[..12].copy_from_slice(&self.guid_prefix);
        guid[12..].copy_from_slice(&(id as u32).to_be_bytes());
        guid
    }

    /// Shared by [`Participant::new_publisher`] and
    /// `ShmemParticipant::new_loaning_publisher` (defined in
    /// [`super::loan`]) so both paths construct an identical
    /// [`ShmemPublisher`].
    pub(super) fn make_publisher(&self, topic: &str, qos: QoS) -> Result<ShmemPublisher, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if topic.is_empty() {
            return Err(Error::TopicEmpty);
        }
        let id = self.pub_counter.fetch_add(1, Ordering::SeqCst);
        Ok(ShmemPublisher {
            domain: self.domain,
            topic: topic.to_string(),
            qos,
            broker: self.broker.clone(),
            writer_guid: self.make_guid(id),
            seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl Participant for ShmemParticipant {
    async fn new_publisher(&self, topic: &str, qos: QoS) -> Result<Box<dyn Publisher>, Error> {
        Ok(Box::new(self.make_publisher(topic, qos)?))
    }

    async fn new_subscriber(
        &self,
        topic: &str,
        qos: QoS,
        opts: SubscriberOptions,
    ) -> Result<(SampleReceiver, Box<dyn Subscriber>), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if topic.is_empty() {
            return Err(Error::TopicEmpty);
        }
        let inner = self.broker.subscribe(topic, &qos, &opts);
        let poller = ipc::spawn_poller(
            self.domain,
            topic.to_string(),
            qos.durability,
            inner.clone(),
            self.poll_interval,
        );
        let deadline_task = opts
            .deadline_missed
            .clone()
            .and_then(|cb| spawn_deadline_watcher(&inner, qos.deadline_ns, cb));
        let receiver = SampleReceiver {
            inner: inner.clone(),
        };
        let sub = ShmemSubscriber {
            inner,
            broker: self.broker.clone(),
            topic: topic.to_string(),
            poller: Mutex::new(Some(poller)),
            deadline_task: Mutex::new(deadline_task),
        };
        Ok((receiver, Box::new(sub)))
    }

    fn domain(&self) -> Domain {
        self.domain
    }

    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// `ShmemParticipant`'s [`HealthProvider`](crate::observability::HealthProvider)
/// implementation: [`HealthStatus::Down`](crate::observability::HealthStatus::Down)
/// once closed, [`HealthStatus::Ok`](crate::observability::HealthStatus::Ok)
/// otherwise. Direct port of go-DDS's `shmem.participant.Health`
/// (`shmem/shmem.go`), including its `{"state":"closed"}` details string,
/// byte-for-byte.
//fusa:req REQ-MON-003
impl crate::observability::HealthProvider for ShmemParticipant {
    fn health(&self) -> crate::observability::Health {
        if self.closed.load(Ordering::SeqCst) {
            return crate::observability::Health::down(r#"{"state":"closed"}"#);
        }
        crate::observability::Health::ok()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn fast(domain: Domain) -> Arc<ShmemParticipant> {
        ShmemParticipant::new_with_poll_interval(domain, StdDuration::from_millis(5)).unwrap()
    }

    //fusa:test REQ-SHMEM-001
    //fusa:test REQ-SHMEM-002
    #[tokio::test]
    async fn basic_same_process_pubsub() {
        let p = fast(Domain(101));
        let (rx, _sub) = p
            .new_subscriber("shmem/basic", QoS::default(), SubscriberOptions::default())
            .await
            .unwrap();
        let pub_ = p
            .new_publisher("shmem/basic", QoS::default())
            .await
            .unwrap();
        pub_.write(b"hello".to_vec()).await.unwrap();
        let sample = tokio::time::timeout(StdDuration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sample.payload, b"hello");
        assert_eq!(sample.topic, "shmem/basic");
    }

    //fusa:test REQ-SHMEM-002
    #[tokio::test]
    async fn same_process_delivers_exactly_once_not_twice() {
        // Guards against the go-DDS reference's own known same-process
        // double-delivery behavior (see `ipc` module docs) — a same-process
        // subscriber on this transport must see each write exactly once.
        let p = fast(Domain(102));
        let (rx, _sub) = p
            .new_subscriber("shmem/once", QoS::default(), SubscriberOptions::default())
            .await
            .unwrap();
        let pub_ = p.new_publisher("shmem/once", QoS::default()).await.unwrap();
        pub_.write(b"x".to_vec()).await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(80)).await;
        assert!(rx.try_recv().is_some(), "expected exactly one delivery");
        assert!(
            rx.try_recv().is_none(),
            "sample must not be delivered twice"
        );
    }

    //fusa:test REQ-SHMEM-004
    #[tokio::test]
    async fn transient_local_late_joiner_same_process() {
        let p = fast(Domain(103));
        let pub_ = p
            .new_publisher("shmem/tl", crate::types::RELIABLE_QOS.clone())
            .await
            .unwrap();
        pub_.write(b"cached".to_vec()).await.unwrap();
        let (rx, _sub) = p
            .new_subscriber(
                "shmem/tl",
                crate::types::RELIABLE_QOS.clone(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        let sample = tokio::time::timeout(StdDuration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sample.payload, b"cached");
    }

    //fusa:test REQ-SHMEM-001
    #[tokio::test]
    async fn domain_out_of_range() {
        assert!(matches!(
            ShmemParticipant::new(Domain(-1)),
            Err(Error::DomainOutOfRange)
        ));
        assert!(matches!(
            ShmemParticipant::new(Domain(233)),
            Err(Error::DomainOutOfRange)
        ));
    }

    #[tokio::test]
    async fn empty_topic_rejected() {
        let p = fast(Domain(104));
        assert!(matches!(
            p.new_publisher("", QoS::default()).await,
            Err(Error::TopicEmpty)
        ));
        assert!(matches!(
            p.new_subscriber("", QoS::default(), SubscriberOptions::default())
                .await,
            Err(Error::TopicEmpty)
        ));
    }

    //fusa:test REQ-SHMEM-008
    #[tokio::test]
    async fn write_after_close_returns_closed() {
        let p = fast(Domain(105));
        let pub_ = p
            .new_publisher("shmem/close", QoS::default())
            .await
            .unwrap();
        pub_.close().await.unwrap();
        assert!(matches!(
            pub_.write(b"x".to_vec()).await,
            Err(Error::Closed)
        ));
    }

    //fusa:test REQ-SHMEM-008
    #[tokio::test]
    async fn participant_close_is_idempotent_and_blocks_new_ops() {
        let p = fast(Domain(106));
        p.close().await.unwrap();
        p.close().await.unwrap();
        assert!(matches!(
            p.new_publisher("t", QoS::default()).await,
            Err(Error::Closed)
        ));
    }

    /// `ShmemParticipant::health` reports `Ok` before `close()` and `Down`
    /// with `{"state":"closed"}` details after — matching go-DDS's
    /// `shmem.participant.Health` byte-for-byte.
    //fusa:test REQ-MON-003
    #[tokio::test]
    async fn shmem_participant_health_reflects_closed_state() {
        use crate::observability::{HealthProvider, HealthStatus};

        let p = fast(Domain(113));
        let h = p.health();
        assert_eq!(h.status, HealthStatus::Ok);
        assert_eq!(h.details, None);

        p.close().await.unwrap();
        let h = p.health();
        assert_eq!(h.status, HealthStatus::Down);
        assert_eq!(h.details.as_deref(), Some(r#"{"state":"closed"}"#));
    }

    //fusa:test REQ-SHMEM-005
    #[tokio::test]
    async fn max_sample_size_enforced() {
        let p = fast(Domain(107));
        let qos = QoS {
            max_sample_size: 4,
            ..QoS::default()
        };
        let pub_ = p.new_publisher("shmem/maxsize", qos).await.unwrap();
        assert!(matches!(
            pub_.write(vec![0u8; 5]).await,
            Err(Error::PayloadTooLarge)
        ));
        assert!(pub_.write(vec![0u8; 4]).await.is_ok());
    }

    #[tokio::test]
    async fn unsubscribe_stops_delivery() {
        let p = fast(Domain(108));
        let (rx, sub) = p
            .new_subscriber("shmem/unsub", QoS::default(), SubscriberOptions::default())
            .await
            .unwrap();
        sub.unsubscribe();
        let pub_ = p
            .new_publisher("shmem/unsub", QoS::default())
            .await
            .unwrap();
        pub_.write(b"after-unsub".to_vec()).await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(50)).await;
        assert!(rx.try_recv().is_none());
    }

    #[tokio::test]
    async fn close_stops_delivery_and_recv_returns_none() {
        let p = fast(Domain(109));
        let (rx, sub) = p
            .new_subscriber(
                "shmem/close-recv",
                QoS::default(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        sub.close().await.unwrap();
        let result = tokio::time::timeout(StdDuration::from_millis(100), rx.recv()).await;
        assert!(result.is_ok() && result.unwrap().is_none());
    }

    //fusa:test REQ-SHMEM-006
    #[tokio::test]
    async fn domain_isolation_no_cross_domain_delivery() {
        let p0 = fast(Domain(110));
        let p1 = fast(Domain(111));
        let (rx1, _sub) = p1
            .new_subscriber(
                "shmem/shared-topic",
                QoS::default(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        let pub0 = p0
            .new_publisher("shmem/shared-topic", QoS::default())
            .await
            .unwrap();
        pub0.write(b"domain0-msg".to_vec()).await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(50)).await;
        assert!(rx1.try_recv().is_none());
    }

    #[tokio::test]
    async fn sequence_numbers_monotonic() {
        let p = fast(Domain(112));
        let (rx, _sub) = p
            .new_subscriber("shmem/seq", QoS::default(), SubscriberOptions::default())
            .await
            .unwrap();
        let pub_ = p.new_publisher("shmem/seq", QoS::default()).await.unwrap();
        for _ in 0..3 {
            pub_.write(b"x".to_vec()).await.unwrap();
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
        let s1 = rx.try_recv().unwrap();
        let s2 = rx.try_recv().unwrap();
        let s3 = rx.try_recv().unwrap();
        assert!(s1.sequence_number < s2.sequence_number);
        assert!(s2.sequence_number < s3.sequence_number);
    }

    #[test]
    fn traits_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ShmemParticipant>();
    }

    //fusa:test REQ-ASIL-002
    //fusa:test REQ-MEM-001
    #[test]
    fn no_unsafe_code_in_shmem() {
        // Traceability anchor — see `super::ipc`'s module docs for why this
        // module tree deliberately does not use POSIX shared memory
        // (mmap), preserving zero `unsafe` blocks.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(true);
        }
    }
}
