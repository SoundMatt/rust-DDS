// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Core DDS interface traits: Participant, Publisher, Subscriber.
//!
//! All implementations satisfy these traits. Application code programs
//! against these traits; swap the backing transport at the call site.
//!
//! Per RELAY spec §8.2 and §18.3 (Rust async-primary model).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::sync::Notify;

use crate::error::Error;
use crate::relay::Context;
use crate::types::{Domain, QoS, Sample};

// ---------------------------------------------------------------------------
// SampleReceiver
// ---------------------------------------------------------------------------

/// Shared inner state for a subscriber sample queue.
///
/// Uses `std::sync::Mutex` so the queue can be locked briefly from both
/// sync and async contexts without holding across await points.
//fusa:req REQ-CONC-001
//fusa:req REQ-CONC-002
//fusa:req REQ-IEC-006
//fusa:req REQ-MEM-002
//fusa:req REQ-ASIL-007
pub(crate) struct SubInner {
    pub(crate) queue: Mutex<VecDeque<Sample>>,
    pub(crate) capacity: usize,
    pub(crate) policy: crate::relay::BackPressurePolicy,
    pub(crate) notify: Notify,
    pub(crate) closed: AtomicBool,
    pub(crate) unsubscribed: AtomicBool,
}

impl SubInner {
    //fusa:req REQ-RT-005
    //fusa:req REQ-MEM-004
    //fusa:req REQ-IEC-001
    pub(crate) fn new(capacity: usize, policy: crate::relay::BackPressurePolicy) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity.min(256))),
            capacity,
            policy,
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            unsubscribed: AtomicBool::new(false),
        }
    }

    /// Push a sample into the queue, applying the back-pressure policy.
    ///
    /// Returns `true` if accepted, `false` if dropped.
    //fusa:req REQ-IEC-005
    //fusa:req REQ-RT-001
    //fusa:req REQ-ASIL-008
    pub(crate) fn push(&self, sample: Sample) -> bool {
        if self.unsubscribed.load(Ordering::SeqCst) || self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let mut q = self.queue.lock().unwrap();
        match self.policy {
            crate::relay::BackPressurePolicy::DropNewest => {
                if q.len() >= self.capacity {
                    return false;
                }
                q.push_back(sample);
            }
            crate::relay::BackPressurePolicy::DropOldest => {
                if q.len() >= self.capacity {
                    q.pop_front();
                }
                q.push_back(sample);
            }
            //fusa:req REQ-MEM-003
            crate::relay::BackPressurePolicy::Block => {
                // TODO REQ-MEM-003: replace with true async backpressure in a future milestone.
                // For now, Block appends unconditionally (mock-only transport).
                q.push_back(sample);
            }
        }
        self.notify.notify_one();
        true
    }

    pub(crate) fn pop(&self) -> Option<Sample> {
        self.queue.lock().unwrap().pop_front()
    }

    //fusa:req REQ-MEM-004
    //fusa:req REQ-ASIL-007
    //fusa:req REQ-IEC-010
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(crate) fn unsubscribe(&self) {
        self.unsubscribed.store(true, Ordering::SeqCst);
        // §6.4: after unsubscribe the channel MUST be closed so recv() can drain
        // and return None rather than blocking indefinitely.
        self.close();
    }
}

/// The receiving end of a DDS subscriber channel.
///
/// Created by `Participant::new_subscriber`. Await `recv()` in a loop to
/// consume samples. `try_recv()` is non-blocking.
pub struct SampleReceiver {
    pub(crate) inner: std::sync::Arc<SubInner>,
}

impl SampleReceiver {
    /// Wait for the next sample. Returns `None` when the subscriber is closed
    /// and the queue is fully drained.
    //fusa:req REQ-ASIL-010
    //fusa:req REQ-MEM-005
    pub async fn recv(&self) -> Option<Sample> {
        loop {
            if let Some(s) = self.inner.pop() {
                return Some(s);
            }
            if self.inner.closed.load(Ordering::SeqCst) {
                // One final drain attempt after observing closed; any samples
                // pushed before close() was called are returned before None.
                return self.inner.pop();
            }
            // Async wait — no busy-spin (REQ-ASIL-010). Notify::notified() is
            // registered here; any push() between the pop() above and this await
            // will re-fire notify_one(), preventing a missed wakeup.
            self.inner.notify.notified().await;
        }
    }

    /// Non-blocking read. Returns `None` if no sample is queued.
    //fusa:req REQ-RT-002
    pub fn try_recv(&self) -> Option<Sample> {
        self.inner.pop()
    }
}

impl std::fmt::Debug for SampleReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SampleReceiver")
            .field("closed", &self.inner.closed.load(Ordering::Relaxed))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Subscriber trait
// ---------------------------------------------------------------------------

/// DDS subscriber — receives samples from a single topic.
///
/// Acquire the receiving channel via `Participant::new_subscriber`, which
/// returns both the `Box<dyn Subscriber>` lifecycle handle and a `SampleReceiver`.
//fusa:req REQ-SUB-001
//fusa:req REQ-SUB-002
//fusa:req REQ-SUB-003
//fusa:req REQ-SUB-004
//fusa:req REQ-SUB-005
#[async_trait]
pub trait Subscriber: Send + Sync {
    /// Remove this subscriber from the topic without closing the channel.
    ///
    /// No more samples will be delivered after this call, but samples already
    /// in the channel can still be drained via `SampleReceiver::try_recv`.
    fn unsubscribe(&self);

    /// Close the subscriber and release all resources.
    ///
    /// Idempotent: calling close more than once is safe.
    async fn close(&self) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------
// Publisher trait
// ---------------------------------------------------------------------------

/// DDS publisher — writes samples to a single topic.
//fusa:req REQ-PUB-001
//fusa:req REQ-PUB-002
//fusa:req REQ-PUB-003
//fusa:req REQ-PUB-004
#[async_trait]
pub trait Publisher: Send + Sync {
    /// Write a payload to the topic. Returns immediately after queuing delivery.
    async fn write(&self, payload: Vec<u8>) -> Result<(), Error>;

    /// Write with context-cancellation support.
    ///
    /// Returns `Error::Timeout` if `ctx` is done before the write completes.
    async fn write_ctx(&self, ctx: Context, payload: Vec<u8>) -> Result<(), Error>;

    /// Close the publisher and release all resources. Idempotent.
    async fn close(&self) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------
// Participant trait
// ---------------------------------------------------------------------------

/// Root factory for DDS publishers and subscribers.
///
/// Create one participant per domain. Implementations are swappable; see
/// `mock::MockParticipant` for an in-process implementation suitable for
/// development and testing.
//fusa:req REQ-PART-001
//fusa:req REQ-PART-002
//fusa:req REQ-PART-003
//fusa:req REQ-PART-004
//fusa:req REQ-PART-005
//fusa:req REQ-PART-006
//fusa:req REQ-CONC-001
//fusa:req REQ-IEC-010
//fusa:req REQ-RT-003
#[async_trait]
pub trait Participant: Send + Sync {
    /// Create a publisher for the given topic and QoS.
    ///
    /// Returns `Error::TopicEmpty` if `topic` is empty.
    async fn new_publisher(&self, topic: &str, qos: QoS) -> Result<Box<dyn Publisher>, Error>;

    /// Create a subscriber for the given topic and QoS.
    ///
    /// Returns `(SampleReceiver, Box<dyn Subscriber>)`:
    /// - `SampleReceiver` — used to receive samples.
    /// - `Box<dyn Subscriber>` — lifecycle handle for unsubscribe/close.
    ///
    /// Returns `Error::TopicEmpty` if `topic` is empty.
    async fn new_subscriber(
        &self,
        topic: &str,
        qos: QoS,
    ) -> Result<(SampleReceiver, Box<dyn Subscriber>), Error>;

    /// Return the domain this participant joined.
    fn domain(&self) -> Domain;

    /// Close the participant and all associated publishers and subscribers.
    ///
    /// Idempotent. After close, all writes and subscribes return `Error::Closed`.
    async fn close(&self) -> Result<(), Error>;
}
