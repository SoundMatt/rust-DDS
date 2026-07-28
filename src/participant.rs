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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::error::Error;
use crate::relay::{Context, DeadlineCallback, SubscriberOptions};
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
//fusa:req REQ-CONC-003 — single lock per SubInner; Broker lock is never held while SubInner lock is held
//fusa:req REQ-CONC-004 — each SubInner has an independent queue; slow subscribers cannot block others
//fusa:req REQ-IEC-006
//fusa:req REQ-IEC-012 — queue, capacity, policy fields are pub(crate); not accessible outside crate
//fusa:req REQ-IEC-014 — unsubscribed/closed flags checked at push() entry before any state mutation
//fusa:req REQ-MEM-002
//fusa:req REQ-ASIL-007
//fusa:req REQ-INT-003 — closed flag is set with SeqCst store; never reset after being set true
pub(crate) struct SubInner {
    pub(crate) queue: Mutex<VecDeque<Sample>>,
    pub(crate) capacity: usize,
    pub(crate) policy: crate::relay::BackPressurePolicy,
    pub(crate) notify: Notify,
    pub(crate) closed: AtomicBool,
    pub(crate) unsubscribed: AtomicBool,
    /// Notified on every `push()` and on `close()` — consumed by an optional
    /// Deadline QoS watcher task (see [`spawn_deadline_watcher`]) to detect
    /// "a sample arrived" (re-arm the deadline window) or "the subscriber
    /// closed" (stop watching) without polling.
    ///
    /// Deliberately a *separate* `Notify` from `notify` above: `notify` is
    /// awaited by `SampleReceiver::recv()`, and `Notify::notify_one` wakes
    /// at most one registered waiter — sharing one `Notify` between `recv()`
    /// and a deadline watcher would race the two consumers and could starve
    /// either one of a wakeup.
    pub(crate) deadline_notify: Notify,
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
            deadline_notify: Notify::new(),
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
        // Deadline QoS (§15.2): a sample just arrived on this reader, so any
        // running deadline watcher must re-arm its window from now rather
        // than fire on the window that started before this sample landed.
        self.deadline_notify.notify_one();
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
        // Wake any running deadline watcher immediately so it observes
        // `closed` and stops on its next loop iteration, rather than
        // lingering up to one more deadline period before checking.
        self.deadline_notify.notify_waiters();
    }

    //fusa:req REQ-HAZ-005
    pub(crate) fn unsubscribe(&self) {
        self.unsubscribed.store(true, Ordering::SeqCst);
        // §6.4: after unsubscribe the channel MUST be closed so recv() can drain
        // and return None rather than blocking indefinitely.
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Deadline QoS enforcement
// ---------------------------------------------------------------------------

/// Spawn a Deadline QoS watcher task for `inner`, per RELAY spec §15.2 and
/// DDS `DEADLINE` QoS semantics: fires `callback` whenever `deadline_ns`
/// nanoseconds elapse without a new sample reaching `inner` (via
/// [`SubInner::push`]).
///
/// Returns `None` when `deadline_ns == 0` (Deadline QoS disabled) — no task
/// is spawned and there is nothing to stop later. Otherwise spawns one
/// `tokio` task, independently stoppable via the returned [`JoinHandle`],
/// following the same per-reader background-task idiom already used
/// elsewhere in this crate (the SPDP announce loop, the reliable-writer
/// HEARTBEAT loop). The task also exits on its own — without needing to be
/// aborted — once `inner` observes `closed` or `unsubscribed`, both of which
/// wake it immediately via `deadline_notify` (see [`SubInner::close`]);
/// callers still hold the `JoinHandle` and abort it for symmetry with this
/// crate's other lifecycle-tied tasks (e.g. `RtpsPublisher::heartbeat_task`)
/// and to guarantee prompt termination rather than relying solely on the
/// task's own next wakeup.
///
/// Timer semantics deliberately mirror go-DDS's reference implementation
/// (`time.AfterFunc` + `Timer::Reset` in `mock.go`/`rtps/participant.go`):
/// each sample delivery restarts a fresh `deadline_ns` window; if the window
/// elapses uninterrupted, `callback` fires and a new window starts
/// immediately (the callback keeps firing once per elapsed interval for as
/// long as no sample arrives), rather than firing only once ever.
///
/// Callers are responsible for arming this only when a callback is actually
/// registered ([`SubscriberOptions::deadline_missed`] is `Some`) — a
/// non-zero `deadline_ns` with no callback is a documented no-op, matching
/// go-DDS.
//fusa:req REQ-QOS-008
//fusa:req REQ-QOS-009
pub(crate) fn spawn_deadline_watcher(
    inner: &Arc<SubInner>,
    deadline_ns: u64,
    callback: DeadlineCallback,
) -> Option<JoinHandle<()>> {
    if deadline_ns == 0 {
        return None;
    }
    let period = Duration::from_nanos(deadline_ns);
    let inner = Arc::clone(inner);
    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                // The full `period` elapsed with no `push()` in between —
                // Deadline missed.
                _ = tokio::time::sleep(period) => {}
                // A sample was delivered (or the subscriber closed) before
                // `period` elapsed — restart the window from here rather
                // than firing.
                _ = inner.deadline_notify.notified() => {
                    continue;
                }
            }
            if inner.closed.load(Ordering::SeqCst) || inner.unsubscribed.load(Ordering::SeqCst) {
                break;
            }
            callback.fire();
        }
    }))
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
// LoaningPublisher trait
// ---------------------------------------------------------------------------

/// Extends [`Publisher`] with pool-backed, allocation-free loaned-sample
/// writes — `ROADMAP.md`'s "Planned — v0.4 — Shared-Memory Transport"
/// milestone, second checklist item. Declared here (rather than inside
/// `shmem`) so any future transport can implement it too, mirroring
/// go-DDS's own placement of `dds.LoaningPublisher` next to `dds.Publisher`
/// in its top-level `dds.go` rather than inside its `shmem` package;
/// [`crate::shmem::ShmemLoaningPublisher`] is this trait's first
/// implementation (see that module's docs) — go-DDS's `loan.go` zero-copy
/// loan API, which Tier 1 sub-phase 9 (`rust-DDS#30`) deliberately
/// deferred to the shared-memory transport milestone "since it's not
/// meaningful without a zero-copy transport underneath it".
///
/// Use `loan` to obtain a pre-allocated buffer from the publisher's
/// internal pool, write payload data into it, then call `commit` to
/// publish it and return the buffer to the pool. `commit` calls the
/// underlying [`Publisher::write`] internally; the buffer must not be used
/// after `commit` returns.
//fusa:req REQ-LOAN-001
#[async_trait]
pub trait LoaningPublisher: Publisher {
    /// Returns a buffer with at least `size` bytes of capacity (and
    /// `size` as its length, ready to write into directly), backed by
    /// this publisher's internal pool. Returns `Error::LoanBuffer` if
    /// `size` exceeds the pool's configured capacity, `Error::Closed` if
    /// this publisher is closed.
    //fusa:req REQ-LOAN-002
    fn loan(&self, size: usize) -> Result<Vec<u8>, Error>;

    /// Publishes `buf` (a buffer previously returned by `loan` on this
    /// same publisher) and returns it to the pool for reuse. `buf` must
    /// not be used after this call returns.
    //fusa:req REQ-LOAN-003
    async fn commit(&self, buf: Vec<u8>) -> Result<(), Error>;
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

    /// Create a subscriber for the given topic, QoS, and channel options.
    ///
    /// Per RELAY spec §8.2, `qos` carries the DDS endpoint parameters
    /// (reliability, durability, deadline, ...); `opts` carries channel-level
    /// configuration (depth, back-pressure — §14) that is orthogonal to QoS.
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
        opts: SubscriberOptions,
    ) -> Result<(SampleReceiver, Box<dyn Subscriber>), Error>;

    /// Return the domain this participant joined.
    fn domain(&self) -> Domain;

    /// Close the participant and all associated publishers and subscribers.
    ///
    /// Idempotent. After close, all writes and subscribes return `Error::Closed`.
    async fn close(&self) -> Result<(), Error>;
}
