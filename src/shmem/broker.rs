// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Process-local routing table shared by every [`super::participant::ShmemParticipant`]
//! on the same domain within one OS process — the same-process half of the
//! shmem transport (see the `shmem` module docs for the cross-process half,
//! [`super::ipc`]).
//!
//! Direct structural port of go-DDS's `shmem.go` "broker" section
//! (`shmBroker`/`shmSub`/`brokerFor`), itself a near-twin of
//! [`crate::mock`]'s own `Broker`/`TopicState`. One deliberate
//! simplification versus [`crate::mock`]'s broker: this cache holds only
//! the *last* sample per topic regardless of `QoS::history_depth`, matching
//! go-DDS's `shmBroker.lastSample map[string]*dds.Sample` (a single map
//! entry, not a ring buffer) — go-DDS's own shmem broker does not honour
//! `history_depth` either. `mock::MockParticipant`'s deeper `history_depth`
//! ring buffer is *not* carried over here; if a future milestone needs
//! shmem to match that, it is a small, separable follow-up.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::participant::SubInner;
use crate::relay::SubscriberOptions;
use crate::types::{Domain, DurabilityKind, QoS, Sample};

/// Per-topic broker state: this process's subscribers plus, for
/// TransientLocal topics, the last published sample.
struct TopicState {
    subscribers: Vec<Arc<SubInner>>,
    last_sample: Option<Sample>,
}

impl TopicState {
    fn new() -> Self {
        Self {
            subscribers: Vec::new(),
            last_sample: None,
        }
    }
}

/// Process-local, in-memory broker for one domain. Reached only via
/// [`broker_for`] — every [`super::participant::ShmemParticipant`] created
/// for the same [`Domain`] in this process shares one `Broker`, matching
/// go-DDS's `sharedBrokers` map (same-process delivery optimisation,
/// zero file I/O for the in-process path).
//fusa:req REQ-SHMEM-002
//fusa:req REQ-SHMEM-006
pub(super) struct Broker {
    topics: Mutex<HashMap<String, TopicState>>,
}

impl Broker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            topics: Mutex::new(HashMap::new()),
        })
    }

    /// Deliver `sample` to every current process-local subscriber on
    /// `topic`, and — for `DurabilityKind::TransientLocal` — cache it as
    /// this topic's last value for future in-process late joiners.
    //fusa:req REQ-SHMEM-002
    //fusa:req REQ-SHMEM-004
    //fusa:req REQ-SHMEM-007
    pub(super) fn publish(&self, topic: &str, sample: Sample, qos: &QoS) {
        let mut topics = self.topics.lock().unwrap();
        let state = topics
            .entry(topic.to_string())
            .or_insert_with(TopicState::new);
        if qos.durability == DurabilityKind::TransientLocal {
            state.last_sample = Some(sample.clone());
        }
        state
            .subscribers
            .retain(|s| !s.closed.load(std::sync::atomic::Ordering::SeqCst));
        for sub in &state.subscribers {
            sub.push(sample.clone());
        }
    }

    /// Register a new process-local subscriber for `topic`, delivering the
    /// cached last value first when `qos.durability` is `TransientLocal`
    /// (a locally-published one — this is the in-process half of
    /// TransientLocal late-joiner delivery; [`super::ipc`] separately
    /// covers the cross-process half).
    //fusa:req REQ-SHMEM-002
    //fusa:req REQ-SHMEM-004
    pub(super) fn subscribe(
        &self,
        topic: &str,
        qos: &QoS,
        opts: &SubscriberOptions,
    ) -> Arc<SubInner> {
        let depth = opts.chan_depth(64);
        let inner = Arc::new(SubInner::new(depth, opts.back_pressure));

        let mut topics = self.topics.lock().unwrap();
        let state = topics
            .entry(topic.to_string())
            .or_insert_with(TopicState::new);
        if qos.durability == DurabilityKind::TransientLocal {
            if let Some(last) = &state.last_sample {
                inner.push(last.clone());
            }
        }
        state.subscribers.push(inner.clone());
        inner
    }

    /// Remove `inner` from every topic's subscriber list it was registered
    /// under. Cheap linear scan — subscriber counts per process are small;
    /// matches `mock::MockParticipant`'s own unsubscribe path in spirit
    /// (there, removal happens implicitly via the `closed` filter in
    /// `publish`; here we additionally do it eagerly so a long-lived
    /// broker does not accumulate closed entries across many short-lived
    /// subscribers).
    pub(super) fn remove_subscriber(&self, topic: &str, inner: &Arc<SubInner>) {
        let mut topics = self.topics.lock().unwrap();
        if let Some(state) = topics.get_mut(topic) {
            state.subscribers.retain(|s| !Arc::ptr_eq(s, inner));
        }
    }
}

/// Process-wide table of one [`Broker`] per [`Domain`] — the Rust
/// equivalent of go-DDS's package-level `sharedBrokers` map (there guarded
/// by `sharedBrokerMu`; here by the `Mutex` inside `OnceLock`).
//fusa:req REQ-SHMEM-006
static SHARED_BROKERS: OnceLock<Mutex<HashMap<i32, Arc<Broker>>>> = OnceLock::new();

/// Returns the shared [`Broker`] for `domain`, creating it on first use.
/// Every [`super::participant::ShmemParticipant`] constructed for the same
/// domain in this process shares the returned broker; participants on
/// different domains never share one (REQ-SHMEM-006 — domain isolation).
pub(super) fn broker_for(domain: Domain) -> Arc<Broker> {
    let table = SHARED_BROKERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut table = table.lock().unwrap();
    table.entry(domain.0).or_insert_with(Broker::new).clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::BackPressurePolicy;

    fn sample(topic: &str, payload: &[u8]) -> Sample {
        Sample {
            topic: topic.to_string(),
            payload: payload.to_vec(),
            timestamp: chrono::Utc::now(),
            sequence_number: 1,
            writer_guid: [0u8; 16],
        }
    }

    //fusa:test REQ-SHMEM-002
    #[test]
    fn publish_delivers_to_subscriber() {
        let b = Broker::new();
        let inner = b.subscribe("t/x", &QoS::default(), &SubscriberOptions::default());
        b.publish("t/x", sample("t/x", b"hi"), &QoS::default());
        let got = inner.pop().unwrap();
        assert_eq!(got.payload, b"hi");
    }

    //fusa:test REQ-SHMEM-007
    #[test]
    fn topic_isolation() {
        let b = Broker::new();
        let inner_a = b.subscribe("t/a", &QoS::default(), &SubscriberOptions::default());
        let inner_b = b.subscribe("t/b", &QoS::default(), &SubscriberOptions::default());
        b.publish("t/a", sample("t/a", b"for-a"), &QoS::default());
        assert!(inner_a.pop().is_some());
        assert!(inner_b.pop().is_none());
    }

    //fusa:test REQ-SHMEM-004
    #[test]
    fn transient_local_delivers_cache_to_late_joiner() {
        let b = Broker::new();
        let qos = crate::types::RELIABLE_QOS.clone();
        b.publish("t/cached", sample("t/cached", b"cached-value"), &qos);
        let inner = b.subscribe("t/cached", &qos, &SubscriberOptions::default());
        let got = inner.pop().unwrap();
        assert_eq!(got.payload, b"cached-value");
    }

    #[test]
    fn volatile_does_not_cache() {
        let b = Broker::new();
        b.publish("t/v", sample("t/v", b"x"), &QoS::default());
        let inner = b.subscribe("t/v", &QoS::default(), &SubscriberOptions::default());
        assert!(inner.pop().is_none());
    }

    //fusa:test REQ-SHMEM-006
    #[test]
    fn broker_for_domain_isolation() {
        let b0 = broker_for(Domain(50));
        let b1 = broker_for(Domain(51));
        assert!(!Arc::ptr_eq(&b0, &b1));
        let b0_again = broker_for(Domain(50));
        assert!(Arc::ptr_eq(&b0, &b0_again));
    }

    #[test]
    fn remove_subscriber_stops_delivery() {
        let b = Broker::new();
        let inner = b.subscribe("t/rm", &QoS::default(), &SubscriberOptions::default());
        b.remove_subscriber("t/rm", &inner);
        b.publish("t/rm", sample("t/rm", b"after-remove"), &QoS::default());
        assert!(inner.pop().is_none());
    }

    #[test]
    fn drop_oldest_back_pressure_honoured() {
        let b = Broker::new();
        let opts = SubscriberOptions {
            channel_depth: 2,
            back_pressure: BackPressurePolicy::DropOldest,
            ..Default::default()
        };
        let inner = b.subscribe("t/bp", &QoS::default(), &opts);
        b.publish("t/bp", sample("t/bp", b"a"), &QoS::default());
        b.publish("t/bp", sample("t/bp", b"b"), &QoS::default());
        b.publish("t/bp", sample("t/bp", b"c"), &QoS::default());
        let s1 = inner.pop().unwrap();
        let s2 = inner.pop().unwrap();
        assert_eq!(s1.payload, b"b");
        assert_eq!(s2.payload, b"c");
        assert!(inner.pop().is_none());
    }
}
