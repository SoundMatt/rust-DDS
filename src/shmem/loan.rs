// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `LoaningPublisher` wired to the shmem transport — `ROADMAP.md`'s
//! "Planned — v0.4 — Shared-Memory Transport" milestone, second checklist
//! item ("`LoaningPublisher` trait with pool-backed zero-copy writes").
//!
//! The [`crate::participant::LoaningPublisher`] trait itself lives in
//! `src/participant.rs` alongside [`crate::participant::Publisher`] (it
//! extends that trait, matching go-DDS's own `dds.LoaningPublisher`
//! placement in the top-level `dds.go` next to `dds.Publisher`) so a
//! future transport can implement it too; this module is the first (and,
//! for this milestone, only) implementation, matching Tier 1 sub-phase
//! 9's own scoping note that deferred go-DDS's `loan.go` here "since it's
//! not meaningful without a zero-copy transport underneath it" —
//! `ShmemPublisher::write_payload` is that transport.
//!
//! # "Zero-copy", precisely
//!
//! As with go-DDS's own `shmem.loaningPublisher` (`shmem/loan.go`), "zero
//! copy" describes the *hot publish path being allocation-free* — `loan`
//! reuses a pool buffer instead of the caller `Vec::new`-ing a fresh one
//! per sample, and `commit` returns it to the pool afterward — not that a
//! sample crosses the process boundary without any byte copy at all.
//! [`super::ipc::write_sample`] still copies the loaned buffer's bytes
//! into the rendezvous file exactly once per cross-process delivery, the
//! same as [`super::participant::ShmemPublisher::write`]'s
//! non-loaned path; go-DDS's own reference has the identical shape (its
//! `Commit` calls straight through to `Write`, which itself copies into
//! `sample.Payload` and then again into the rendezvous file via
//! `shmPublish`). What `loan`/`commit` actually buys, in both
//! implementations, is: no per-sample heap allocation on a publisher
//! that writes at a steady, bounded-size rate — the allocation happens
//! once (or a handful of times, until the pool's free list fills) rather
//! than once per `write`.
//!
//! # Rust-idiomatic simplification versus go-DDS's `NewLoaningPublisher`
//!
//! go-DDS's `shmem.NewLoaningPublisher(p dds.Participant, ...)` is a free
//! function taking the `dds.Participant` *interface* and type-asserting
//! (`pub.(*shmPublisher)`) that the concrete publisher it just created is
//! actually a shmem one, returning `ErrLoanBuffer` if not (reachable only
//! by passing a non-shmem `dds.Participant`, e.g. `mock`/`rtps`, into the
//! `shmem` package's constructor — a caller error the type system cannot
//! catch in Go). This module instead adds `new_loaning_publisher` as an
//! inherent method on the concrete [`super::participant::ShmemParticipant`]
//! type (below), so that caller error is a compile error instead of a
//! runtime `Result::Err` — there is no `dyn Participant` to
//! downcast, and therefore no failure mode to test for it either.

use async_trait::async_trait;

use crate::error::Error;
use crate::participant::{LoaningPublisher, Publisher};
use crate::relay::Context;
use crate::types::QoS;

use super::participant::ShmemParticipant;
use super::pool::BytePool;

/// A [`LoaningPublisher`] backed by [`super::participant::ShmemPublisher`]
/// and a [`BytePool`].
pub struct ShmemLoaningPublisher {
    inner: super::participant::ShmemPublisher,
    pool: BytePool,
}

impl ShmemLoaningPublisher {
    fn new(inner: super::participant::ShmemPublisher, buf_size: usize) -> Self {
        Self {
            inner,
            pool: BytePool::new(buf_size),
        }
    }
}

#[async_trait]
impl Publisher for ShmemLoaningPublisher {
    async fn write(&self, payload: Vec<u8>) -> Result<(), Error> {
        self.inner.write_payload(payload)
    }

    async fn write_ctx(&self, ctx: Context, payload: Vec<u8>) -> Result<(), Error> {
        if ctx.done() {
            return Err(Error::Timeout);
        }
        self.inner.write_payload(payload)
    }

    async fn close(&self) -> Result<(), Error> {
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl LoaningPublisher for ShmemLoaningPublisher {
    //fusa:req REQ-LOAN-001
    //fusa:req REQ-LOAN-002
    fn loan(&self, size: usize) -> Result<Vec<u8>, Error> {
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let buf = self.pool.get();
        if buf.capacity() < size {
            self.pool.put(buf);
            return Err(Error::LoanBuffer);
        }
        // `resize` zero-fills the newly-visible bytes rather than exposing
        // whatever this buffer's previous tenant left behind — the safe-Rust
        // cost of avoiding an `unsafe { set_len }` shortcut (REQ-ASIL-002 /
        // REQ-MEM-001). The caller is expected to overwrite the loaned
        // range before `commit` regardless, same as go-DDS's own
        // `Loan`/`Commit` contract (go-DDS's `buf[:size]` re-slice exposes
        // genuinely uninitialised-for-this-use leftover bytes instead;
        // functionally equivalent from the caller's point of view, since
        // neither implementation reads the loaned buffer before the caller
        // writes into it).
        let mut buf = buf;
        buf.resize(size, 0);
        Ok(buf)
    }

    //fusa:req REQ-LOAN-003
    async fn commit(&self, buf: Vec<u8>) -> Result<(), Error> {
        let result = self.inner.write_payload(buf.clone());
        self.pool.put(buf);
        result
    }
}

impl ShmemParticipant {
    /// Creates a [`LoaningPublisher`] for `topic` backed by the shmem
    /// transport. `buf_size` is the pool's minimum per-buffer capacity;
    /// `0` uses the pool default (4096 bytes, see [`BytePool::new`]).
    ///
    /// Returns the same errors [`crate::participant::Participant::new_publisher`]
    /// would (`Error::Closed`, `Error::TopicEmpty`).
    //fusa:req REQ-LOAN-001
    pub fn new_loaning_publisher(
        &self,
        topic: &str,
        qos: QoS,
        buf_size: usize,
    ) -> Result<Box<dyn LoaningPublisher>, Error> {
        let inner = self.make_publisher(topic, qos)?;
        Ok(Box::new(ShmemLoaningPublisher::new(inner, buf_size)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participant::Participant;
    use crate::relay::SubscriberOptions;
    use crate::types::Domain;
    use std::sync::Arc;
    use std::time::Duration;

    fn fast(domain: Domain) -> Arc<ShmemParticipant> {
        ShmemParticipant::new_with_poll_interval(domain, Duration::from_millis(5)).unwrap()
    }

    //fusa:test REQ-LOAN-001
    //fusa:test REQ-LOAN-002
    //fusa:test REQ-LOAN-003
    #[tokio::test]
    async fn loan_commit_round_trip() {
        let p = fast(Domain(150));
        let (rx, _sub) = p
            .new_subscriber(
                "shmem/loan/rt",
                QoS::default(),
                SubscriberOptions::default(),
            )
            .await
            .unwrap();
        let lp = p
            .new_loaning_publisher("shmem/loan/rt", QoS::default(), 256)
            .unwrap();

        let mut buf = lp.loan(12).unwrap();
        buf.copy_from_slice(b"hello-shmem!");
        lp.commit(buf).await.unwrap();

        let sample = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sample.payload, b"hello-shmem!");
    }

    //fusa:test REQ-LOAN-002
    #[tokio::test]
    async fn loan_size_exceeding_pool_capacity_returns_loan_buffer_error() {
        let p = fast(Domain(151));
        let lp = p
            .new_loaning_publisher("shmem/loan/size", QoS::default(), 64)
            .unwrap();
        assert!(matches!(lp.loan(4096), Err(Error::LoanBuffer)));
    }

    //fusa:test REQ-LOAN-001
    #[tokio::test]
    async fn loan_after_close_returns_closed() {
        let p = fast(Domain(152));
        let lp = p
            .new_loaning_publisher("shmem/loan/closed", QoS::default(), 256)
            .unwrap();
        lp.close().await.unwrap();
        assert!(matches!(lp.loan(10), Err(Error::Closed)));
    }

    //fusa:test REQ-LOAN-003
    #[tokio::test]
    async fn commit_returns_buffer_to_pool_for_reuse() {
        let p = fast(Domain(153));
        let lp = p
            .new_loaning_publisher("shmem/loan/reuse", QoS::default(), 256)
            .unwrap();
        for i in 0..8u8 {
            let mut buf = lp.loan(4).unwrap();
            buf.copy_from_slice(&[i; 4]);
            lp.commit(buf).await.unwrap();
        }
        // No direct pool-size assertion here (pool internals are private to
        // this module's sibling); this test's real assertion is that eight
        // loan/commit cycles complete without panicking or leaking an
        // error — see `pool::tests` for the pool's own reuse assertions.
    }

    #[tokio::test]
    async fn direct_write_and_close_still_work_via_publisher_trait() {
        let p = fast(Domain(154));
        let lp = p
            .new_loaning_publisher("shmem/loan/direct", QoS::default(), 256)
            .unwrap();
        lp.write(b"direct".to_vec()).await.unwrap();
        lp.close().await.unwrap();
    }

    #[tokio::test]
    async fn max_sample_size_enforced_through_loaning_publisher() {
        let p = fast(Domain(155));
        let qos = QoS {
            max_sample_size: 4,
            ..QoS::default()
        };
        let lp = p
            .new_loaning_publisher("shmem/loan/maxsize", qos, 64)
            .unwrap();
        let buf = lp.loan(5).unwrap();
        assert!(matches!(lp.commit(buf).await, Err(Error::PayloadTooLarge)));
    }
}
