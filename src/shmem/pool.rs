// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`BytePool`] — a fixed-capacity byte-buffer pool backing
//! [`super::loan::ShmemLoaningPublisher`]'s allocation-free publish path.
//!
//! Direct port of go-DDS's `pool.BytePool` (`pool/pool.go`), minus
//! `SampleBuffer` (that type has no consumer yet in this crate — nothing
//! here needs a ring buffer of `Sample`s — so it is not ported; add it if
//! a future milestone needs it). Unlike go-DDS's `sync.Pool`-backed
//! implementation (which lets the Go garbage collector reclaim pooled
//! buffers under memory pressure, and offers no size bound on the pool
//! itself), this port uses a plain `Mutex<Vec<Vec<u8>>>` free list capped
//! at [`BytePool::MAX_POOLED`] entries — Rust has no GC to rely on for
//! that reclamation, and an unbounded free list would be an unbounded
//! allocation under a bursty publish rate with slow commits. Buffers
//! beyond the cap are simply dropped (freed) on `put` rather than pooled,
//! same fail-open behavior as go-DDS's own undersized-buffer discard in
//! `BytePool.Put`.

use std::sync::Mutex;

/// Default pool buffer capacity when `size <= 0` is requested — matches
/// go-DDS's `pool.New`'s `size <= 0` default.
const DEFAULT_POOL_BUF_SIZE: usize = 4096;

/// A pool of reusable, fixed-minimum-capacity byte buffers.
///
/// `get` returns a zero-length buffer with at least `size` bytes of spare
/// capacity; `put` returns a buffer to the pool for reuse, discarding it
/// (rather than pooling) if its capacity is below `size` or the pool's
/// free list is already at [`BytePool::MAX_POOLED`].
//fusa:req REQ-LOAN-002
//fusa:req REQ-LOAN-003
pub struct BytePool {
    free: Mutex<Vec<Vec<u8>>>,
    size: usize,
}

impl BytePool {
    /// Free-list cap — bounds this pool's worst-case retained memory to
    /// `MAX_POOLED * size` bytes (REQ-MEM-001: no unbounded growth on a
    /// hot path).
    pub const MAX_POOLED: usize = 64;

    /// Returns a pool whose `get` yields buffers with at least `size` bytes
    /// of capacity. `size == 0` uses the default of 4096 bytes, matching
    /// go-DDS's `pool.New(0)`.
    //fusa:req REQ-LOAN-002
    pub fn new(size: usize) -> Self {
        let size = if size == 0 {
            DEFAULT_POOL_BUF_SIZE
        } else {
            size
        };
        Self {
            free: Mutex::new(Vec::new()),
            size,
        }
    }

    /// The minimum capacity every buffer this pool returns from `get`
    /// carries.
    pub fn buf_size(&self) -> usize {
        self.size
    }

    /// Returns a zero-length buffer with at least `self.size` bytes of
    /// spare capacity — reused from the free list when available,
    /// otherwise freshly allocated.
    //fusa:req REQ-LOAN-002
    pub fn get(&self) -> Vec<u8> {
        let mut free = self.free.lock().unwrap();
        match free.pop() {
            Some(mut buf) => {
                buf.clear();
                buf
            }
            None => Vec::with_capacity(self.size),
        }
    }

    /// Returns `buf` to the pool for reuse. Buffers with capacity below
    /// `self.size`, or received once the free list is already at
    /// [`BytePool::MAX_POOLED`], are dropped instead of pooled — the pool
    /// never accumulates undersized buffers or grows without bound.
    //fusa:req REQ-LOAN-003
    pub fn put(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.size {
            return;
        }
        let mut free = self.free.lock().unwrap();
        if free.len() >= Self::MAX_POOLED {
            return;
        }
        buf.clear();
        free.push(buf);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-LOAN-002
    #[test]
    fn get_returns_correct_capacity() {
        let bp = BytePool::new(512);
        let buf = bp.get();
        assert!(buf.capacity() >= 512);
        assert_eq!(buf.len(), 0);
    }

    //fusa:test REQ-LOAN-003
    #[test]
    fn put_and_get_reuses_buffer() {
        let bp = BytePool::new(256);
        let mut buf = bp.get();
        buf.extend_from_slice(&[1, 2, 3]);
        bp.put(buf);

        let reused = bp.get();
        assert!(reused.capacity() >= 256);
        assert_eq!(reused.len(), 0);
    }

    //fusa:test REQ-LOAN-003
    #[test]
    fn put_discards_undersized_buffer() {
        let bp = BytePool::new(1024);
        let small = Vec::with_capacity(16);
        bp.put(small); // must not panic, just discarded
        let buf = bp.get();
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn zero_size_defaulted() {
        let bp = BytePool::new(0);
        assert_eq!(bp.buf_size(), DEFAULT_POOL_BUF_SIZE);
        assert!(bp.get().capacity() >= DEFAULT_POOL_BUF_SIZE);
    }

    //fusa:test REQ-MEM-001
    #[test]
    fn put_bounded_free_list_does_not_grow_unbounded() {
        let bp = BytePool::new(64);
        for _ in 0..(BytePool::MAX_POOLED * 4) {
            bp.put(Vec::with_capacity(64));
        }
        assert!(bp.free.lock().unwrap().len() <= BytePool::MAX_POOLED);
    }

    #[test]
    fn concurrent_get_put() {
        use std::sync::Arc;
        let bp = Arc::new(BytePool::new(128));
        let mut handles = Vec::new();
        for _ in 0..50 {
            let bp = Arc::clone(&bp);
            handles.push(std::thread::spawn(move || {
                let mut buf = bp.get();
                buf.push(1);
                bp.put(buf);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
