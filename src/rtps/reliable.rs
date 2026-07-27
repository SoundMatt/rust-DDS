// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Reliable QoS bookkeeping: per-writer send history and per-reader gap
//! tracking (RTPS 2.3 §8.4.9 – §8.4.12).
//!
//! This is Tier 1 sub-phase 7 of the parity build-out plan in `ROADMAP.md`
//! ("Tier 1 — RTPS wire-protocol port" → "Reliable QoS"). It mirrors
//! go-DDS's `rtps/reliable.go` (231 LOC): [`SendHistory`] is the sender-side
//! ring buffer of recently-sent wire messages retained for retransmission
//! (go-DDS's `sendHistory`), and [`RecvTracker`] is the receiver-side
//! per-remote-writer contiguous-watermark gap tracker (go-DDS's
//! `recvTracker`). The HEARTBEAT/ACKNACK/GAP submessage wire codec itself
//! lives in [`super::message`] (extending sub-phase 1's framing module,
//! matching go-DDS's own file layout — `marshalHeartbeat`/`marshalAckNack`/
//! `marshalGAP` are defined in `message.go`, not `reliable.go`). The
//! heartbeat-send/acknack-handle/retransmit *wiring* into the participant
//! runtime lives in [`super::participant`] (extending sub-phase 6's
//! `RtpsParticipant`/`RtpsWriter`/`RtpsReader`), mirroring go-DDS's own
//! split: `reliable.go` holds only the bookkeeping types, while
//! `notifyReliableReaders`/`handleHeartbeat`/`handleAckNack`/
//! `rtpsWriter.sendHeartbeatLocked`/`heartbeatLoop` live in
//! `participant.go`.
//!
//! # Sequence-number packing
//!
//! Both types key their bookkeeping by the packed 64-bit sequence number
//! ([`super::message::SequenceNumber::to_u64`]/`from_u64`, already ported in
//! sub-phase 1 as the direct equivalent of go-DDS's `snToU64`/`u64ToSN`) —
//! never by the raw `{high, low}` pair — so nothing here re-aliases after
//! the low 32 bits wrap.
//!
//! # Concurrency
//!
//! Per `ROADMAP.md`'s async/tokio design table ("Prefer a plain (non-async)
//! `Mutex`/`RwLock` ... over `tokio::sync::Mutex` for these — critical
//! sections are short bookkeeping updates"), both [`SendHistory`] and
//! [`RecvTracker`] guard their state with a plain [`std::sync::Mutex`],
//! exactly like go-DDS's own `sendHistory.mu`/`recvTracker.mu`
//! (`sync.Mutex`). Neither type performs any I/O or holds its lock across an
//! `.await` point.
//!
//! No `unsafe` anywhere (REQ-ASIL-002 / REQ-MEM-001, carried forward).

use std::collections::HashSet;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Period of the periodic HEARTBEAT ticker a reliable writer runs for as
/// long as it is open, so remote readers can detect and recover from losses
/// even without a fresh write. Matches go-DDS's `heartbeatPeriod`.
//fusa:req REQ-RTPS-049
pub const HEARTBEAT_PERIOD: Duration = Duration::from_millis(200);

/// Number of samples retained per reliable writer for retransmission.
/// Matches go-DDS's `maxHistoryDepth`.
//fusa:req REQ-RTPS-046
pub const MAX_HISTORY_DEPTH: usize = 256;

/// Bounds how far ahead of the cumulative-ACK watermark a received sequence
/// number is buffered by [`RecvTracker`]. Samples further ahead are not
/// retained in the out-of-order set (they are re-requested via
/// HEARTBEAT/ACKNACK once the watermark advances), keeping memory bounded
/// against a misbehaving writer. Matches go-DDS's `maxReorderAhead`.
//fusa:req REQ-RTPS-048
pub const MAX_REORDER_AHEAD: u64 = 8192;

// ---------------------------------------------------------------------------
// SendHistory — sender-side reliability
// ---------------------------------------------------------------------------

/// Fixed-size ring of the last [`MAX_HISTORY_DEPTH`] full RTPS wire messages
/// a reliable writer has sent, keyed by full 64-bit sequence number, for
/// retransmission on ACKNACK. Because a writer emits strictly increasing,
/// contiguous sequence numbers, the store is `O(1)`, provably bounded (never
/// larger than [`MAX_HISTORY_DEPTH`]), and free of 32-bit-wraparound
/// aliasing. Matches go-DDS's `sendHistory` exactly (ring index `seq %
/// depth`, retained window `[highest - depth + 1, highest]`).
//fusa:req REQ-RTPS-046
pub struct SendHistory {
    inner: Mutex<SendHistoryInner>,
    hb_count: AtomicI32,
}

struct SendHistoryInner {
    msg: Vec<Option<Vec<u8>>>,
    sn: Vec<u64>,
    highest: u64,
    lowest: u64,
    any: bool,
}

impl Default for SendHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl SendHistory {
    /// Creates an empty history with capacity [`MAX_HISTORY_DEPTH`].
    //fusa:req REQ-RTPS-046
    pub fn new() -> Self {
        let depth = MAX_HISTORY_DEPTH;
        SendHistory {
            inner: Mutex::new(SendHistoryInner {
                msg: vec![None; depth],
                sn: vec![0; depth],
                highest: 0,
                lowest: 0,
                any: false,
            }),
            hb_count: AtomicI32::new(0),
        }
    }

    /// Saves a copy of the full RTPS wire message for possible
    /// retransmission, evicting whatever sequence number previously
    /// occupied the ring slot. Matches go-DDS's `sendHistory.store`.
    //fusa:req REQ-RTPS-046
    pub fn store(&self, seq: u64, msg: &[u8]) {
        let depth = MAX_HISTORY_DEPTH as u64;
        let mut inner = self.inner.lock().expect("SendHistory mutex poisoned");
        let i = (seq % depth) as usize;
        inner.msg[i] = Some(msg.to_vec());
        inner.sn[i] = seq;
        if !inner.any {
            inner.lowest = seq;
            inner.highest = seq;
            inner.any = true;
        }
        if seq > inner.highest {
            inner.highest = seq;
        }
        // The retained window is the last `depth` sequence numbers.
        if inner.highest >= depth {
            let lb = inner.highest - depth + 1;
            if lb > inner.lowest {
                inner.lowest = lb;
            }
        }
    }

    /// Returns the stored message for `seq`, or `None` if it was never
    /// stored or has been evicted from the retained window. Matches
    /// go-DDS's `sendHistory.get`.
    //fusa:req REQ-RTPS-046
    pub fn get(&self, seq: u64) -> Option<Vec<u8>> {
        let depth = MAX_HISTORY_DEPTH as u64;
        let inner = self.inner.lock().expect("SendHistory mutex poisoned");
        if !inner.any || seq < inner.lowest || seq > inner.highest {
            return None;
        }
        let i = (seq % depth) as usize;
        if inner.sn[i] != seq {
            return None;
        }
        inner.msg[i].clone()
    }

    /// Returns the lowest and highest retained sequence numbers, or `None`
    /// if nothing has been stored yet. Matches go-DDS's
    /// `sendHistory.firstLast`.
    //fusa:req REQ-RTPS-046
    pub fn first_last(&self) -> Option<(u64, u64)> {
        let inner = self.inner.lock().expect("SendHistory mutex poisoned");
        if !inner.any {
            return None;
        }
        Some((inner.lowest, inner.highest))
    }

    /// Returns a fresh, monotonically increasing HEARTBEAT count. Matches
    /// go-DDS's `sendHistory.hbCount` (an `atomic.Int32`).
    //fusa:req REQ-RTPS-046
    pub fn next_hb_count(&self) -> i32 {
        self.hb_count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

// ---------------------------------------------------------------------------
// RecvTracker — receiver-side reliability
// ---------------------------------------------------------------------------

/// Tracks reliable-delivery state for a single remote writer.
///
/// Maintains a sliding window: `expected` is the lowest sequence number not
/// yet received (the cumulative-ACK base — everything below it has
/// arrived), and `ahead` holds out-of-order sequence numbers at or above
/// `expected` that have already been received. `expected` advances only
/// over a contiguous run, so a missing sequence number is re-NACKed on
/// every HEARTBEAT until it actually arrives, and gaps larger than one
/// 32-bit ACKNACK window are recovered window-by-window as the watermark
/// advances. Matches go-DDS's `recvTracker` exactly.
//fusa:req REQ-RTPS-047
pub struct RecvTracker {
    inner: Mutex<RecvTrackerInner>,
    ack_count: AtomicI32,
}

struct RecvTrackerInner {
    expected: u64,
    ahead: HashSet<u64>,
    init_done: bool,
}

impl Default for RecvTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RecvTracker {
    /// Creates a tracker with no writer contact yet.
    //fusa:req REQ-RTPS-047
    pub fn new() -> Self {
        RecvTracker {
            inner: Mutex::new(RecvTrackerInner {
                expected: 0,
                ahead: HashSet::new(),
                init_done: false,
            }),
            ack_count: AtomicI32::new(0),
        }
    }

    /// Sets the cumulative-ACK base on first contact with a writer
    /// (typically from a HEARTBEAT's `FirstSN`) so the reader can request
    /// the writer's whole history. A no-op once the tracker has seen any
    /// sample. Matches go-DDS's `recvTracker.initExpected`.
    //fusa:req REQ-RTPS-047
    pub fn init_expected(&self, first_sn: u64) {
        let mut inner = self.inner.lock().expect("RecvTracker mutex poisoned");
        if !inner.init_done {
            inner.expected = first_sn;
            inner.init_done = true;
        }
    }

    /// Marks `seq` as received and advances the contiguous watermark over
    /// any buffered successors. Returns `false` when `seq` was already
    /// delivered (below the watermark) or already buffered, so callers can
    /// suppress duplicate delivery. Matches go-DDS's `recvTracker.record`.
    //fusa:req REQ-RTPS-047
    pub fn record(&self, seq: u64) -> bool {
        let mut inner = self.inner.lock().expect("RecvTracker mutex poisoned");
        if !inner.init_done {
            inner.expected = seq;
            inner.init_done = true;
        }
        if seq < inner.expected {
            return false; // already delivered
        }
        if seq == inner.expected {
            inner.expected += 1;
            loop {
                let next = inner.expected;
                if !inner.ahead.remove(&next) {
                    break;
                }
                inner.expected += 1;
            }
            return true;
        }
        // seq > expected: buffer it (bounded) unless already seen.
        if inner.ahead.contains(&seq) {
            return false;
        }
        if seq - inner.expected <= MAX_REORDER_AHEAD {
            inner.ahead.insert(seq);
        }
        true
    }

    /// Returns the ACKNACK base and bitmap describing the sequence numbers
    /// still missing in `[expected, last_sn]`, capped at one 32-bit window.
    /// `base` is the cumulative-ACK watermark; bit `N` set means `base + N`
    /// is missing. `need_ack` is `true` when at least one sequence number in
    /// the window is missing. Returns `(0, 0, false)` if this tracker has
    /// not yet had `init_expected`/`record` called. Matches go-DDS's
    /// `recvTracker.missing`.
    //fusa:req REQ-RTPS-047
    pub fn missing(&self, last_sn: u64) -> (u64, u32, bool) {
        let inner = self.inner.lock().expect("RecvTracker mutex poisoned");
        if !inner.init_done {
            return (0, 0, false);
        }
        let base = inner.expected;
        if last_sn < base {
            return (base, 0, false); // fully caught up with the writer
        }
        let mut end = last_sn;
        if end > base + 31 {
            end = base + 31;
        }
        let mut bitmap = 0u32;
        let mut need_ack = false;
        let mut sn = base;
        while sn <= end {
            // `expected` is never present in `ahead`, so this also flags
            // `base` itself.
            if !inner.ahead.contains(&sn) {
                bitmap |= 1 << (sn - base);
                need_ack = true;
            }
            sn += 1;
        }
        (base, bitmap, need_ack)
    }

    /// Returns a fresh, monotonically increasing ACKNACK count. Matches
    /// go-DDS's `recvTracker.nextAckCount`.
    //fusa:req REQ-RTPS-047
    pub fn next_ack_count(&self) -> i32 {
        self.ack_count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-RTPS-046
    #[test]
    fn send_history_stores_and_retrieves() {
        let h = SendHistory::new();
        h.store(1, &[0xAA]);
        h.store(2, &[0xBB]);
        assert_eq!(h.get(1), Some(vec![0xAA]));
        assert_eq!(h.get(2), Some(vec![0xBB]));
        assert_eq!(h.get(3), None);
        assert_eq!(h.first_last(), Some((1, 2)));
    }

    // Cross-checked against go-DDS's own `sendHistory` (real `store`/
    // `firstLast`/`get`, not reimplemented). Go reproduction
    // (`rtps/zzrepro_reliable_test.go`, never committed to go-DDS, deleted
    // after use):
    //
    //   h := newSendHistory()
    //   for i := uint64(1); i <= 300; i++ { h.store(i, []byte{byte(i)}) }
    //   first, last, ok := h.firstLast()
    //   fmt.Printf("first=%d last=%d ok=%v\n", first, last, ok)
    //   // -> first=45 last=300 ok=true
    //   fmt.Printf("evicted=%v\n", h.get(1) == nil)
    //   // -> evicted=true
    //
    // Full run: `go test ./rtps/... -run TestZZReproReliableBytes -v`
    // (go-DDS commit e9b36f5 / rust-DDS branch feat/rtps-reliable-qos).
    //fusa:test REQ-RTPS-046
    #[test]
    fn send_history_evicts_beyond_max_depth_matching_go_dds_reference() {
        let h = SendHistory::new();
        for i in 1u64..=300 {
            h.store(i, &[i as u8]);
        }
        assert_eq!(h.first_last(), Some((45, 300)));
        assert_eq!(h.get(1), None); // evicted
        assert_eq!(h.get(44), None); // evicted (lowest retained is 45)
        assert_eq!(h.get(45), Some(vec![45u8])); // still retained (lowest of the window)
        assert_eq!(h.get(300), Some(vec![300u32 as u8])); // 300 truncates to u8 = 44
    }

    //fusa:test REQ-RTPS-046
    #[test]
    fn send_history_hb_count_is_monotonically_increasing() {
        let h = SendHistory::new();
        assert_eq!(h.next_hb_count(), 1);
        assert_eq!(h.next_hb_count(), 2);
        assert_eq!(h.next_hb_count(), 3);
    }

    //fusa:test REQ-RTPS-047
    #[test]
    fn recv_tracker_record_advances_over_contiguous_run() {
        let rt = RecvTracker::new();
        assert!(rt.record(1)); // fresh, also initializes expected=1 -> 2
        assert!(rt.record(2));
        assert!(rt.record(3));
        let (base, bitmap, need_ack) = rt.missing(3);
        assert_eq!(base, 4);
        assert_eq!(bitmap, 0);
        assert!(!need_ack);
    }

    //fusa:test REQ-RTPS-047
    #[test]
    fn recv_tracker_duplicate_is_not_fresh() {
        let rt = RecvTracker::new();
        assert!(rt.record(1));
        assert!(!rt.record(1)); // already delivered (below watermark)
    }

    // Cross-checked against go-DDS's own `recvTracker` (real `initExpected`/
    // `record`/`missing`, not reimplemented). Go reproduction
    // (`rtps/zzrepro_reliable_test.go`, never committed to go-DDS, deleted
    // after use):
    //
    //   rt := &recvTracker{}
    //   rt.initExpected(1)
    //   rt.record(1)
    //   rt.record(3) // gap at 2
    //   base, bitmap, needAck := rt.missing(5)
    //   fmt.Printf("base=%d bitmap=%#b needAck=%v\n", base, bitmap, needAck)
    //   // -> base=2 bitmap=0b1101 needAck=true
    //
    // Full run: `go test ./rtps/... -run TestZZReproReliableBytes -v`
    // (go-DDS commit e9b36f5 / rust-DDS branch feat/rtps-reliable-qos).
    //fusa:test REQ-RTPS-047
    #[test]
    fn recv_tracker_gap_detection_matches_go_dds_reference() {
        let rt = RecvTracker::new();
        rt.init_expected(1);
        rt.record(1);
        rt.record(3); // gap at 2
        let (base, bitmap, need_ack) = rt.missing(5);
        assert_eq!(base, 2);
        assert_eq!(bitmap, 0b1101);
        assert!(need_ack);
    }

    //fusa:test REQ-RTPS-047
    #[test]
    fn recv_tracker_missing_reports_not_yet_contacted() {
        let rt = RecvTracker::new();
        let (base, bitmap, need_ack) = rt.missing(10);
        assert_eq!(base, 0);
        assert_eq!(bitmap, 0);
        assert!(!need_ack);
    }

    //fusa:test REQ-RTPS-048
    #[test]
    fn recv_tracker_out_of_order_beyond_max_reorder_ahead_is_not_buffered() {
        let rt = RecvTracker::new();
        rt.init_expected(1);
        // Far beyond MAX_REORDER_AHEAD: still reported "fresh" (not a
        // duplicate) but not retained in `ahead`, matching go-DDS's bounded
        // buffering — a second delivery of the same far-ahead SN is also
        // treated as fresh (never remembered), unlike an in-window SN.
        let far = 1 + MAX_REORDER_AHEAD + 100;
        assert!(rt.record(far));
        assert!(rt.record(far)); // not remembered -> still reports fresh
    }

    //fusa:test REQ-RTPS-047
    #[test]
    fn recv_tracker_ack_count_is_monotonically_increasing() {
        let rt = RecvTracker::new();
        assert_eq!(rt.next_ack_count(), 1);
        assert_eq!(rt.next_ack_count(), 2);
    }

    //fusa:test REQ-RTPS-049
    #[test]
    fn heartbeat_period_matches_go_dds_reference() {
        assert_eq!(HEARTBEAT_PERIOD, std::time::Duration::from_millis(200));
    }
}
