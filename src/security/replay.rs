// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`ReplayGuard`] — an anti-replay guard that tracks recently-seen
//! sequence numbers within a sliding time window.
//!
//! Direct port of go-DDS's `security.ReplayGuard`
//! (`github.com/SoundMatt/go-DDS`, `security/replay.go`). go-DDS's own doc
//! comment for the type states the property this port preserves exactly:
//! "`ReplayGuard` protects against replay attacks by tracking recently-seen
//! sequence numbers within a sliding time window. Each sequence number is
//! associated with the timestamp of the message that carried it. A
//! sequence number is considered a replay if it has been seen within
//! window duration of the current call."
//!
//! This is `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" fifth
//! checklist item ("Anti-replay guard (`ReplayGuard`)"). Like
//! [`super::acl::AccessPolicy`] above it, `ReplayGuard` is an orthogonal
//! mechanism, not a [`super::plugin::SecurityPlugin`] payload-seal/open
//! transform — a caller checks a sample's sequence number through a
//! `ReplayGuard` as an independent decision from sealing/opening its
//! payload or checking it against an `AccessPolicy`. As with every other
//! item in this module tree, wiring `ReplayGuard` checks into
//! `crate::rtps::participant::RtpsParticipant`'s receive path is deferred
//! until a concrete caller need arises — this item is scoped to the guard
//! mechanism itself. HMAC-SHA-256 discovery authentication (go-DDS's
//! `security/discovery.go`) remains the one still-unimplemented v0.5
//! checklist item after this one.
//!
//! # Timestamps: `Instant`, not wall-clock time
//!
//! go-DDS's `ReplayGuard.Check(seq uint64, ts time.Time)` takes the
//! *claimed send timestamp* of the message as an explicit parameter — a
//! wall-clock `time.Time` — rather than always reading the guard's own
//! clock. This lets a caller (or, as in go-DDS's own test suite, a test)
//! drive the sliding window against a timeline it controls rather than
//! real time. This port preserves that same explicit-timestamp design but
//! represents `ts` as [`std::time::Instant`] rather than
//! `std::time::SystemTime`/`chrono::DateTime`: this crate's own
//! established convention for "how long ago" freshness-window bookkeeping
//! (`crate::rtps::spdp::PeerProxy::last_seen`,
//! `crate::rtps::fragment::FragBuffer::created`) already uses `Instant`,
//! and `Instant` supports exactly the arithmetic go-DDS's own tests need
//! to construct a synthetic past or future timestamp (`Instant::now() -
//! Duration`, `Instant::now() + Duration`), without the wall-clock-skew/
//! non-monotonicity concerns `Instant` exists specifically to avoid.
//!
//! # Concurrency
//!
//! `ReplayGuard` is safe for concurrent use from multiple tasks — matching
//! go-DDS's own doc comment ("`ReplayGuard` is safe for concurrent use
//! from multiple goroutines") — via an internal `std::sync::Mutex`
//! guarding its seen-sequence-number map, the same interior-mutability
//! shape `crate::rtps::fragment::FragmentAssembler` already uses for its
//! own reassembly-buffer map. Every method here takes `&self`, not `&mut
//! self`, so `ReplayGuard` is usable directly behind a shared `Arc`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use thiserror::Error;

/// The sliding window a [`ReplayGuard`] falls back to when constructed
/// with a zero window. Matches go-DDS's `NewReplayGuard`'s substitution of
/// `30 * time.Second` for any `window <= 0`.
//fusa:req REQ-SEC-026
pub const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(30);

/// Returned by [`ReplayGuard::check`] when `seq` has already been seen
/// within the guard's window.
///
/// Direct port of go-DDS's `security.ErrReplay` sentinel error
/// (`errors.New("security: replayed sequence number detected")`) — a
/// distinct, dedicated error type here rather than a
/// [`super::plugin::SecurityError`] variant, since `ReplayGuard` is not a
/// `SecurityPlugin` and this failure mode (a duplicate sequence number)
/// has no counterpart among `SecurityError`'s seal/open-framing variants.
//fusa:req REQ-SEC-026
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Error)]
#[error("security: replayed sequence number detected")]
pub struct ReplayError;

/// Tracks recently-seen sequence numbers within a sliding time window to
/// detect replayed (duplicate) messages.
///
/// Direct port of go-DDS's `security.ReplayGuard`. See the [module-level
/// docs](self) for the timestamp and concurrency design this port
/// preserves.
///
/// # Examples
///
/// ```
/// use rust_dds::security::ReplayGuard;
/// use std::time::Instant;
///
/// let guard = ReplayGuard::new(std::time::Duration::from_secs(30));
/// let now = Instant::now();
/// assert!(guard.check(1, now).is_ok());
/// // The same sequence number, seen again within the window, is a replay.
/// assert!(guard.check(1, now).is_err());
/// ```
#[derive(Debug)]
pub struct ReplayGuard {
    window: Duration,
    seen: Mutex<HashMap<u64, Instant>>,
}

impl ReplayGuard {
    /// Creates a `ReplayGuard` with the given sliding window.
    ///
    /// Matches go-DDS's `NewReplayGuard(window time.Duration) *ReplayGuard`:
    /// a zero window is replaced with [`DEFAULT_REPLAY_WINDOW`] (30
    /// seconds) — go-DDS's `window <= 0` check narrows to `window ==
    /// Duration::ZERO` here since [`Duration`] cannot represent a negative
    /// value in the first place.
    //fusa:req REQ-SEC-026
    pub fn new(window: Duration) -> Self {
        let window = if window.is_zero() {
            DEFAULT_REPLAY_WINDOW
        } else {
            window
        };
        Self {
            window,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Reports whether `seq` is a replay.
    ///
    /// Matches go-DDS's `ReplayGuard.Check`: if `seq` has not been seen
    /// within [`window`](ReplayGuard::new) of `ts`, it is recorded (keyed
    /// on `ts`) and `Ok(())` is returned. If `seq` has already been seen
    /// within the window, [`ReplayError`] is returned instead, and the
    /// existing recorded timestamp for `seq` is left untouched. `ts` is
    /// the claimed send timestamp of the message being checked; entries
    /// whose recorded timestamp is more than `window` before `ts` are
    /// pruned as a side effect of every call, exactly as go-DDS's own
    /// `Check` calls its unexported `purge` on every invocation.
    //fusa:req REQ-SEC-026
    //fusa:req REQ-SEC-027
    pub fn check(&self, seq: u64, ts: Instant) -> Result<(), ReplayError> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        Self::purge_locked(&mut seen, self.window, ts);
        if seen.contains_key(&seq) {
            return Err(ReplayError);
        }
        seen.insert(seq, ts);
        Ok(())
    }

    /// Removes every entry whose recorded timestamp is more than `window`
    /// before now.
    ///
    /// Matches go-DDS's `ReplayGuard.Purge`. [`check`](ReplayGuard::check)
    /// already purges on every call; call this method explicitly only
    /// when driving the clock externally (e.g. in tests), matching
    /// go-DDS's own doc comment for `Purge`.
    //fusa:req REQ-SEC-027
    pub fn purge(&self) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        Self::purge_locked(&mut seen, self.window, Instant::now());
    }

    /// Returns the number of sequence numbers currently tracked.
    ///
    /// Matches go-DDS's `ReplayGuard.Len`.
    //fusa:req REQ-SEC-027
    pub fn len(&self) -> usize {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.len()
    }

    /// Returns `true` if no sequence numbers are currently tracked.
    ///
    /// go-DDS's `ReplayGuard` has no `Empty`/`IsEmpty` method of its own;
    /// this is added purely so [`len`](ReplayGuard::len) has the
    /// conventional Rust `is_empty` companion, not a behavioral addition.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every entry in `seen` older than `window` before `now`.
    /// Matches go-DDS's unexported `ReplayGuard.purge`.
    ///
    /// Uses [`Instant::checked_sub`] rather than plain subtraction so that
    /// a `window` longer than the process's elapsed monotonic time can
    /// never panic (REQ-ASIL-003): when no valid cutoff exists that far
    /// in the past, nothing is old enough to be stale yet, so every entry
    /// is kept.
    fn purge_locked(seen: &mut HashMap<u64, Instant>, window: Duration, now: Instant) {
        let cutoff = now.checked_sub(window);
        seen.retain(|_, t| match cutoff {
            Some(cutoff) => *t >= cutoff,
            None => true,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // -- ReplayGuard behavior, ported 1:1 from go-DDS's replay_test.go --

    /// Matches go-DDS's `TestReplayGuard_FirstSeenAllowed`.
    //fusa:test REQ-SEC-026
    #[test]
    fn first_seen_allowed() {
        let g = ReplayGuard::new(Duration::from_secs(30));
        let now = Instant::now();
        assert!(g.check(1, now).is_ok());
    }

    /// Matches go-DDS's `TestReplayGuard_ReplayDetected`.
    //fusa:test REQ-SEC-026
    #[test]
    fn replay_detected() {
        let g = ReplayGuard::new(Duration::from_secs(30));
        let now = Instant::now();
        let _ = g.check(42, now);
        assert_eq!(g.check(42, now), Err(ReplayError));
    }

    /// Matches go-DDS's `TestReplayGuard_DifferentSeqAllowed`.
    //fusa:test REQ-SEC-026
    #[test]
    fn different_seq_allowed() {
        let g = ReplayGuard::new(Duration::from_secs(30));
        let now = Instant::now();
        let _ = g.check(1, now);
        assert!(g.check(2, now).is_ok());
    }

    /// Matches go-DDS's `TestReplayGuard_Purge_RemovesExpiredEntries`.
    //fusa:test REQ-SEC-027
    #[test]
    fn purge_removes_expired_entries() {
        let g = ReplayGuard::new(Duration::from_millis(50));
        let past = Instant::now() - Duration::from_millis(100); // outside window
        let _ = g.check(99, past);

        // After purging against now, the past entry should be removed.
        g.purge();
        assert_eq!(g.len(), 0);
    }

    /// Matches go-DDS's `TestReplayGuard_ExpiredSeq_AllowedAfterWindow`.
    //fusa:test REQ-SEC-027
    #[test]
    fn expired_seq_allowed_after_window() {
        let g = ReplayGuard::new(Duration::from_millis(50));
        let past = Instant::now() - Duration::from_millis(100);
        let _ = g.check(7, past);

        // The entry should have expired; checking seq 7 with a future ts
        // should succeed.
        let future = Instant::now();
        assert!(g.check(7, future).is_ok());
    }

    /// Matches go-DDS's `TestReplayGuard_DefaultWindow`: a zero window is
    /// replaced with 30s — just verify it constructs and checks without
    /// panicking.
    //fusa:test REQ-SEC-026
    #[test]
    fn default_window() {
        let g = ReplayGuard::new(Duration::ZERO);
        assert!(g.check(1, Instant::now()).is_ok());
    }

    /// Matches go-DDS's `TestReplayGuard_Len_TracksCount`.
    //fusa:test REQ-SEC-027
    #[test]
    fn len_tracks_count() {
        let g = ReplayGuard::new(Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(g.len(), 0);
        let _ = g.check(1, now);
        let _ = g.check(2, now);
        assert_eq!(g.len(), 2);
    }

    /// Matches go-DDS's `TestReplayGuard_Concurrent`.
    //fusa:test REQ-SEC-027
    #[tokio::test]
    async fn concurrent() {
        let g = Arc::new(ReplayGuard::new(Duration::from_secs(1)));
        let now = Instant::now();
        let mut handles = Vec::new();
        for seq in 0u64..20 {
            let g = Arc::clone(&g);
            handles.push(tokio::spawn(async move {
                let _ = g.check(seq, now);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    // -- Additional coverage beyond the ported go-DDS suite -------------

    /// `is_empty` mirrors `len() == 0`, both before and after entries are
    /// recorded — the conventional Rust companion go-DDS's own `Len` has
    /// no equivalent of, added here purely as an API-ergonomics pin, not
    /// a behavioral difference from go-DDS.
    #[test]
    fn is_empty_tracks_len() {
        let g = ReplayGuard::new(Duration::from_secs(30));
        assert!(g.is_empty());
        let _ = g.check(1, Instant::now());
        assert!(!g.is_empty());
    }

    /// A replay that is detected does not overwrite the original recorded
    /// timestamp for `seq` — checking the same `seq` again with a
    /// *different* timestamp still reports a replay (and, since `check`
    /// short-circuits before inserting, `len` stays at one entry for that
    /// `seq`), matching go-DDS's `Check`, which only calls `g.seen[seq] =
    /// ts` on the non-replay path.
    #[test]
    fn replay_does_not_reset_recorded_timestamp() {
        let g = ReplayGuard::new(Duration::from_secs(30));
        let first = Instant::now();
        let _ = g.check(5, first);
        let later = first + Duration::from_millis(1);
        assert_eq!(g.check(5, later), Err(ReplayError));
        assert_eq!(g.len(), 1);
    }

    /// `ReplayGuard` is `Send + Sync` — the compile-time property that
    /// lets it be shared behind an `Arc` across concurrent tokio tasks the
    /// way [`concurrent`] above exercises at runtime. Compiling this test
    /// is itself the proof, mirroring `access_policy_is_send_sync` and
    /// `null_plugin_is_send_sync` in this module tree's other files.
    //fusa:test REQ-SEC-027
    #[test]
    fn replay_guard_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReplayGuard>();
    }

    /// A `ReplayError` renders go-DDS's exact `ErrReplay` message text —
    /// pins the sentinel-error port's `Display` output, the only
    /// user-visible surface a caller matching on this error would see in
    /// a log line.
    #[test]
    fn replay_error_display_matches_go_dds() {
        assert_eq!(
            ReplayError.to_string(),
            "security: replayed sequence number detected"
        );
    }
}
