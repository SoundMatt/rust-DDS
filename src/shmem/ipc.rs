// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Cross-process half of the shmem transport: a per-topic rendezvous file
//! under a well-known directory, written by [`write_sample`] and observed
//! by a polling [`spawn_poller`] task on the reading side.
//!
//! # Deviation from go-DDS's `shmem.go`, and why
//!
//! go-DDS's reference (`shmem.go`) notifies cross-process subscribers by
//! writing the same rendezvous file this module writes, then sending one
//! byte over a Unix-domain datagram socket (`net.ListenUnixgram`/
//! `net.Dial("unixgram", ...)`) so the listener does not have to poll.
//! Two reasons this module does not port that socket step:
//!
//! 1. **Cross-platform CI.** This crate's test matrix
//!    (`.github/workflows/ci.yml`) runs `cargo test --all-features` on
//!    `windows-latest`, not just Linux/macOS. `AF_UNIX` `SOCK_DGRAM`
//!    support on Windows is inconsistent (Windows only gained `AF_UNIX`
//!    stream-socket support in Windows 10 1803+, and Rust's std/tokio do
//!    not expose a portable `SOCK_DGRAM` Unix-socket type on Windows at
//!    all). go-DDS's own CI matrix (`go-DDS/.github/workflows/ci.yml`) runs
//!    `windows-latest` too, but its cross-process notification is
//!    explicitly best-effort there: `NewSubscriber` discards
//!    `newShmListener`'s error (`sub.listener, _ = newShmListener(...)`),
//!    so on a platform where the listener fails to bind, cross-process
//!    delivery silently degrades to "same-process only" rather than
//!    failing loudly. This crate's REQ-ASIL-003 posture (public entry
//!    points do not silently drop a stated capability) prefers a
//!    mechanism that actually works identically on all three CI
//!    platforms over one that is best-effort on one of them.
//! 2. **REQ-ASIL-002/REQ-MEM-001 (no `unsafe` anywhere in this crate).**
//!    True POSIX shared memory (`shm_open`+`mmap`, or a wrapping crate
//!    like `memmap2`/`shared_memory`) requires treating a region another
//!    process can concurrently mutate as a Rust reference, which is
//!    exactly the kind of aliasing the borrow checker cannot verify —
//!    every safe-looking wrapper crate's actual byte-access API is either
//!    an `unsafe fn` or documents the same unchecked-aliasing hazard one
//!    level down. This module (and hence
//!    [`super::participant::ShmemParticipant`]) does not reach for mmap at
//!    all: the "shared-memory" transport's data channel is a plain file —
//!    which, worth noting, is *also* what go-DDS's own `shmem` package
//!    actually does, despite its package doc comment's claim
//!    ("mmap-backed operation is supported on Linux and macOS"): a fresh
//!    clone of `go-DDS/shmem/shmem.go` has no `mmap`/`syscall` import or
//!    call anywhere in the file — `shmPublish`/`readData` are
//!    `os.Create`/`os.Open` plus `io.ReadFull`, ordinary file I/O, the
//!    same category of implementation this module uses. This crate's
//!    "zero unsafe, full stop" bar (every prior `rtps` sub-phase carries
//!    the same `REQ-ASIL-002/REQ-MEM-001` line — see e.g.
//!    `src/rtps/transport.rs`'s own "No `unsafe`" section) makes explicit
//!    what go-DDS's shmem package already quietly does in practice.
//!
//! In place of the socket step, [`spawn_poller`] polls the rendezvous file
//! on a short `tokio::time::interval` (default
//! [`DEFAULT_POLL_INTERVAL`]) — same-host file I/O against a file that is
//! typically backed by a tmpfs-style temp filesystem, so the added latency
//! versus a socket notification is on the order of the poll interval, not
//! disk-seek latency.
//!
//! # Same-process double-delivery — avoided, not just documented
//!
//! Because [`super::participant::ShmemPublisher::write`] delivers to
//! process-local subscribers via [`super::broker::Broker::publish`] *and*
//! writes the rendezvous file (so a subscriber in a different process can
//! see it), a naive cross-process poller running inside the *same*
//! process as the writer would redeliver every sample a second time. This
//! is a real, documented behavior of go-DDS's own reference — its own
//! `shmem_test.go` (`TestSequenceNumber_Shmem`, `TestWriterGUID_Shmem`)
//! explicitly filters out the duplicate cross-process redelivery by
//! checking for a zeroed `SequenceNumber`/`WriterGUID` (go-DDS's
//! `shmListener.loop` sets neither field), rather than preventing it. This
//! module prevents it instead: every write embeds the writing process's
//! [`process_origin_id`] in the rendezvous file (see [`FileHeader`]), and
//! [`spawn_poller`] skips delivering a file update whose `origin_id`
//! matches this process's own — that sample already reached this
//! process's subscribers directly through the broker. A *different*
//! process's writes always have a different `origin_id`, so cross-process
//! delivery is unaffected; and because the full [`crate::types::Sample`]
//! metadata (sequence number, writer GUID, timestamp) is carried in the
//! file, a genuinely cross-process delivery is not degraded to zeroed
//! fields the way go-DDS's is.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::task::JoinHandle;

use crate::participant::SubInner;
use crate::types::{Domain, DurabilityKind, Guid, Sample};

/// Default cadence [`spawn_poller`] checks the rendezvous file at.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Payload length cap enforced on read before allocating a buffer for the
/// declared length — defends against a corrupted length prefix causing an
/// unbounded allocation (REQ-MEM-001), matching the same defensive pattern
/// `src/rtps/persist.rs`'s `MAX_PERSISTED_PAYLOAD_BYTES` already
/// establishes in this crate.
pub const MAX_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;

/// Fixed-size header written before every sample's payload in the
/// rendezvous file. All integers little-endian.
///
/// | Field | Bytes | Meaning |
/// |---|---|---|
/// | `origin_id` | 8 | [`process_origin_id`] of the writing process |
/// | `seq` | 8 | The writer's per-publisher sequence number |
/// | `timestamp_unix_nanos` | 8 | `Sample::timestamp`, as `i64` Unix nanoseconds |
/// | `writer_guid` | 16 | `Sample::writer_guid` |
/// | `payload_len` | 4 | Length of the payload that follows |
const HEADER_LEN: usize = 8 + 8 + 8 + 16 + 4;

/// A random-per-process identifier distinguishing this OS process's own
/// rendezvous-file writes from another process's, so [`spawn_poller`] can
/// skip redelivering a sample this process already delivered in-process
/// via the broker (see this module's doc comment, "Same-process
/// double-delivery").
pub fn process_origin_id() -> u64 {
    static ORIGIN_ID: OnceLock<u64> = OnceLock::new();
    *ORIGIN_ID.get_or_init(rand::random)
}

/// Root directory every rendezvous file lives under —
/// `<tmp>/rust-dds-shmem/`. Unlike go-DDS's `shmDir` constant
/// (`/tmp/godds-shmem`, a Unix-only literal path), this uses
/// [`std::env::temp_dir`] so it resolves correctly on Windows too.
fn root_dir() -> PathBuf {
    std::env::temp_dir().join("rust-dds-shmem")
}

/// Directory holding one topic's rendezvous file(s), scoped by domain.
///
/// Deliberate improvement over go-DDS's `shmTopicDir`, which ignores
/// `Domain` entirely (`shmTopicDir(topic string)` ties the path only to
/// the sanitised topic name) — so in go-DDS, two unrelated processes on
/// *different* DDS domains but the same topic string collide on the same
/// rendezvous file, even though go-DDS's in-process broker map
/// (`sharedBrokers map[dds.Domain]*shmBroker`) *is* correctly keyed by
/// domain. Including `domain` in the path here closes that gap
/// (REQ-SHMEM-006 — domain isolation applies to the cross-process path
/// too, not just the in-process broker).
fn topic_dir(domain: Domain, topic: &str) -> PathBuf {
    let safe: String = topic
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '_',
            other => other,
        })
        .collect();
    root_dir().join(format!("domain-{}", domain.0)).join(safe)
}

fn data_path(domain: Domain, topic: &str) -> PathBuf {
    topic_dir(domain, topic).join("data.bin")
}

/// Serialises `sample` into the [`HEADER_LEN`]-byte header plus payload
/// wire format described on [`HEADER_LEN`].
fn encode(sample: &Sample) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN + sample.payload.len());
    buf.extend_from_slice(&process_origin_id().to_le_bytes());
    buf.extend_from_slice(&sample.sequence_number.to_le_bytes());
    buf.extend_from_slice(
        &sample
            .timestamp
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_le_bytes(),
    );
    buf.extend_from_slice(&sample.writer_guid);
    buf.extend_from_slice(&(sample.payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&sample.payload);
    buf
}

/// Decoded rendezvous-file content: everything [`encode`] wrote, before
/// the topic name (not stored in the file — the poller already knows it
/// from its own subscription) is reattached by the caller.
struct Decoded {
    origin_id: u64,
    seq: u64,
    timestamp_unix_nanos: i64,
    writer_guid: Guid,
    payload: Vec<u8>,
}

/// Errors reading/parsing the rendezvous file. Never surfaced as a panic —
/// [`spawn_poller`] treats every variant as "no update this tick" and
/// tries again next tick, since a torn read here (this process observing
/// the file mid-write) would otherwise be indistinguishable from a
/// legitimate transient race; see [`write_sample`]'s atomic
/// write-then-rename, which makes torn reads structurally impossible on
/// this crate's own writes, but a decode error is still handled
/// defensively for any other content that might occupy this path.
#[derive(Debug)]
enum DecodeError {
    Truncated,
    OversizedPayload,
    Io,
}

fn decode(bytes: &[u8]) -> Result<Decoded, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    let origin_id = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let seq = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let timestamp_unix_nanos = i64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let mut writer_guid = Guid::default();
    writer_guid.copy_from_slice(&bytes[24..40]);
    let payload_len = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(DecodeError::OversizedPayload);
    }
    let payload_len = payload_len as usize;
    if bytes.len() < HEADER_LEN + payload_len {
        return Err(DecodeError::Truncated);
    }
    Ok(Decoded {
        origin_id,
        seq,
        timestamp_unix_nanos,
        writer_guid,
        payload: bytes[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
    })
}

/// Writes `sample` to `topic`'s rendezvous file for `domain`, so any other
/// process's [`spawn_poller`] task for the same (domain, topic) observes
/// it on its next tick.
///
/// Writes to a `.tmp` sibling file first, then [`std::fs::rename`]s it
/// into place — atomic on the same filesystem on every platform this
/// crate targets (POSIX `rename(2)` and Windows' `MoveFileEx` both
/// guarantee the destination is never observed partially written), so a
/// concurrent reader always sees either the previous complete file or the
/// new one, never a torn write. This is a deliberate improvement over
/// go-DDS's `shmPublish`, which performs a plain `os.Create` + two
/// `f.Write` calls with no rename step — a concurrent `readData` in
/// go-DDS *can* observe a torn write.
///
/// Failure is non-fatal by design, matching go-DDS's own `shmPublish`
/// (whose every error is silently swallowed): a rendezvous-file write
/// failure only degrades cross-process delivery for this one sample, and
/// must never fail the publisher's `write()` call itself (which has
/// already, by this point, succeeded for every process-local subscriber
/// via the broker).
//fusa:req REQ-SHMEM-003
pub(super) fn write_sample(domain: Domain, topic: &str, sample: &Sample) {
    let dir = topic_dir(domain, topic);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let tmp_path = dir.join("data.bin.tmp");
    let final_path = dir.join("data.bin");
    let bytes = encode(sample);
    let write_result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&bytes)?;
        f.flush()?;
        Ok(())
    })();
    if write_result.is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp_path, &final_path);
}

fn read_current(path: &Path) -> Result<Decoded, DecodeError> {
    let mut f = std::fs::File::open(path).map_err(|_| DecodeError::Io)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|_| DecodeError::Io)?;
    decode(&bytes)
}

/// Spawns the cross-process polling task for one subscriber.
///
/// Polls `topic`'s rendezvous file for `domain` every `poll_interval`;
/// each tick that finds a `seq` newer than the last one this task
/// delivered, and whose `origin_id` is *not* this process's own (see the
/// module doc comment, "Same-process double-delivery"), pushes the
/// decoded [`Sample`] into `inner`.
///
/// On the first tick, seeds "last delivered seq" from whatever is
/// currently on disk *without* delivering it — except when `durability`
/// is `DurabilityKind::TransientLocal`, in which case a current,
/// different-origin sample is delivered once immediately, matching DDS
/// TransientLocal late-joiner semantics for the cross-process path (a
/// case go-DDS's own `newShmListener` does not handle at all: it only
/// reacts to a socket notification arriving *after* the listener starts,
/// so a go-DDS shmem subscriber started after a remote process's last
/// write never receives that value cross-process — see this module's top
/// doc comment for the same finding applied to `Domain` isolation).
/// Under `DurabilityKind::Volatile`, stale on-disk content from before
/// this subscriber existed is never delivered, matching DDS Volatile
/// semantics.
///
/// Returns the task's [`JoinHandle`] — independently stoppable via
/// `.abort()`, following this crate's established per-subscriber
/// background-task idiom (e.g. `participant::spawn_deadline_watcher`).
//fusa:req REQ-SHMEM-003
//fusa:req REQ-SHMEM-004
pub(super) fn spawn_poller(
    domain: Domain,
    topic: String,
    durability: DurabilityKind,
    inner: Arc<SubInner>,
    poll_interval: Duration,
) -> JoinHandle<()> {
    let path = data_path(domain, &topic);
    let self_origin = process_origin_id();
    tokio::spawn(async move {
        let mut last_seq: u64 = match read_current(&path) {
            Ok(d) if d.origin_id != self_origin && durability == DurabilityKind::TransientLocal => {
                deliver(&inner, &topic, &d);
                d.seq
            }
            Ok(d) => d.seq,
            Err(_) => 0,
        };
        let mut ticker = tokio::time::interval(poll_interval);
        loop {
            ticker.tick().await;
            if inner.closed.load(Ordering::SeqCst) || inner.unsubscribed.load(Ordering::SeqCst) {
                break;
            }
            let Ok(d) = read_current(&path) else {
                continue;
            };
            if d.origin_id == self_origin || d.seq <= last_seq {
                continue;
            }
            last_seq = d.seq;
            deliver(&inner, &topic, &d);
        }
    })
}

fn deliver(inner: &Arc<SubInner>, topic: &str, d: &Decoded) {
    let timestamp = DateTime::<Utc>::from_timestamp_nanos(d.timestamp_unix_nanos);
    inner.push(Sample {
        topic: topic.to_string(),
        payload: d.payload.clone(),
        timestamp,
        sequence_number: d.seq,
        writer_guid: d.writer_guid,
    });
}

/// A process-local counter used only by tests to keep concurrently-running
/// tests' rendezvous directories from colliding on shared topic names.
#[cfg(test)]
static TEST_TOPIC_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(super) fn unique_test_topic(prefix: &str) -> String {
    format!("{prefix}-{}", TEST_TOPIC_SEQ.fetch_add(1, Ordering::SeqCst))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::BackPressurePolicy;

    fn sample(topic: &str, seq: u64, payload: &[u8]) -> Sample {
        Sample {
            topic: topic.to_string(),
            payload: payload.to_vec(),
            timestamp: Utc::now(),
            sequence_number: seq,
            writer_guid: [7u8; 16],
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let s = sample("t/rt", 42, b"hello");
        let bytes = encode(&s);
        let d = decode(&bytes).unwrap();
        assert_eq!(d.origin_id, process_origin_id());
        assert_eq!(d.seq, 42);
        assert_eq!(d.writer_guid, [7u8; 16]);
        assert_eq!(d.payload, b"hello");
    }

    #[test]
    fn decode_rejects_truncated_header() {
        assert!(matches!(decode(&[0u8; 4]), Err(DecodeError::Truncated)));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let s = sample("t/short", 1, b"0123456789");
        let mut bytes = encode(&s);
        bytes.truncate(bytes.len() - 3);
        assert!(matches!(decode(&bytes), Err(DecodeError::Truncated)));
    }

    #[test]
    fn decode_rejects_oversized_payload_len() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[40..44].copy_from_slice(&(MAX_PAYLOAD_BYTES + 1).to_le_bytes());
        assert!(matches!(decode(&bytes), Err(DecodeError::OversizedPayload)));
    }

    #[test]
    fn domain_included_in_rendezvous_path() {
        let p0 = data_path(Domain(1), "same/topic");
        let p1 = data_path(Domain(2), "same/topic");
        assert_ne!(
            p0, p1,
            "different domains must use different rendezvous files"
        );
    }

    #[test]
    fn topic_sanitisation_matches_persist_rs_convention() {
        let p = topic_dir(Domain(0), "a/b\\c:d");
        assert!(p.to_string_lossy().contains("a_b_c_d"));
    }

    #[tokio::test]
    async fn write_then_read_current_round_trip() {
        let domain = Domain(90);
        let topic = unique_test_topic("t/write-read");
        let s = sample(&topic, 5, b"payload");
        write_sample(domain, &topic, &s);
        let d = read_current(&data_path(domain, &topic)).unwrap();
        assert_eq!(d.seq, 5);
        assert_eq!(d.payload, b"payload");
    }

    //fusa:test REQ-SHMEM-003
    #[tokio::test]
    async fn poller_skips_own_origin_and_delivers_other_origin() {
        let domain = Domain(91);
        let topic = unique_test_topic("t/origin");
        let inner = Arc::new(SubInner::new(8, BackPressurePolicy::DropNewest));

        // Simulate this process's own write landing on disk before the
        // poller starts — the poller must not redeliver it.
        write_sample(domain, &topic, &sample(&topic, 1, b"own-write"));

        let handle = spawn_poller(
            domain,
            topic.clone(),
            DurabilityKind::Volatile,
            inner.clone(),
            Duration::from_millis(5),
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            inner.pop().is_none(),
            "same-origin rendezvous write must not be redelivered"
        );

        // Now simulate a different process's write by forging a different
        // origin_id directly into the file.
        let mut foreign = encode(&sample(&topic, 2, b"foreign-write"));
        foreign[0..8].copy_from_slice(&(process_origin_id().wrapping_add(1)).to_le_bytes());
        let dir = topic_dir(domain, &topic);
        std::fs::write(dir.join("data.bin"), &foreign).unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;
        let got = inner.pop().expect("foreign-origin write must be delivered");
        assert_eq!(got.payload, b"foreign-write");
        handle.abort();
    }

    //fusa:test REQ-SHMEM-004
    #[tokio::test]
    async fn transient_local_poller_delivers_existing_foreign_value_once() {
        let domain = Domain(92);
        let topic = unique_test_topic("t/tl-poller");
        let mut foreign = encode(&sample(&topic, 9, b"late-joiner-value"));
        foreign[0..8].copy_from_slice(&(process_origin_id().wrapping_add(1)).to_le_bytes());
        let dir = topic_dir(domain, &topic);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.bin"), &foreign).unwrap();

        let inner = Arc::new(SubInner::new(8, BackPressurePolicy::DropNewest));
        let handle = spawn_poller(
            domain,
            topic,
            DurabilityKind::TransientLocal,
            inner.clone(),
            Duration::from_millis(5),
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        let got = inner
            .pop()
            .expect("TransientLocal late joiner must get the cached value");
        assert_eq!(got.payload, b"late-joiner-value");
        handle.abort();
    }

    //fusa:test REQ-SHMEM-004
    #[tokio::test]
    async fn volatile_poller_does_not_deliver_existing_foreign_value() {
        let domain = Domain(93);
        let topic = unique_test_topic("t/volatile-poller");
        let mut foreign = encode(&sample(&topic, 9, b"stale-value"));
        foreign[0..8].copy_from_slice(&(process_origin_id().wrapping_add(1)).to_le_bytes());
        let dir = topic_dir(domain, &topic);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.bin"), &foreign).unwrap();

        let inner = Arc::new(SubInner::new(8, BackPressurePolicy::DropNewest));
        let handle = spawn_poller(
            domain,
            topic,
            DurabilityKind::Volatile,
            inner.clone(),
            Duration::from_millis(5),
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            inner.pop().is_none(),
            "Volatile subscriber must not receive pre-existing on-disk content"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn poller_stops_after_subscriber_closed() {
        let domain = Domain(94);
        let topic = unique_test_topic("t/poller-close");
        let inner = Arc::new(SubInner::new(8, BackPressurePolicy::DropNewest));
        let handle = spawn_poller(
            domain,
            topic,
            DurabilityKind::Volatile,
            inner.clone(),
            Duration::from_millis(5),
        );
        inner.close();
        tokio::time::timeout(Duration::from_millis(200), handle)
            .await
            .expect("poller task must stop promptly after the subscriber closes")
            .unwrap();
    }
}
