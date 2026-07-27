// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! TransientLocal durability persistence — disk-backed last-sample cache.
//!
//! This is part of Tier 1 sub-phase 9 of the parity build-out plan in
//! `ROADMAP.md` ("Tier 1 — RTPS wire-protocol port" → "Small supporting
//! pieces... TransientLocal durability persistence hooks"). Direct port of
//! go-DDS's `rtps/persist.go` (87 LOC): [`persist_load`]/[`persist_flush`]/
//! [`persist_path`] are go-DDS's `persistLoad`/`persistFlush`/`persistPath`.
//! This is the RTPS-wire-level durability hook, distinct from this crate's
//! existing in-process `mock::MockParticipant` TransientLocal last-value
//! cache (`src/mock/mod.rs`, v0.1) — that cache never survives a process
//! restart; this one is a file on disk, so a late-joining reader can
//! recover the last sample for a topic even after the writer's process
//! (and this participant's own process, if restarted) is gone.
//!
//! # File format
//!
//! One file per topic, named `topic-<sanitised(T)>.bin` inside the
//! configured directory (topic path separators `/`, `\`, and `:` replaced
//! with `_` so the name is a single flat file — matches go-DDS's
//! `strings.NewReplacer("/", "_", "\\", "_", ":", "_")`). File contents: a
//! 4-byte little-endian length prefix followed by the raw payload bytes,
//! nothing else — matches go-DDS's `binary.LittleEndian.PutUint32` header.
//! Byte-exact against real go-DDS output (see the `tests` module below).
//!
//! # Wiring
//!
//! [`super::participant::RtpsParticipant::new_with_persistent_history`]
//! is the hook: constructing a participant with a persistence directory
//! (go-DDS's `WithPersistentHistory` functional option) makes
//! [`super::participant::RtpsWriter::write`] call [`persist_flush`] after
//! every write (mirroring go-DDS's `persistFlush(w.p.persistDir, w.topic,
//! localCopy)`), and [`super::participant::RtpsParticipant::new_transient_local_reader`]/
//! [`super::participant::RtpsParticipant::new_reliable_transient_local_reader`]
//! call [`persist_load`] as a fallback when no in-memory last sample exists
//! yet for the topic (mirroring go-DDS's `NewSubscriber`'s `else if
//! p.persistDir != ""` branch). Like go-DDS, an empty directory string is a
//! no-op (persistence disabled) and disk errors never propagate to the
//! caller as a panic or a write failure — see each function's own docs.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Payload length cap enforced by [`persist_load`] before allocating a
/// buffer for the declared length — matches go-DDS's `64*1024*1024` guard
/// in `persistLoad`, defending against a corrupted or adversarial length
/// prefix causing an unbounded allocation (REQ-MEM-001).
pub const MAX_PERSISTED_PAYLOAD_BYTES: u32 = 64 * 1024 * 1024;

/// Error returned by [`persist_load`] when the on-disk file cannot be
/// read as a valid persisted sample. Matches go-DDS's `persistLoad`'s
/// `error` return (file-not-found, truncated header/payload, and the
/// oversized-length guard all surface here) — never panics on malformed
/// disk content (REQ-ASIL-003).
#[derive(Debug, Error)]
pub enum PersistLoadError {
    /// The declared payload length exceeds [`MAX_PERSISTED_PAYLOAD_BYTES`].
    #[error("persist: payload {got} bytes exceeds {MAX_PERSISTED_PAYLOAD_BYTES} byte cap")]
    OversizedPayload { got: u32 },
    /// The file could not be opened or read (including "not found", which
    /// is the normal case on first run — matches go-DDS's own doc comment:
    /// "file not found on first run — normal").
    #[error("persist: {0}")]
    Io(#[from] std::io::Error),
}

/// Returns the file path for `topic` inside `dir`. Topic path separators
/// are replaced with `_` so the name is a single flat file. Matches
/// go-DDS's `persistPath` exactly.
///
/// Reference bytes reproduced from go-DDS's actual `rtps` package (real
/// `persistPath`/`persistFlush`/`persistLoad`, not reimplemented). Go
/// reproduction (package-local scratch test file,
/// `rtps/zzrepro_persist_test.go`, never committed to go-DDS, deleted
/// after use) and its exact output are documented on [`persist_flush`].
//fusa:req REQ-RTPS-057
pub fn persist_path(dir: &str, topic: &str) -> PathBuf {
    let safe: String = topic
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '_',
            other => other,
        })
        .collect();
    Path::new(dir).join(format!("topic-{safe}.bin"))
}

/// Reads the last-written sample for `topic` from `dir`, if present.
///
/// Returns `Ok(None)` when `dir` is empty (persistence disabled — the
/// no-op fast path, matches go-DDS's `if dir == "" { return nil, nil }`).
/// Returns `Err` when the file is missing (normal on first run), truncated,
/// or declares a payload length exceeding [`MAX_PERSISTED_PAYLOAD_BYTES`].
/// Returns `Ok(Some(payload))` on success. Matches go-DDS's `persistLoad`
/// exactly, including which failure modes surface as an error vs. as a
/// clean "nothing persisted yet" result.
//fusa:req REQ-RTPS-057
pub fn persist_load(dir: &str, topic: &str) -> Result<Option<Vec<u8>>, PersistLoadError> {
    if dir.is_empty() {
        return Ok(None);
    }
    let path = persist_path(dir, topic);
    let mut f = std::fs::File::open(path)?; // not found on first run — normal
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf)?;
    let length = u32::from_le_bytes(len_buf);
    if length > MAX_PERSISTED_PAYLOAD_BYTES {
        return Err(PersistLoadError::OversizedPayload { got: length });
    }
    let mut buf = vec![0u8; length as usize];
    f.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Writes `payload` to `topic`'s file in `dir`, replacing any previous
/// content.
///
/// A no-op when `dir` is empty (persistence disabled). Any I/O failure
/// (read-only directory, disk full, permission denied, ...) is silently
/// ignored — matches go-DDS's `persistFlush`, whose own doc comment notes
/// this is deliberate so "a write to a read-only directory does not block
/// the caller".
///
/// Reference bytes reproduced from go-DDS's actual `rtps` package (real
/// `persistFlush`/`persistPath`/`persistLoad`, not reimplemented). Go
/// reproduction (package-local scratch test file,
/// `rtps/zzrepro_persist_test.go`, never committed to go-DDS, deleted
/// after use):
///
/// ```text
/// dir := t.TempDir()
/// payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
/// persistFlush(dir, "a/b:c\\d", payload)
/// path := persistPath(dir, "a/b:c\\d")
/// fmt.Printf("path basename=%s\n", path[len(dir)+1:])
/// // -> path basename=topic-a_b_c_d.bin
/// data, _ := os.ReadFile(path)
/// fmt.Printf("filebytes=%x\n", data)
/// // -> filebytes=06000000deadbeef0102
/// fmt.Printf("filelen=%d\n", len(data))
/// // -> filelen=10
/// got, _ := persistLoad(dir, "a/b:c\\d")
/// fmt.Printf("loaded=%x match=%v\n", got, string(got) == string(payload))
/// // -> loaded=deadbeef0102 match=true
/// ```
///
/// Full run: `go test ./rtps/... -run TestZZReproPersist -v`
/// (go-DDS commit 01cbc67 / rust-DDS branch feat/rtps-persist-wildcard).
//fusa:req REQ-RTPS-057
pub fn persist_flush(dir: &str, topic: &str, payload: &[u8]) {
    if dir.is_empty() {
        return;
    }
    let path = persist_path(dir, topic);
    let Ok(mut f) = std::fs::File::create(path) else {
        return; // e.g. read-only directory — silently ignored, matches go-DDS
    };
    let len_bytes = (payload.len() as u32).to_le_bytes();
    let _ = f.write_all(&len_bytes);
    let _ = f.write_all(payload);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `persist_load("", ...)` is the disabled fast-path: `Ok(None)`,
    /// matches go-DDS's `TestPersistLoad_EmptyDir`.
    //fusa:test REQ-RTPS-057
    #[test]
    fn load_with_empty_dir_is_disabled_noop() {
        assert!(matches!(persist_load("", "any/topic"), Ok(None)));
    }

    /// A missing file is an error (normal on first run), not a panic or a
    /// silent `Ok(None)` — matches go-DDS's `TestPersistLoad_FileNotFound`.
    //fusa:test REQ-RTPS-057
    #[test]
    fn load_missing_file_is_an_error() {
        let dir =
            std::env::temp_dir().join(format!("rust-dds-persist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap();
        assert!(persist_load(dir_str, "no/such/topic").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Byte-exact round trip against the file-format documented on
    /// [`persist_flush`] — reproduced from real go-DDS output above.
    //fusa:test REQ-RTPS-057
    #[test]
    fn flush_then_load_roundtrips_and_matches_go_dds_byte_layout() {
        let dir =
            std::env::temp_dir().join(format!("rust-dds-persist-test-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap();
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];

        persist_flush(dir_str, "a/b:c\\d", &payload);

        let path = persist_path(dir_str, "a/b:c\\d");
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            "topic-a_b_c_d.bin"
        );
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(hex::encode(&raw), "06000000deadbeef0102");
        assert_eq!(raw.len(), 10);

        let loaded = persist_load(dir_str, "a/b:c\\d").unwrap();
        assert_eq!(loaded, Some(payload.to_vec()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file too short to contain even the 4-byte length header errors,
    /// not panics — matches go-DDS's `TestPersistLoad_TruncatedHeader`.
    //fusa:test REQ-RTPS-057
    //fusa:test REQ-RTPS-009
    #[test]
    fn load_truncated_header_is_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "rust-dds-persist-test-trunc-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap();
        let path = persist_path(dir_str, "trunc/header");
        std::fs::write(&path, [0x01]).unwrap();

        assert!(persist_load(dir_str, "trunc/header").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A declared length exceeding the 64 MiB cap errors before any
    /// large allocation is attempted (REQ-MEM-001) — matches go-DDS's
    /// `TestPersistLoad_OversizedPayload`.
    //fusa:test REQ-RTPS-057
    //fusa:test REQ-MEM-001
    #[test]
    fn load_oversized_declared_length_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "rust-dds-persist-test-oversz-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap();
        let path = persist_path(dir_str, "oversized/topic");
        let declared: u32 = 65 * 1024 * 1024;
        std::fs::write(&path, declared.to_le_bytes()).unwrap();

        match persist_load(dir_str, "oversized/topic") {
            Err(PersistLoadError::OversizedPayload { got }) => assert_eq!(got, declared),
            other => panic!("expected OversizedPayload, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file with a valid header but a short/missing payload errors —
    /// matches go-DDS's `TestPersistLoad_MissingPayload`.
    //fusa:test REQ-RTPS-057
    #[test]
    fn load_header_with_no_payload_is_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "rust-dds-persist-test-nopayload-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap();
        let path = persist_path(dir_str, "missing/payload");
        std::fs::write(&path, 5u32.to_le_bytes()).unwrap();

        assert!(persist_load(dir_str, "missing/payload").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `persist_flush("", ...)` must not panic — matches go-DDS's
    /// `TestPersistFlush_EmptyDir`.
    //fusa:test REQ-RTPS-057
    #[test]
    fn flush_with_empty_dir_does_not_panic() {
        persist_flush("", "any/topic", b"data");
    }

    /// `persist_flush` into a nonexistent directory must not panic —
    /// matches go-DDS's `TestPersistFlush_InvalidDir`.
    //fusa:test REQ-RTPS-057
    //fusa:test REQ-ASIL-003
    #[test]
    fn flush_into_nonexistent_dir_does_not_panic() {
        persist_flush(
            "/nonexistent/rust-dds-dir-that-should-not-exist",
            "any/topic",
            b"data",
        );
    }

    /// Topic path separators (`/`, `\`, `:`) are all replaced, leaving no
    /// unsafe character in the resulting file name — matches go-DDS's
    /// `TestPersistPath_SpecialChars`.
    //fusa:test REQ-RTPS-057
    #[test]
    fn persist_path_sanitises_all_separator_characters() {
        let path = persist_path("/tmp/data", "a/b:c\\d");
        let base = path.file_name().unwrap().to_str().unwrap();
        for ch in ['/', ':', '\\'] {
            assert!(!base.contains(ch), "unsafe char {ch:?} in {base:?}");
        }
    }
}
