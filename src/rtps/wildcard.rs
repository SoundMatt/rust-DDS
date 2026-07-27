// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Topic wildcard matching.
//!
//! This is part of Tier 1 sub-phase 9 of the parity build-out plan in
//! `ROADMAP.md` ("Tier 1 — RTPS wire-protocol port" → "Small supporting
//! pieces... topic wildcard matching"). Direct port of go-DDS's
//! `rtps/wildcard.go` (41 LOC): [`topic_matches`] is go-DDS's
//! `TopicMatches`, and the private recursive helper is go-DDS's
//! `matchSlices`. Pure string logic, no I/O, no wire format — nothing here
//! needs byte-exact verification against go-DDS in the CDR sense, but the
//! matching *behavior* is verified against real go-DDS output for a fixed
//! table of pattern/topic pairs (see the `tests` module below).
//!
//! # Wiring
//!
//! [`super::participant::RtpsParticipant::dispatch_to_readers`] calls this
//! function exactly where go-DDS's own `dispatchToReaders` calls
//! `TopicMatches` — matching a concrete writer topic (`topic_filter`)
//! against a (possibly wildcarded) reader topic (`state.topic`) — and
//! nowhere else: go-DDS's `sedp.go` (`registerWriter`/`registerReader`/
//! `handleEndpointAnnounce`) matches topics with plain `==` throughout, no
//! `TopicMatches` call anywhere in that file, so `sedp.rs`'s existing
//! literal-equality endpoint matching is intentionally left as-is here —
//! changing it would not be a faithful port.

/// Reports whether `pattern` (which may contain MQTT-style `+` and `#`
/// wildcards) matches the concrete topic name `topic`.
///
/// Rules (matching go-DDS's `TopicMatches` exactly):
/// - `+` matches exactly one topic level (no slashes).
/// - `#` at the end of a segment matches zero or more remaining levels.
/// - Literal segments must match exactly (case-sensitive).
/// - `"foo/"` and `"foo"` are distinct topics (two levels vs one level).
//fusa:req REQ-RTPS-056
pub fn topic_matches(pattern: &str, topic: &str) -> bool {
    let p_segs: Vec<&str> = pattern.split('/').collect();
    let t_segs: Vec<&str> = topic.split('/').collect();
    match_segments(&p_segs, &t_segs)
}

/// Matches go-DDS's `matchSlices` exactly, including its recursive
/// structure (small, bounded recursion depth — one call per `/`-separated
/// topic level, never attacker-amplifiable beyond the input length, so no
/// REQ-MEM-001 concern despite the recursion).
//fusa:req REQ-RTPS-056
fn match_segments(p_segs: &[&str], t_segs: &[&str]) -> bool {
    let Some((p_head, p_rest)) = p_segs.split_first() else {
        return t_segs.is_empty();
    };
    if *p_head == "#" {
        return true;
    }
    let Some((t_head, t_rest)) = t_segs.split_first() else {
        return false;
    };
    if *p_head == "+" || p_head == t_head {
        return match_segments(p_rest, t_rest);
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed pattern/topic vectors reproduced from go-DDS's real
    /// `TopicMatches` (`github.com/SoundMatt/go-DDS`, `rtps/wildcard.go`) —
    /// go-DDS itself ships no `wildcard_test.go`, so these vectors were
    /// generated from a package-local scratch test file calling the real,
    /// unexported `TopicMatches`/`matchSlices` directly (never committed to
    /// go-DDS, deleted after use):
    ///
    /// ```text
    /// // rtps/zzrepro_wildcard_test.go
    /// package rtps
    ///
    /// import (
    ///     "fmt"
    ///     "testing"
    /// )
    ///
    /// func TestZZReproWildcard(t *testing.T) {
    ///     cases := []struct{ pattern, topic string }{
    ///         {"a/b/c", "a/b/c"},
    ///         {"a/b/c", "a/b/d"},
    ///         {"a/+/c", "a/x/c"},
    ///         {"a/+/c", "a/x/y/c"},
    ///         {"a/#", "a/b/c/d"},
    ///         {"a/#", "a"},
    ///         {"#", "anything/at/all"},
    ///         {"a/+", "a/b"},
    ///         {"a/+", "a/b/c"},
    ///         {"foo/", "foo"},
    ///         {"foo", "foo/"},
    ///         {"+/+/+", "a/b/c"},
    ///         {"a/b/+", "a/b"},
    ///         {"", ""},
    ///         {"a/B/c", "a/b/c"},
    ///     }
    ///     for _, c := range cases {
    ///         fmt.Printf("%-12q %-16q -> %v\n", c.pattern, c.topic,
    ///             TopicMatches(c.pattern, c.topic))
    ///     }
    /// }
    /// ```
    ///
    /// Full run: `go test ./rtps/... -run TestZZReproWildcard -v`
    /// (go-DDS commit 01cbc67 / rust-DDS branch feat/rtps-persist-wildcard).
    /// Output (each line: `pattern topic -> matched`):
    ///
    /// ```text
    /// "a/b/c"      "a/b/c"          -> true
    /// "a/b/c"      "a/b/d"          -> false
    /// "a/+/c"      "a/x/c"          -> true
    /// "a/+/c"      "a/x/y/c"        -> false
    /// "a/#"        "a/b/c/d"        -> true
    /// "a/#"        "a"              -> true
    /// "#"          "anything/at/all" -> true
    /// "a/+"        "a/b"            -> true
    /// "a/+"        "a/b/c"          -> false
    /// "foo/"       "foo"            -> false
    /// "foo"        "foo/"           -> false
    /// "+/+/+"      "a/b/c"          -> true
    /// "a/b/+"      "a/b"            -> false
    /// ""           ""               -> true
    /// "a/B/c"      "a/b/c"          -> false
    /// ```
    //fusa:test REQ-RTPS-056
    #[test]
    fn matches_go_dds_reference_vectors() {
        let cases: &[(&str, &str, bool)] = &[
            ("a/b/c", "a/b/c", true),
            ("a/b/c", "a/b/d", false),
            ("a/+/c", "a/x/c", true),
            ("a/+/c", "a/x/y/c", false),
            ("a/#", "a/b/c/d", true),
            ("a/#", "a", true),
            ("#", "anything/at/all", true),
            ("a/+", "a/b", true),
            ("a/+", "a/b/c", false),
            ("foo/", "foo", false),
            ("foo", "foo/", false),
            ("+/+/+", "a/b/c", true),
            ("a/b/+", "a/b", false),
            ("", "", true),
            ("a/B/c", "a/b/c", false),
        ];
        for (pattern, topic, want) in cases {
            assert_eq!(
                topic_matches(pattern, topic),
                *want,
                "topic_matches({pattern:?}, {topic:?})"
            );
        }
    }

    /// `#` at the very start matches everything, including a completely
    /// unrelated single-level topic.
    //fusa:test REQ-RTPS-056
    #[test]
    fn hash_matches_zero_levels() {
        assert!(topic_matches("#", "x"));
        assert!(topic_matches("#", ""));
    }

    /// `+` never crosses a `/` boundary — it is a single-level wildcard,
    /// not a multi-level one.
    //fusa:test REQ-RTPS-056
    #[test]
    fn plus_is_single_level_only() {
        assert!(!topic_matches("+", "a/b"));
        assert!(topic_matches("+", "a"));
    }

    /// Trailing-slash topics are a distinct (extra, empty-final-segment)
    /// level, not collapsed with the no-trailing-slash form.
    //fusa:test REQ-RTPS-056
    #[test]
    fn trailing_slash_is_a_distinct_level() {
        assert!(!topic_matches("a/b", "a/b/"));
        assert!(!topic_matches("a/b/", "a/b"));
        assert!(topic_matches("a/b/", "a/b/"));
    }

    /// Literal segments are case-sensitive.
    //fusa:test REQ-RTPS-056
    #[test]
    fn literal_segments_are_case_sensitive() {
        assert!(!topic_matches("Square", "square"));
        assert!(topic_matches("Square", "Square"));
    }

    /// A pattern with no wildcards behaves exactly like exact-string
    /// equality — the property `dispatch_to_readers` relies on when it
    /// falls back to a literal `==` check before calling `topic_matches`
    /// (an optimisation, not a correctness dependency: this test pins that
    /// the two are equivalent for wildcard-free patterns).
    //fusa:test REQ-RTPS-056
    #[test]
    fn wildcard_free_pattern_matches_iff_equal() {
        for (pattern, topic) in [
            ("Square", "Square"),
            ("Square", "Circle"),
            ("a/b/c", "a/b/c"),
            ("a/b/c", "a/b"),
        ] {
            assert_eq!(topic_matches(pattern, topic), pattern == topic);
        }
    }
}
