// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! [`AccessPolicy`] — a topic-level read/write access control list.
//!
//! Direct port of go-DDS's `security.AccessPolicy`
//! (`github.com/SoundMatt/go-DDS`, `security/access.go`). go-DDS's own doc
//! comment for the type states the property this port preserves exactly:
//! "`AccessPolicy` enforces topic-level read/write permissions. Rules are
//! evaluated in order; the first matching rule wins. A topic that matches
//! no rule is denied all access."
//!
//! This is `ROADMAP.md`'s "Planned — v0.5 — Security (Tier 2)" fourth
//! checklist item ("Topic ACL (`AccessPolicy`)"). Unlike [`super::plugin`],
//! [`super::hmac`], and [`super::aes_gcm`] above, `AccessPolicy` does not
//! implement [`super::plugin::SecurityPlugin`] — it is a separate
//! authorization mechanism (which participants/writers/readers may
//! publish/subscribe to which topics), not a payload-seal/open transform.
//! go-DDS's own `security` package keeps the two orthogonal for the same
//! reason: an `AccessPolicy` check and a `SecurityPlugin` seal/open call
//! are independent decisions a caller makes about the same outbound or
//! inbound sample. As with the other three landed items in this module
//! tree, wiring `AccessPolicy` checks into
//! `crate::rtps::participant::RtpsParticipant`'s write/receive paths is
//! deferred until a concrete caller need arises — this item is scoped to
//! the ACL mechanism itself.
//!
//! # Pattern syntax
//!
//! go-DDS's `AccessPolicy` matches topic names against each rule's
//! `Pattern` field using Go stdlib's [`path.Match`][go-path-match] shell-
//! glob semantics — *not* a DDS-style content-filter expression, and *not*
//! a regular expression. This port implements that exact algorithm (ported
//! from `$GOROOT/src/path/match.go`, not reimplemented from the one-
//! paragraph doc-comment summary, so that pattern/name pairs Go's stdlib
//! would classify as a malformed pattern are classified identically here):
//!
//! - `*` matches any sequence of non-`/` bytes (stops at a path segment
//!   boundary — `vehicle/*` matches `vehicle/speed` but not
//!   `vehicle/engine/rpm`).
//! - `?` matches any single non-`/` byte.
//! - `[abc]` matches any one of the listed bytes; `[a-c]` matches a byte
//!   in that inclusive range; `[^abc]` negates the class. An empty class
//!   (`[]`), an unterminated class (`[abc`), or a class with a dangling
//!   `-` (`[a-]`, `[-a]`) is a malformed pattern.
//! - `\c` matches the literal byte `c`, including `\*`, `\?`, `\[`, and
//!   `\\` themselves.
//! - Any other byte matches itself literally.
//!
//! A pattern must match the *entire* topic name, not a substring — the
//! same requirement `path.Match` documents. Malformed patterns are never
//! reported to the caller as an error (see [`AccessPolicy::can_read`] /
//! [`AccessPolicy::can_write`]'s docs): matching go-DDS's `allows` method,
//! a rule whose pattern is malformed is silently skipped, as if it were
//! not present in the rule list.
//!
//! [go-path-match]: https://pkg.go.dev/path#Match

/// A bitfield of the operations a [`Rule`] grants on a topic.
///
/// Direct port of go-DDS's `security.Permission` (a `uint8` bitfield) and
/// its three named values.
//fusa:req REQ-SEC-024
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Permission(u8);

impl Permission {
    /// Grants read access (subscribe) to a topic. Matches go-DDS's
    /// `security.PermRead = 1 << 0`.
    pub const READ: Permission = Permission(1 << 0);

    /// Grants write access (publish) to a topic. Matches go-DDS's
    /// `security.PermWrite = 1 << 1`.
    pub const WRITE: Permission = Permission(1 << 1);

    /// Grants both read and write access. Matches go-DDS's
    /// `security.PermReadWrite = PermRead | PermWrite`.
    pub const READ_WRITE: Permission = Permission(Self::READ.0 | Self::WRITE.0);

    /// Returns `true` if `self` includes every bit set in `other` —
    /// go-DDS's inline `r.Allow&perm != 0` bitmask check, extracted into a
    /// named method since Rust does not overload `&` for a custom-newtype
    /// truthiness test the way Go's untyped `!= 0` comparison reads.
    fn contains(self, other: Permission) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for Permission {
    type Output = Permission;

    fn bitor(self, rhs: Permission) -> Permission {
        Permission(self.0 | rhs.0)
    }
}

/// Pairs a topic pattern with the [`Permission`] it grants.
///
/// Direct port of go-DDS's `security.Rule`. See the [module-level
/// docs](self) for the pattern syntax.
///
/// # Examples
///
/// ```
/// use rust_dds::security::{Permission, Rule};
///
/// // Exact match, read-only.
/// let _ = Rule { pattern: "vehicle/speed".to_string(), allow: Permission::READ };
/// // Any single-segment child, read-write.
/// let _ = Rule { pattern: "vehicle/*".to_string(), allow: Permission::READ_WRITE };
/// // Any top-level topic, read-only.
/// let _ = Rule { pattern: "*".to_string(), allow: Permission::READ };
/// ```
//fusa:req REQ-SEC-024
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The topic-name glob pattern this rule matches against — see the
    /// [module-level docs](self) for the exact syntax.
    pub pattern: String,
    /// The permission(s) granted to a topic name this rule matches.
    pub allow: Permission,
}

/// A topic-level access control list: enforces which topics may be read
/// (subscribed) and/or written (published).
///
/// Direct port of go-DDS's `security.AccessPolicy`. Rules are evaluated in
/// declaration order and the **first matching rule wins** — a later rule
/// for the same topic is never consulted once an earlier rule has already
/// matched, even if the earlier rule denies the permission being checked.
/// A topic that matches no rule at all is denied every permission
/// (default-deny, not default-allow).
///
/// # Object safety and concurrency
///
/// `AccessPolicy` is a plain, immutable-after-construction value type (not
/// a trait), so unlike [`super::plugin::SecurityPlugin`] it has no
/// object-safety dimension. It is `Send + Sync` (its only field is a
/// `Vec<Rule>` of `Send + Sync` parts), so a single `AccessPolicy` can be
/// shared via `Arc<AccessPolicy>` across the concurrent tokio tasks this
/// crate's writer/reader/receive loops already use (see
/// `crate::rtps::transport`), mirroring how a `SecurityPlugin` is shared —
/// see the `usable_across_concurrent_tasks` test below.
//fusa:req REQ-SEC-024
//fusa:req REQ-SEC-025
#[derive(Clone, Debug, Default)]
pub struct AccessPolicy {
    rules: Vec<Rule>,
}

impl AccessPolicy {
    /// Creates an `AccessPolicy` from `rules`, preserving their order.
    ///
    /// Matches go-DDS's `NewAccessPolicy(rules ...Rule) *AccessPolicy`:
    /// rules are evaluated in the order given here, first match wins (see
    /// the [type-level docs](AccessPolicy)). Accepts anything iterable of
    /// [`Rule`] — an array literal, a `Vec<Rule>`, or any other
    /// `IntoIterator<Item = Rule>` — rather than requiring a `Vec` up
    /// front, standing in for Go's variadic `...Rule` parameter.
    pub fn new(rules: impl IntoIterator<Item = Rule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
        }
    }

    /// Returns `true` if any rule grants [`Permission::READ`] on `topic`.
    ///
    /// Matches go-DDS's `AccessPolicy.CanRead`. As with go-DDS, a
    /// malformed pattern on a rule is treated as if that rule were absent
    /// (skipped, not surfaced as an error) — see the [module-level
    /// docs](self) for exactly which patterns are malformed.
    pub fn can_read(&self, topic: &str) -> bool {
        self.allows(topic, Permission::READ)
    }

    /// Returns `true` if any rule grants [`Permission::WRITE`] on `topic`.
    ///
    /// Matches go-DDS's `AccessPolicy.CanWrite`. See [`can_read`](
    /// AccessPolicy::can_read)'s docs for the malformed-pattern handling
    /// this method shares.
    pub fn can_write(&self, topic: &str) -> bool {
        self.allows(topic, Permission::WRITE)
    }

    /// Matches go-DDS's unexported `AccessPolicy.allows`: walks `rules` in
    /// order, skipping any rule whose pattern fails to parse, and returns
    /// whether the first rule that *does* match `topic` grants `perm`.
    /// Returns `false` (deny) if no rule matches `topic` at all.
    fn allows(&self, topic: &str, perm: Permission) -> bool {
        for rule in &self.rules {
            match glob_match(rule.pattern.as_bytes(), topic.as_bytes()) {
                Ok(true) => return rule.allow.contains(perm),
                Ok(false) => continue,
                Err(GlobError::BadPattern) => continue, // malformed pattern — skip
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Glob matching — a byte-exact port of Go stdlib's `path.Match`
// (`$GOROOT/src/path/match.go`), the algorithm go-DDS's `AccessPolicy`
// delegates to. Operates on `&[u8]` throughout (not `&str`) precisely
// because Go's implementation slices its pattern/name at arbitrary byte
// offsets while probing `*`-skip positions, which is only ever a valid
// operation on a byte slice, not on a UTF-8-checked `&str` (see
// `scan_star_skip` below) — mirroring how Go's own `string` type imposes
// no UTF-8-boundary discipline on slicing either.
// ---------------------------------------------------------------------------

/// Mirrors Go stdlib's `path.ErrBadPattern`: the only failure mode
/// `glob_match` (and go-DDS's `path.Match`) has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GlobError {
    BadPattern,
}

/// Reports whether `name` matches the shell-style glob `pattern`, using
/// exactly Go stdlib `path.Match`'s algorithm and error conditions. See
/// the [module-level docs](self) for the supported syntax.
fn glob_match(pattern: &[u8], name: &[u8]) -> Result<bool, GlobError> {
    let mut pattern = pattern;
    let mut name = name;
    'pattern: loop {
        if pattern.is_empty() {
            return Ok(name.is_empty());
        }
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            // Trailing `*` matches the rest of `name` unless it contains
            // a `/`.
            return Ok(!name.contains(&b'/'));
        }

        let (t, matched) = match_chunk(chunk, name)?;
        if matched && (t.is_empty() || !pattern.is_empty()) {
            name = t;
            continue 'pattern;
        }

        if star {
            // Look for a match skipping i+1 bytes. Cannot skip a `/`.
            let mut i = 0usize;
            while i < name.len() && name[i] != b'/' {
                let (t2, matched2) = match_chunk(chunk, &name[i + 1..])?;
                if matched2 {
                    // If this is the last chunk, make sure we exhausted
                    // `name`; otherwise keep looking for a longer skip.
                    if pattern.is_empty() && !t2.is_empty() {
                        i += 1;
                        continue;
                    }
                    name = t2;
                    continue 'pattern;
                }
                i += 1;
            }
        }

        // Before returning `false` with no error, check that the
        // remainder of the pattern is syntactically valid — matching
        // go-DDS's/Go stdlib's own behavior of surfacing a malformed
        // pattern even on a branch that would otherwise just report "no
        // match".
        let mut rest_pattern = pattern;
        while !rest_pattern.is_empty() {
            let (_, chunk2, rest2) = scan_chunk(rest_pattern);
            rest_pattern = rest2;
            match_chunk(chunk2, &[])?;
        }
        return Ok(false);
    }
}

/// Splits the next chunk (a non-`*` run, possibly preceded by one or more
/// `*`) off the front of `pattern`. Returns `(star, chunk, rest)`: `star`
/// is `true` if the chunk was preceded by `*`, `chunk` is the run of
/// literal/`?`/`[...]` terms that follows, and `rest` is whatever remains
/// of `pattern` after `chunk` (starting at the next `*`, if any).
///
/// A `\`-escaped byte inside `chunk` (including a `\*`) is skipped over
/// without ending the chunk; a `*` inside an (even unterminated) `[...]`
/// class does not end the chunk either — direct port of Go stdlib's
/// `scanChunk`.
fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while !pattern.is_empty() && pattern[0] == b'*' {
        pattern = &pattern[1..];
        star = true;
    }
    let mut inrange = false;
    let mut i = 0usize;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => inrange = true,
            b']' => inrange = false,
            b'*' if !inrange => return (star, &pattern[..i], &pattern[i..]),
            _ => {}
        }
        i += 1;
    }
    (star, pattern, &[])
}

/// Checks whether `chunk` (a star-free run of literals/`?`/`[...]` terms)
/// matches a prefix of `s`. On success, returns the unconsumed remainder
/// of `s`; direct port of Go stdlib's `matchChunk`.
fn match_chunk<'s>(mut chunk: &[u8], mut s: &'s [u8]) -> Result<(&'s [u8], bool), GlobError> {
    let mut failed = false;
    while !chunk.is_empty() {
        if s.is_empty() {
            failed = true;
        }
        match chunk[0] {
            b'[' => {
                // Character class. The zero rune (`'\0'`) mirrors Go's
                // zero-value `var r rune` when `failed` is already true
                // and the class is parsed purely to validate its syntax,
                // never compared against real input.
                let mut r = '\0';
                if !failed {
                    let (rr, n) = decode_rune(s);
                    r = rr;
                    s = &s[n..];
                }
                chunk = &chunk[1..];

                let mut negated = false;
                if !chunk.is_empty() && chunk[0] == b'^' {
                    negated = true;
                    chunk = &chunk[1..];
                }

                let mut range_matched = false;
                let mut nrange = 0u32;
                loop {
                    if !chunk.is_empty() && chunk[0] == b']' && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if !chunk.is_empty() && chunk[0] == b'-' {
                        let (hi2, rest2) = get_esc(&chunk[1..])?;
                        hi = hi2;
                        chunk = rest2;
                    }
                    range_matched = range_matched || (lo <= r && r <= hi);
                    nrange += 1;
                }
                failed = failed || (range_matched == negated);
            }

            b'?' => {
                if !failed {
                    failed = s[0] == b'/';
                    let (_, n) = decode_rune(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }

            b'\\' => {
                chunk = &chunk[1..];
                if chunk.is_empty() {
                    return Err(GlobError::BadPattern);
                }
                // Fall through to literal-byte matching against the
                // escaped byte, mirroring Go's `fallthrough` from `case
                // '\\'` into `default`.
                if !failed {
                    failed = chunk[0] != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }

            literal => {
                if !failed {
                    failed = literal != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    if failed {
        Ok((&[], false))
    } else {
        Ok((s, true))
    }
}

/// Reads one possibly-`\`-escaped byte-range endpoint from the front of a
/// character class's `chunk`, returning the decoded rune and the
/// unconsumed remainder. Direct port of Go stdlib's `getEsc`.
fn get_esc(mut chunk: &[u8]) -> Result<(char, &[u8]), GlobError> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(GlobError::BadPattern);
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return Err(GlobError::BadPattern);
        }
    }
    let (r, n) = decode_rune(chunk);
    if r == char::REPLACEMENT_CHARACTER && n == 1 {
        return Err(GlobError::BadPattern);
    }
    let nchunk = &chunk[n..];
    if nchunk.is_empty() {
        return Err(GlobError::BadPattern);
    }
    Ok((r, nchunk))
}

/// Decodes the first UTF-8 scalar value from `s`, mirroring Go stdlib's
/// `utf8.DecodeRuneInString`: an empty slice decodes as
/// `(REPLACEMENT_CHARACTER, 0)`, and a malformed encoding at the start of
/// `s` decodes as `(REPLACEMENT_CHARACTER, 1)` — the one-byte "advance by
/// one and try again" recovery Go's decoder uses, which `get_esc`'s
/// `n == 1` check above depends on to distinguish "genuinely malformed
/// byte" from "a validly-encoded literal replacement-character rune".
///
/// Every rust-dds-facing caller of glob matching passes a Rust `&str`
/// (guaranteed valid UTF-8) converted via `.as_bytes()`, so in practice
/// this only ever decodes well-formed UTF-8; the malformed-input branches
/// exist to keep this port's behavior defined byte-for-byte identically to
/// Go's for the arbitrary `&[u8]` this function's own signature accepts
/// (the `[u8]`-vs-`str` design [module-level docs](self) explain).
fn decode_rune(s: &[u8]) -> (char, usize) {
    let Some(&first) = s.first() else {
        return (char::REPLACEMENT_CHARACTER, 0);
    };
    let want_len: usize = if first < 0x80 {
        1
    } else if first & 0xE0 == 0xC0 {
        2
    } else if first & 0xF0 == 0xE0 {
        3
    } else if first & 0xF8 == 0xF0 {
        4
    } else {
        0
    };
    if want_len == 0 || want_len > s.len() {
        return (char::REPLACEMENT_CHARACTER, 1);
    }
    match std::str::from_utf8(&s[..want_len])
        .ok()
        .and_then(|t| t.chars().next())
    {
        Some(c) => (c, want_len),
        None => (char::REPLACEMENT_CHARACTER, 1),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // -- Reference vectors ---------------------------------------------
    //
    // Independently-reproducible reference results, generated by running a
    // small Go program against a fresh clone of go-DDS's `security`
    // package: for each `(pattern, name)` pair, `matched`/`is_err` is
    // exactly what go-DDS's own `path.Match(pattern, name)` call (the
    // stdlib function `AccessPolicy.allows` delegates to) returns.
    // Pinning these keeps this port byte-exact with the reference
    // implementation's glob semantics, not just self-consistent.
    //
    // Regenerate with:
    //
    // ```text
    // matched, err := path.Match(pattern, name)
    // fmt.Println(matched, err != nil)
    // ```
    //fusa:test REQ-SEC-024
    #[test]
    fn matches_go_reference_glob_vectors() {
        struct Vector {
            pattern: &'static str,
            name: &'static str,
            matched: bool,
            is_err: bool,
        }

        let vectors = [
            Vector {
                pattern: "vehicle/speed",
                name: "vehicle/speed",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "vehicle/*",
                name: "vehicle/speed",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "vehicle/*",
                name: "vehicle/engine/rpm",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "*",
                name: "speed",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "*",
                name: "vehicle/speed",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "[bad",
                name: "good",
                matched: false,
                is_err: true,
            },
            Vector {
                pattern: "[abc]",
                name: "a",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "[abc]",
                name: "d",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "[^abc]",
                name: "d",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "[^abc]",
                name: "a",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "[a-c]",
                name: "b",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "[a-c]",
                name: "z",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: r"a\*b",
                name: "a*b",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: r"a\*b",
                name: "axb",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "?ehicle/speed",
                name: "vehicle/speed",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "?ehicle/speed",
                name: "vehicle2/speed",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "**",
                name: "anything",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "**",
                name: "any/thing",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "a**b",
                name: "ab",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "a**b",
                name: "axyzb",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "a**b",
                name: "a/b",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "topic[",
                name: "topic[",
                matched: false,
                is_err: true,
            },
            Vector {
                pattern: "[",
                name: "a",
                matched: false,
                is_err: true,
            },
            Vector {
                pattern: "",
                name: "",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "",
                name: "x",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "abc",
                name: "abc",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "abc",
                name: "abcd",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "a?c",
                name: "a/c",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "vehicle/[sr]*",
                name: "vehicle/speed",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "vehicle/[sr]*",
                name: "vehicle/rpm",
                matched: true,
                is_err: false,
            },
            Vector {
                pattern: "vehicle/[sr]*",
                name: "vehicle/torque",
                matched: false,
                is_err: false,
            },
            Vector {
                pattern: "[]a]",
                name: "a",
                matched: false,
                is_err: true,
            },
            Vector {
                pattern: "[-a]",
                name: "-",
                matched: false,
                is_err: true,
            },
            Vector {
                pattern: "[a-]",
                name: "-",
                matched: false,
                is_err: true,
            },
        ];

        for v in vectors {
            let result = glob_match(v.pattern.as_bytes(), v.name.as_bytes());
            match result {
                Ok(matched) => {
                    assert!(
                        !v.is_err,
                        "pattern {:?} name {:?}: expected an error, got Ok({matched})",
                        v.pattern, v.name
                    );
                    assert_eq!(
                        matched, v.matched,
                        "pattern {:?} name {:?}: matched mismatch",
                        v.pattern, v.name
                    );
                }
                Err(_) => {
                    assert!(
                        v.is_err,
                        "pattern {:?} name {:?}: expected Ok({}), got an error",
                        v.pattern, v.name, v.matched
                    );
                }
            }
        }
    }

    // -- AccessPolicy behavior, ported 1:1 from go-DDS's access_test.go --

    /// Matches go-DDS's `TestAccessPolicy_ExactMatch_Read`.
    //fusa:test REQ-SEC-024
    #[test]
    fn exact_match_read() {
        let p = AccessPolicy::new([Rule {
            pattern: "vehicle/speed".to_string(),
            allow: Permission::READ,
        }]);
        assert!(p.can_read("vehicle/speed"));
        assert!(!p.can_write("vehicle/speed"));
    }

    /// Matches go-DDS's `TestAccessPolicy_ExactMatch_Write`.
    //fusa:test REQ-SEC-024
    #[test]
    fn exact_match_write() {
        let p = AccessPolicy::new([Rule {
            pattern: "actuator/brake".to_string(),
            allow: Permission::WRITE,
        }]);
        assert!(p.can_write("actuator/brake"));
        assert!(!p.can_read("actuator/brake"));
    }

    /// Matches go-DDS's `TestAccessPolicy_ReadWrite`.
    //fusa:test REQ-SEC-024
    #[test]
    fn read_write() {
        let p = AccessPolicy::new([Rule {
            pattern: "sensor/temp".to_string(),
            allow: Permission::READ_WRITE,
        }]);
        assert!(p.can_read("sensor/temp"));
        assert!(p.can_write("sensor/temp"));
    }

    /// Matches go-DDS's `TestAccessPolicy_GlobMatch_SingleSegment`.
    //fusa:test REQ-SEC-024
    #[test]
    fn glob_match_single_segment() {
        let p = AccessPolicy::new([Rule {
            pattern: "vehicle/*".to_string(),
            allow: Permission::READ,
        }]);
        assert!(p.can_read("vehicle/speed"));
        assert!(p.can_read("vehicle/rpm"));
        // Multi-segment child must not match ('*' stops at '/').
        assert!(!p.can_read("vehicle/engine/rpm"));
    }

    /// Matches go-DDS's `TestAccessPolicy_GlobMatch_AllTopLevel`.
    //fusa:test REQ-SEC-024
    #[test]
    fn glob_match_all_top_level() {
        let p = AccessPolicy::new([Rule {
            pattern: "*".to_string(),
            allow: Permission::READ,
        }]);
        assert!(p.can_read("speed"));
        // '*' does not match a topic with a '/' separator.
        assert!(!p.can_read("vehicle/speed"));
    }

    /// Matches go-DDS's `TestAccessPolicy_NoMatch_DenyAll`.
    //fusa:test REQ-SEC-025
    #[test]
    fn no_match_denies_all() {
        let p = AccessPolicy::new([Rule {
            pattern: "allowed/topic".to_string(),
            allow: Permission::READ_WRITE,
        }]);
        assert!(!p.can_read("other/topic"));
        assert!(!p.can_write("other/topic"));
    }

    /// Matches go-DDS's `TestAccessPolicy_EmptyPolicy_DenyAll`.
    //fusa:test REQ-SEC-025
    #[test]
    fn empty_policy_denies_all() {
        let p = AccessPolicy::new([]);
        assert!(!p.can_read("any/topic"));
        assert!(!p.can_write("any/topic"));
    }

    /// Matches go-DDS's `TestAccessPolicy_FirstMatchWins`: a second rule
    /// for the same exact pattern is never reached once an earlier rule
    /// has already matched, even though the earlier rule denies the
    /// permission being asked about.
    //fusa:test REQ-SEC-025
    #[test]
    fn first_match_wins() {
        let p = AccessPolicy::new([
            Rule {
                pattern: "topic".to_string(),
                allow: Permission::READ,
            },
            Rule {
                pattern: "topic".to_string(),
                allow: Permission::WRITE,
            },
        ]);
        assert!(p.can_read("topic"));
        // Second rule is shadowed — write should be denied.
        assert!(!p.can_write("topic"));
    }

    /// Matches go-DDS's `TestAccessPolicy_MalformedPattern_Skipped`: a
    /// rule with a malformed pattern is skipped, not surfaced as an
    /// error and not treated as a match, so evaluation proceeds to the
    /// next rule.
    //fusa:test REQ-SEC-025
    #[test]
    fn malformed_pattern_skipped() {
        let p = AccessPolicy::new([
            Rule {
                pattern: "[bad".to_string(),
                allow: Permission::READ_WRITE,
            },
            Rule {
                pattern: "good".to_string(),
                allow: Permission::READ,
            },
        ]);
        assert!(p.can_read("good"));
        // The malformed rule matches nothing — including its own literal
        // spelling — since it is skipped outright rather than evaluated.
        assert!(!p.can_read("bad"));
        assert!(!p.can_read("[bad"));
    }

    // -- Additional coverage beyond the ported go-DDS suite -------------

    /// `AccessPolicy::new` accepts a `Vec<Rule>` too, not just an array
    /// literal — pinning the `IntoIterator<Item = Rule>` constructor
    /// signature works with the collection callers are most likely to
    /// already have on hand.
    #[test]
    fn new_accepts_vec_of_rules() {
        let rules = vec![Rule {
            pattern: "a".to_string(),
            allow: Permission::READ,
        }];
        let p = AccessPolicy::new(rules);
        assert!(p.can_read("a"));
    }

    /// `Permission::READ_WRITE` is the bitwise union of `READ` and
    /// `WRITE`, both via the named constant and via the `|` operator —
    /// pins go-DDS's `PermReadWrite = PermRead | PermWrite` definition.
    #[test]
    fn read_write_is_union_of_read_and_write() {
        assert_eq!(Permission::READ_WRITE, Permission::READ | Permission::WRITE);
    }

    /// A rule granting only `READ` does not also grant `WRITE`, and vice
    /// versa — the permission bits are independent, not implicitly
    /// escalated.
    #[test]
    fn read_and_write_permissions_are_independent() {
        let p = AccessPolicy::new([Rule {
            pattern: "*".to_string(),
            allow: Permission::READ,
        }]);
        assert!(p.can_read("topic"));
        assert!(!p.can_write("topic"));
    }

    /// Rule declaration order matters even across *different* (not just
    /// identical) patterns: a broader rule declared first shadows a more
    /// specific rule declared after it for any topic the broader rule
    /// also matches — exercising `first match wins` isn't only a same-
    /// pattern-twice special case.
    #[test]
    fn broader_earlier_rule_shadows_narrower_later_rule() {
        let p = AccessPolicy::new([
            Rule {
                pattern: "vehicle/*".to_string(),
                allow: Permission::READ,
            },
            Rule {
                pattern: "vehicle/speed".to_string(),
                allow: Permission::READ_WRITE,
            },
        ]);
        // The first rule (read-only) matches "vehicle/speed" first, so
        // the second, more specific read-write rule is never reached.
        assert!(p.can_read("vehicle/speed"));
        assert!(!p.can_write("vehicle/speed"));
    }

    /// `AccessPolicy` is usable across concurrent tokio tasks via a
    /// shared `Arc<AccessPolicy>`, mirroring the `SecurityPlugin`
    /// implementations' `plugin_usable_across_concurrent_tasks` tests —
    /// the property a real writer and reader task would both depend on
    /// if they held a clone of the same policy `Arc`. Compiling and
    /// passing this test is itself proof of the `Send + Sync` bound.
    //fusa:test REQ-SEC-024
    #[tokio::test]
    async fn usable_across_concurrent_tasks() {
        let policy = Arc::new(AccessPolicy::new([
            Rule {
                pattern: "vehicle/*".to_string(),
                allow: Permission::READ,
            },
            Rule {
                pattern: "actuator/*".to_string(),
                allow: Permission::WRITE,
            },
        ]));
        let mut handles = Vec::new();
        for _ in 0u8..8 {
            let policy = Arc::clone(&policy);
            handles.push(tokio::spawn(async move {
                assert!(policy.can_read("vehicle/speed"));
                assert!(!policy.can_write("vehicle/speed"));
                assert!(policy.can_write("actuator/brake"));
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// Compile-time assertion helper mirroring `plugin::tests`'s
    /// `null_plugin_is_send_sync`, pinning that `AccessPolicy` itself
    /// (not just an `Arc` around it) meets the `Send + Sync` bound.
    //fusa:test REQ-SEC-024
    #[test]
    fn access_policy_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AccessPolicy>();
    }
}
