# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Report security vulnerabilities by emailing **matt@jellybaby.com**.

Do **not** open a public GitHub issue for security vulnerabilities. Include:

- A description of the vulnerability
- Steps to reproduce or proof-of-concept code
- The version affected
- Suggested severity (Critical / High / Medium / Low)

We aim to acknowledge reports within **48 hours** and provide a fix or mitigation within **14 days** for Critical/High severity issues.

## Security Requirements

This library implements the following cybersecurity controls (see `requirements.json`):

| Req ID | Control |
|--------|---------|
| REQ-SEC-001 | Topic name validation — empty names rejected |
| REQ-SEC-003 | Access denied error variant available for ACL enforcement |
| REQ-SEC-004 | GUID deserialization validated (hex length and format check) |
| REQ-SEC-006 | Dependency CVE audit via `cargo audit` in CI |
| REQ-SEC-007 | Monotonic sequence numbers for replay detection |
| REQ-SEC-009 | Bounded queue allocation — no unbounded growth |
| REQ-SEC-011 | Payload bounds enforced via safe Rust slice operations |
| REQ-SEC-012 | Bounded task spawning — one task per subscription |
| REQ-SEC-014 | `AccessDenied` maps to `relay::Error::NotConnected` |
| REQ-SEC-015 | No silent failures — all errors propagated via `Error` |

## Dependency Audit

`cargo audit` runs on every push and pull request. Any RUSTSEC advisory against a
direct or transitive dependency is treated as a blocking CI failure (REQ-SEC-006).

To run locally:

```sh
cargo install cargo-audit
cargo audit
```

## Scope

This library is the **in-process mock transport only** (v0.1). It does not perform
network I/O, authentication, or cryptography. Future transports (RTPS/UDP, TLS)
will introduce additional security considerations covered by REQ-SEC-002 through
REQ-SEC-015 in `requirements.json`.

## No Unsafe Code

No `unsafe` blocks are used in this library. All memory safety is guaranteed by
the Rust type system and borrow checker (REQ-MEM-001).
