// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! POSIX-shared-memory-style transport for same-host DDS communication —
//! `ROADMAP.md`'s "Planned — v0.4 — Shared-Memory Transport" milestone.
//!
//! Reference: go-DDS's `shmem` package (`github.com/SoundMatt/go-DDS`,
//! `shmem/shmem.go` + `shmem/loan.go`, 776 LOC combined) — same-host
//! participants exchange samples without going through the full RTPS/UDP
//! stack [`crate::rtps::dds_participant::RtpsUdpParticipant`] provides.
//! Two processes in the same domain on the same topic discover each other
//! through nothing more than a well-known filesystem path (no SPDP/SEDP
//! discovery protocol, unlike `rtps`) and exchange samples with no socket,
//! no wire framing, and none of `rtps`'s network-stack overhead.
//!
//! File layout, by concern (mirrors this crate's established `src/rtps/`
//! file-per-concern convention):
//!
//! - [`pool`] — [`pool::BytePool`], the allocation-free buffer pool
//!   backing [`loan::ShmemLoaningPublisher`]. Direct port of go-DDS's
//!   `pool.BytePool` (`pool/pool.go`).
//! - [`broker`] — the same-process delivery path: one [`broker::Broker`]
//!   shared by every [`participant::ShmemParticipant`] on the same
//!   [`crate::types::Domain`] within this OS process. Structural port of
//!   go-DDS's `shmem.go` "broker" section.
//! - [`ipc`] — the cross-process delivery path: a per-(domain, topic)
//!   rendezvous file, written on every publish and polled by each
//!   subscriber. See that module's own doc comment for the two
//!   deliberate, fully-documented deviations from go-DDS's own
//!   `shmem.go` this crate makes and why (no Unix-domain-socket
//!   notification — cross-platform CI; no `mmap` — REQ-ASIL-002/
//!   REQ-MEM-001's zero-`unsafe` bar), and for how same-process
//!   double-delivery (a real, documented behavior of go-DDS's own
//!   reference — see that module's doc comment) is avoided here rather
//!   than merely tolerated.
//! - [`participant`] — [`participant::ShmemParticipant`] (`ROADMAP.md`'s
//!   "Planned — v0.4" first checklist item), wiring `broker` and `ipc`
//!   together behind [`crate::participant::Participant`]/
//!   [`crate::participant::Publisher`]/[`crate::participant::Subscriber`]
//!   — the same public traits [`crate::mock::MockParticipant`] and
//!   [`crate::rtps::dds_participant::RtpsUdpParticipant`] already
//!   implement, so [`crate::adapt`]/[`crate::relay::Node`] work with it
//!   via `Arc<dyn Participant>` with no changes needed there, and
//!   application code can swap transports at the call site.
//! - [`loan`] — [`loan::ShmemLoaningPublisher`] (`ROADMAP.md`'s "Planned
//!   — v0.4" second checklist item, `LoaningPublisher` trait with
//!   pool-backed zero-copy writes), the go-DDS `loan.go` zero-copy loan
//!   API that Tier 1 sub-phase 9 (`rust-DDS#30`) deliberately deferred to
//!   this milestone "since it's not meaningful without a zero-copy
//!   transport underneath it" — [`participant::ShmemPublisher`] is that
//!   transport. The [`crate::participant::LoaningPublisher`] trait itself
//!   is declared in `src/participant.rs` (extending
//!   [`crate::participant::Publisher`], mirroring go-DDS's own
//!   `dds.LoaningPublisher` placement next to `dds.Publisher` in
//!   `dds.go`) so a future transport can implement it too; this module is
//!   its first implementation.
//!
//! No `unsafe` anywhere in this module tree (REQ-ASIL-002 / REQ-MEM-001,
//! carried forward from the crate-wide constraint, same as every `rtps`
//! sub-phase) — see [`ipc`]'s module doc comment for why this transport
//! does not reach for POSIX `mmap`/`shm_open` despite its name, and how
//! that tracks what go-DDS's own reference implementation actually does
//! (not what its package doc comment claims).

pub mod broker;
pub mod ipc;
pub mod loan;
pub mod participant;
pub mod pool;

pub use loan::ShmemLoaningPublisher;
pub use participant::ShmemParticipant;
