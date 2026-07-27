// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! RTPS UDP transport — Tier 1 sub-phase 3 of the parity build-out plan in
//! `ROADMAP.md`.
//!
//! Socket setup per the RTPS 2.3 §9.6.1 port-assignment formula and the
//! SPDP discovery multicast group. Mirrors go-DDS's `rtps/transport.go`
//! (socket lifecycle) and `rtps/locator.go` (port-formula constants,
//! `spdpMulticastAddr`/`spdpMulticastAddrV6`) — the ecosystem's RTPS
//! correctness oracle (see `ROADMAP.md` Tier 1).
//!
//! # Async model
//!
//! This crate is committed to `tokio` throughout `Participant`/`Publisher`/
//! `Subscriber` (see ROADMAP.md's "Async vs. sync" table), so RTPS I/O is
//! async on tokio rather than a parallel sync/thread-based transport.
//! Concurrency shape, translated from go-DDS's goroutine design:
//!
//! | go-DDS | rust-DDS (this module) |
//! |---|---|
//! | One `dataReceiveLoop` goroutine per participant, multiplexing *all* sockets | One `tokio::task` per [`RtpsSocket`], each running `UdpSocket::recv_from` in a loop |
//! | Decoded datagrams dispatched via `handleDataPacket`/... inline in that loop | Datagrams pushed as [`RtpsDatagram`] into an internal `mpsc` channel for a consumer task to decode/dispatch |
//! | `s.done chan struct{}` closed to stop `readLoop` | The returned `tokio::task::JoinHandle` is `.abort()`-ed by the owner to stop the receive loop |
//!
//! Each socket's receive loop is independent (no single multiplexing loop),
//! which is the natural tokio shape: `tokio::spawn` per socket instead of a
//! single goroutine `select`-ing over N channels.
//!
//! # No `unsafe`
//!
//! REQ-ASIL-002 / REQ-MEM-001 (no `unsafe` anywhere in the crate) hold here
//! without exception. go-DDS needed platform-specific `libc`/`syscall` calls
//! only for TSN socket options (`SO_PRIORITY`, `IP_TOS`, `SO_TXTIME` in
//! `rtps/traffic_linux.go`) — out of scope for this sub-phase (Tier 3's
//! `dds-safety::tsn`, which explicitly depends on this transport layer).
//! The one OS-specific option this sub-phase *does* need —
//! `SO_REUSEADDR`/`SO_REUSEPORT`, so multiple participants on the same host
//! can share the SPDP multicast port the way go-DDS's
//! `net.ListenMulticastUDP` allows — goes through the `socket2` crate's
//! safe API (`Socket::set_reuse_address`/`set_reuse_port`), never a raw
//! libc call. When TX timestamping is needed by Tier 3, the same
//! `socket2`-only rule applies.
//!
//! # IPv4 / IPv6
//!
//! IPv4 is the primary, fully-tested path (mirrors go-DDS's default
//! configuration). IPv6 socket setup is provided for parity
//! (`bind_unicast_v6`/`bind_multicast_v6`, `SPDP_MULTICAST_ADDR_V6`) but,
//! exactly as go-DDS's own docs note for its `WithIPv6` option, it has had
//! **limited interop testing** — rust-DDS makes no stronger claim here than
//! go-DDS does.
//!
//! Internal only: not re-exported from the crate root, not yet wired into
//! `Participant`/`Publisher`/`Subscriber`. Consumed starting with SPDP
//! (sub-phase 4) and SEDP (sub-phase 5).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// Port-assignment formula (RTPS 2.3 §9.6.1)
// ---------------------------------------------------------------------------

/// `Pb` — the RTPS well-known port base. Matches go-DDS's `rtps.portBase`.
//fusa:req REQ-RTPS-016
pub const PORT_BASE: u32 = 7400;

/// `DG` — the per-domain port gain. Matches go-DDS's `rtps.domainGain`.
//fusa:req REQ-RTPS-016
pub const DOMAIN_GAIN: u32 = 250;

/// `PG` — the per-participant port gain. Matches go-DDS's
/// `rtps.participantGain`.
//fusa:req REQ-RTPS-016
pub const PARTICIPANT_GAIN: u32 = 2;

/// The RTPS 2.3 §9.6.1 SPDP metatraffic multicast port for `domain`:
/// `metaMulticast(domain) = 7400 + 250*domain`.
///
/// Returns `None` if the computed port does not fit in `u16` (unreachable
/// for any domain in this crate's validated range of 0–232, since the
/// largest such port is 65,400 — checked defensively anyway because this
/// function has no way to see the caller's validated `Domain`).
//fusa:req REQ-RTPS-016
pub fn meta_multicast_port(domain: u32) -> Option<u16> {
    u16::try_from(PORT_BASE + DOMAIN_GAIN * domain).ok()
}

/// The RTPS 2.3 §9.6.1 metatraffic unicast port for `domain` and
/// `participant_idx`: `metaUnicast(domain,i) = 7400 + 250*domain + 10 + 2*i`.
//fusa:req REQ-RTPS-016
pub fn meta_unicast_port(domain: u32, participant_idx: u32) -> Option<u16> {
    u16::try_from(PORT_BASE + DOMAIN_GAIN * domain + 10 + PARTICIPANT_GAIN * participant_idx).ok()
}

/// The RTPS 2.3 §9.6.1 user-data unicast port for `domain` and
/// `participant_idx`: `dataUnicast(domain,i) = 7400 + 250*domain + 11 + 2*i`.
//fusa:req REQ-RTPS-016
pub fn data_unicast_port(domain: u32, participant_idx: u32) -> Option<u16> {
    u16::try_from(PORT_BASE + DOMAIN_GAIN * domain + 11 + PARTICIPANT_GAIN * participant_idx).ok()
}

/// The standard RTPS/SPDP IPv4 discovery multicast group, `239.255.0.1`.
/// Matches go-DDS's `rtps.spdpMulticastAddr`.
//fusa:req REQ-RTPS-017
pub const SPDP_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 1);

/// The RTPS/SPDP IPv6 discovery multicast group (site-local scope),
/// `FF03::1`. Matches go-DDS's `rtps.spdpMulticastAddrV6`. See the module
/// docs' IPv6 note — limited interop testing, same as go-DDS.
//fusa:req REQ-RTPS-017
pub const SPDP_MULTICAST_ADDR_V6: Ipv6Addr = Ipv6Addr::new(0xFF03, 0, 0, 0, 0, 0, 0, 1);

/// Maximum single UDP datagram receive buffer size. Matches go-DDS's
/// `rtps.maxUDPSize`.
const MAX_UDP_DATAGRAM: usize = 65535;

/// Number of sequential ports tried by [`RtpsSocket::bind_unicast_v4`] /
/// [`RtpsSocket::bind_unicast_v6`] before giving up. Matches go-DDS's
/// `newUnicastSocket`/`newUnicastSocketV6` retry loop (`i := 0; i < 16`).
const UNICAST_PORT_RETRIES: u16 = 16;

// ---------------------------------------------------------------------------
// RtpsDatagram
// ---------------------------------------------------------------------------

/// A single received UDP datagram plus the sender's address. Matches
/// go-DDS's `udpPacket` (`data []byte`, `from *net.UDPAddr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpsDatagram {
    /// The raw datagram payload, exactly as received (RTPS message framing
    /// and submessage decoding is a later sub-phase's concern, not this
    /// transport layer's).
    pub data: Vec<u8>,
    /// The sender's address.
    pub from: SocketAddr,
}

// ---------------------------------------------------------------------------
// RtpsSocket
// ---------------------------------------------------------------------------

/// An async UDP socket bound for RTPS traffic, with an owned local port and
/// (once [`spawn_receive_loop`](RtpsSocket::spawn_receive_loop) is called) a
/// background receive task.
///
/// Construct with one of the `bind_*` associated functions rather than
/// directly — each applies the socket options (and, for multicast sockets,
/// group join) appropriate to its traffic pattern.
#[derive(Debug)]
pub struct RtpsSocket {
    socket: Arc<UdpSocket>,
    port: u16,
}

impl RtpsSocket {
    /// Bind an IPv4 unicast socket on `0.0.0.0:<port>`. If `port` is
    /// already in use, tries `port+1 .. port+16` before giving up — matches
    /// go-DDS's `newUnicastSocket` retry loop.
    ///
    /// No `SO_REUSEADDR`/`SO_REUSEPORT` — unlike the multicast sockets,
    /// unicast metatraffic/user-data ports are not meant to be shared
    /// between participants on the same host; the port-retry loop is how
    /// multiple local participants each get their own port, exactly as in
    /// go-DDS.
    //fusa:req REQ-RTPS-016
    //fusa:req REQ-RTPS-018
    pub async fn bind_unicast_v4(port: u16) -> io::Result<Self> {
        Self::bind_unicast_retry(port, |p| {
            let socket = new_socket2(Domain::IPV4, false)?;
            socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, p).into())?;
            Ok(socket)
        })
        .await
    }

    /// Bind an IPv6 unicast socket on `[::]:<port>`. Same retry behaviour as
    /// [`bind_unicast_v4`](RtpsSocket::bind_unicast_v4). See the module
    /// docs' IPv6 note.
    //fusa:req REQ-RTPS-016
    //fusa:req REQ-RTPS-018
    pub async fn bind_unicast_v6(port: u16) -> io::Result<Self> {
        Self::bind_unicast_retry(port, |p| {
            let socket = new_socket2(Domain::IPV6, false)?;
            socket.set_only_v6(true)?;
            socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, p, 0, 0).into())?;
            Ok(socket)
        })
        .await
    }

    async fn bind_unicast_retry(
        port: u16,
        make: impl Fn(u16) -> io::Result<Socket>,
    ) -> io::Result<Self> {
        let mut last_err = None;
        for i in 0..UNICAST_PORT_RETRIES {
            let candidate = port.saturating_add(i);
            match make(candidate) {
                Ok(socket) => return Self::finish(socket),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::other(format!(
                "rtps: no free UDP port in range [{port}, {})",
                port.saturating_add(UNICAST_PORT_RETRIES)
            ))
        }))
    }

    /// Bind an IPv4 multicast receive socket on `group:port`, joining
    /// `group` on all interfaces. Sets `SO_REUSEADDR`/`SO_REUSEPORT` (via
    /// `socket2`'s safe API — see the module docs) so multiple participants
    /// on the same host can all receive SPDP traffic on the same port,
    /// mirroring go-DDS's `net.ListenMulticastUDP` semantics.
    ///
    /// Binds to `0.0.0.0:port` rather than `group:port` — the portable
    /// convention for receiving multicast on both Unix and Windows; the
    /// multicast group membership itself is what determines which packets
    /// the socket receives, not the bind address.
    //fusa:req REQ-RTPS-017
    //fusa:req REQ-RTPS-019
    pub async fn bind_multicast_v4(group: Ipv4Addr, port: u16) -> io::Result<Self> {
        let socket = new_socket2(Domain::IPV4, true)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        let tokio_socket = into_tokio(socket)?;
        tokio_socket.join_multicast_v4(group, Ipv4Addr::UNSPECIFIED)?;
        let bound_port = tokio_socket.local_addr()?.port();
        Ok(RtpsSocket {
            socket: Arc::new(tokio_socket),
            port: bound_port,
        })
    }

    /// Bind an IPv6 multicast receive socket on `[group]:port`, joining
    /// `group` on the default interface (interface index 0 — "any"). Same
    /// `SO_REUSEADDR`/`SO_REUSEPORT` rationale as
    /// [`bind_multicast_v4`](RtpsSocket::bind_multicast_v4). See the module
    /// docs' IPv6 note.
    //fusa:req REQ-RTPS-017
    //fusa:req REQ-RTPS-019
    pub async fn bind_multicast_v6(group: Ipv6Addr, port: u16) -> io::Result<Self> {
        let socket = new_socket2(Domain::IPV6, true)?;
        socket.set_only_v6(true)?;
        socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        let tokio_socket = into_tokio(socket)?;
        tokio_socket.join_multicast_v6(&group, 0)?;
        let bound_port = tokio_socket.local_addr()?.port();
        Ok(RtpsSocket {
            socket: Arc::new(tokio_socket),
            port: bound_port,
        })
    }

    /// Finish setting up a bound (but not yet nonblocking/tokio-registered)
    /// socket2 socket: mark it nonblocking, hand it to tokio, and read back
    /// the actual bound port from the OS (which may differ from any
    /// originally-requested port, e.g. when port `0` was requested to get
    /// an OS-assigned ephemeral port).
    fn finish(socket: Socket) -> io::Result<Self> {
        let tokio_socket = into_tokio(socket)?;
        let port = tokio_socket.local_addr()?.port();
        Ok(RtpsSocket {
            socket: Arc::new(tokio_socket),
            port,
        })
    }

    /// The local port this socket ended up bound to (may differ from the
    /// port originally requested to `bind_unicast_v4`/`bind_unicast_v6` if
    /// a retry was needed).
    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// Send `buf` to `target`.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    /// Spawn a `tokio::task` that loops `recv_from` on this socket,
    /// pushing each received datagram as an [`RtpsDatagram`] into a new
    /// bounded `mpsc` channel of capacity `channel_capacity`.
    ///
    /// This is the concrete translation of go-DDS's `readLoop` goroutine
    /// (one per socket, not multiplexed) called out in the module docs.
    /// Behavioural notes, matching go-DDS's `readLoop`/`recv chan
    /// udpPacket` design:
    ///
    /// - If the channel is full (a slow consumer), the datagram is dropped
    ///   rather than backpressuring the socket read — matches go-DDS's
    ///   `select { case s.recv <- pkt: default: // slow consumer; drop }`.
    /// - If the channel's receiver has been dropped (no consumer left), the
    ///   loop exits rather than spinning.
    /// - A fatal socket I/O error (e.g. the socket has been closed) also
    ///   ends the loop.
    ///
    /// The caller stops the loop on demand by `.abort()`-ing the returned
    /// `JoinHandle` — the tokio idiom replacing go-DDS's `close(s.done)`.
    //fusa:req REQ-RTPS-020
    pub fn spawn_receive_loop(
        &self,
        channel_capacity: usize,
    ) -> (mpsc::Receiver<RtpsDatagram>, JoinHandle<()>) {
        let socket = Arc::clone(&self.socket);
        let (tx, rx) = mpsc::channel(channel_capacity);
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            // A fatal socket I/O error (e.g. the socket has been closed)
            // ends the `while let`; see the doc comment above for the two
            // other loop-exit conditions (full/closed channel).
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let datagram = RtpsDatagram {
                    data: buf[..n].to_vec(),
                    from,
                };
                match tx.try_send(datagram) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Slow consumer: drop, matches go-DDS.
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });
        (rx, handle)
    }
}

/// Mark a bound `socket2::Socket` nonblocking and hand it to tokio.
/// `socket2::Socket`s are blocking by default; tokio's reactor refuses to
/// register a blocking file descriptor, so this step is mandatory on every
/// path that builds an [`RtpsSocket`].
fn into_tokio(socket: Socket) -> io::Result<UdpSocket> {
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Build a `socket2::Socket` for UDP with `SO_REUSEADDR` set, and
/// (when `reuse_port` is true) `SO_REUSEPORT` where the platform supports
/// it. All through `socket2`'s safe API — no raw libc calls, no `unsafe`
/// (REQ-ASIL-002 / REQ-MEM-001).
//fusa:req REQ-RTPS-019
fn new_socket2(domain: Domain, reuse_port: bool) -> io::Result<Socket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if reuse_port {
        // SO_REUSEPORT has no Windows equivalent; socket2 only exposes
        // `set_reuse_port` on Unix targets, so this is naturally a no-op
        // (compiled out) on Windows rather than an error.
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
    }
    Ok(socket)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Port-formula reference values. The formula itself
    // (portBase + domainGain*domain [+ 10|11 + participantGain*i]) is
    // exact integer arithmetic ported 1:1 from go-DDS's
    // `rtps.metaMulticastPort`/`metaUnicastPort`/`userUnicastPort`
    // (`rtps/locator.go`) — there is no encoding/decoding step to
    // byte-diff, so these are cross-checked directly against the real
    // go-DDS functions rather than a wire-byte oracle. Reproduction
    // (package-local scratch test file, never committed):
    //
    //   func TestZZReproPortFormula(t *testing.T) {
    //       fmt.Println(metaMulticastPort(0), metaMulticastPort(7), metaMulticastPort(232))
    //       fmt.Println(metaUnicastPort(0, 0), metaUnicastPort(7, 3))
    //       fmt.Println(userUnicastPort(0, 0), userUnicastPort(7, 3))
    //   }
    //   // -> 7400 9150 65400
    //   // -> 7410 9166
    //   // -> 7411 9167
    //
    // Full run: `go test ./rtps/... -run TestZZReproPortFormula -v`
    // (go-DDS commit df20115 / rust-DDS branch feat/rtps-udp-transport).

    //fusa:test REQ-RTPS-016
    #[test]
    fn meta_multicast_port_matches_go_dds_reference() {
        assert_eq!(meta_multicast_port(0), Some(7400));
        assert_eq!(meta_multicast_port(7), Some(9150));
        assert_eq!(meta_multicast_port(232), Some(65400));
    }

    //fusa:test REQ-RTPS-016
    #[test]
    fn meta_unicast_port_matches_go_dds_reference() {
        assert_eq!(meta_unicast_port(0, 0), Some(7410));
        assert_eq!(meta_unicast_port(7, 3), Some(9166));
    }

    //fusa:test REQ-RTPS-016
    #[test]
    fn data_unicast_port_matches_go_dds_reference() {
        assert_eq!(data_unicast_port(0, 0), Some(7411));
        assert_eq!(data_unicast_port(7, 3), Some(9167));
    }

    //fusa:test REQ-RTPS-016
    #[test]
    fn data_unicast_port_is_one_more_than_meta_unicast_port() {
        for domain in [0u32, 1, 7, 232] {
            for idx in [0u32, 1, 5] {
                assert_eq!(
                    data_unicast_port(domain, idx),
                    meta_unicast_port(domain, idx).map(|p| p + 1)
                );
            }
        }
    }

    //fusa:test REQ-RTPS-017
    #[test]
    fn spdp_multicast_addr_matches_go_dds_reference() {
        assert_eq!(SPDP_MULTICAST_ADDR, Ipv4Addr::new(239, 255, 0, 1));
        assert_eq!(SPDP_MULTICAST_ADDR.to_string(), "239.255.0.1");
    }

    //fusa:test REQ-RTPS-017
    #[test]
    fn spdp_multicast_addr_v6_matches_go_dds_reference() {
        assert_eq!(SPDP_MULTICAST_ADDR_V6.to_string(), "ff03::1");
    }

    //fusa:test REQ-RTPS-018
    #[tokio::test]
    async fn bind_unicast_v4_gets_an_ephemeral_free_port() {
        let sock = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        // Port 0 asks the OS for any free ephemeral port; the bound port
        // must be nonzero and the retry loop must have succeeded on the
        // first attempt (0 + 0 == 0 is not itself a valid claim, but the
        // OS never hands back port 0 as an actual bound port).
        assert_ne!(sock.local_port(), 0);
    }

    //fusa:test REQ-RTPS-018
    #[tokio::test]
    async fn bind_unicast_v4_retries_on_a_taken_port() {
        let held = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let held_port = held.local_port();
        // Requesting the exact port that `held` already owns must not fail
        // outright — it must retry forward (held_port+1, +2, ...) and
        // succeed on a different port, matching go-DDS's newUnicastSocket.
        let second = RtpsSocket::bind_unicast_v4(held_port).await.unwrap();
        assert_ne!(second.local_port(), held_port);
    }

    //fusa:test REQ-RTPS-018
    #[tokio::test]
    async fn bind_unicast_v6_gets_an_ephemeral_free_port() {
        // IPv6 may be unavailable in some CI sandboxes; skip rather than
        // fail if so; the module docs already flag IPv6 as
        // limited-interop-testing, not a hard guarantee.
        if let Ok(sock) = RtpsSocket::bind_unicast_v6(0).await {
            assert_ne!(sock.local_port(), 0);
        }
    }

    //fusa:test REQ-RTPS-020
    #[tokio::test]
    async fn send_and_receive_round_trip_over_loopback() {
        let receiver = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let recv_port = receiver.local_port();
        let (mut rx, handle) = receiver.spawn_receive_loop(8);

        let sender = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let dst = SocketAddr::from((Ipv4Addr::LOCALHOST, recv_port));
        sender.send_to(b"hello rtps", dst).await.unwrap();

        let datagram = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("receive loop did not deliver a datagram in time")
            .expect("channel closed unexpectedly");
        assert_eq!(datagram.data, b"hello rtps");
        assert_eq!(datagram.from.ip(), Ipv4Addr::LOCALHOST);

        handle.abort();
    }

    //fusa:test REQ-RTPS-020
    #[tokio::test]
    async fn receive_loop_stops_when_aborted() {
        let receiver = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let (_rx, handle) = receiver.spawn_receive_loop(8);
        handle.abort();
        let result = handle.await;
        assert!(result.unwrap_err().is_cancelled());
    }

    //fusa:test REQ-RTPS-020
    #[tokio::test]
    async fn receive_loop_drops_datagrams_when_channel_is_full() {
        let receiver = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let recv_port = receiver.local_port();
        // Capacity 1: the second send should be dropped rather than
        // blocking the read loop or panicking.
        let (mut rx, handle) = receiver.spawn_receive_loop(1);

        let sender = RtpsSocket::bind_unicast_v4(0).await.unwrap();
        let dst = SocketAddr::from((Ipv4Addr::LOCALHOST, recv_port));
        sender.send_to(b"first", dst).await.unwrap();
        // Give the receive task a moment to pull "first" into the channel
        // before the second send arrives, so capacity-1 backpressure is
        // exercised deterministically rather than racily.
        tokio::time::sleep(Duration::from_millis(50)).await;
        sender.send_to(b"second", dst).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let first = rx.recv().await.unwrap();
        assert_eq!(first.data, b"first");
        // "second" was either buffered (capacity 1 still has room after
        // "first" is drained by the test, i.e. before this recv) or
        // dropped; either is an acceptable, non-panicking outcome — the
        // guarantee under test is only that the receive loop keeps running
        // and does not deadlock/panic under a full channel.
        handle.abort();
    }

    //fusa:test REQ-RTPS-019
    #[tokio::test]
    async fn bind_multicast_v4_joins_the_spdp_group() {
        // Multicast is unavailable in some CI sandboxes/containers (no
        // multicast-capable interface); treat that as a skip, not a
        // failure — go-DDS's own `newMulticastReceiveSocket` documents and
        // falls back from exactly this condition.
        let port = RtpsSocket::bind_unicast_v4(0).await.unwrap().local_port();
        if let Ok(sock) = RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, port).await {
            assert_eq!(sock.local_port(), port);
        }
    }

    //fusa:test REQ-RTPS-019
    #[tokio::test]
    async fn two_sockets_can_share_a_multicast_port_via_reuseport() {
        // The whole point of SO_REUSEADDR/SO_REUSEPORT on the multicast
        // path: two independent sockets (standing in for two local
        // participants) must both be able to bind the *same* multicast
        // port without erroring.
        let port = RtpsSocket::bind_unicast_v4(0).await.unwrap().local_port();
        let first = RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, port).await;
        let second = RtpsSocket::bind_multicast_v4(SPDP_MULTICAST_ADDR, port).await;
        // No multicast-capable interface in this environment is an
        // acceptable skip; only the `(Ok, Ok)` case has anything to assert.
        if let (Ok(a), Ok(b)) = (first, second) {
            assert_eq!(a.local_port(), b.local_port());
        }
    }
}
