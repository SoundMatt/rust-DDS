# rust-DDS

A Rust library for [DDS](https://www.omg.org/omg-dds-portal/) (Data Distribution Service) publish/subscribe. Works in any domain — IoT, robotics, industrial control, vehicle networks, simulation, and more.

The `Participant` trait is stable. Implementations are swappable without changing application code.

[![CI](https://github.com/SoundMatt/rust-DDS/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/rust-DDS/actions/workflows/ci.yml)

**RELAY spec:** v1.7 · **Language:** Rust 2021 · **MSRV:** 1.75

---

## Modules

| Module | Description | Platform |
|---|---|---|
| `rust_dds` | Core `Participant`, `Publisher`, `Subscriber` traits, `Sample`, `QoS`, `Domain`, `Guid` | All |
| `mock` | In-process broker — zero OS dependencies. Default for development and testing. | All |
| `adapt` | RELAY v1.7 adapter — `adapt()`, `to_message()`, `from_message()` | All |
| `relay` | Local RELAY types (Protocol, Message, Node, Context, SubscriberOptions) | All |

Additional transports (RTPS, shmem, security, WaitSet) are planned — see [ROADMAP.md](ROADMAP.md).

---

## Install

```toml
[dependencies]
rust-dds = { git = "https://github.com/SoundMatt/rust-DDS" }
tokio = { version = "1", features = ["full"] }
```

---

## Quick start

```rust
use std::sync::Arc;
use rust_dds::{
    mock::MockParticipant,
    participant::Participant,
    types::{Domain, QoS},
};

#[tokio::main]
async fn main() {
    let p = MockParticipant::new(Domain(0)).unwrap();

    let (rx, _sub) = p.new_subscriber("sensors/temperature", QoS::default()).await.unwrap();
    let pub_ = p.new_publisher("sensors/temperature", QoS::default()).await.unwrap();

    pub_.write(b"{\"value\": 21.5, \"unit\": \"celsius\"}".to_vec()).await.unwrap();

    let sample = rx.recv().await.unwrap();
    println!("{}", String::from_utf8_lossy(&sample.payload));
}
```

---

## QoS

```rust
use rust_dds::types::{DEFAULT_QOS, RELIABLE_QOS};

// Live data — BestEffort + Volatile (default)
let _pub = p.new_publisher("robot/joint/angles", DEFAULT_QOS.clone()).await.unwrap();

// Commands — Reliable + TransientLocal; late joiners see current state
let _cmd = p.new_publisher("robot/joint/target", RELIABLE_QOS.clone()).await.unwrap();
```

---

## TransientLocal — late-joiner cache

```rust
// Publish before subscriber joins
let pub_ = p.new_publisher("t/state", RELIABLE_QOS.clone()).await.unwrap();
pub_.write(b"current-value".to_vec()).await.unwrap();

// Late joiner immediately receives the cached sample
let (rx, _) = p.new_subscriber("t/state", RELIABLE_QOS.clone()).await.unwrap();
let sample = rx.recv().await.unwrap();
assert_eq!(sample.payload, b"current-value");
```

---

## RELAY adapter

Wrap any `Participant` as a `relay::Node` for protocol-agnostic tooling:

```rust
use std::sync::Arc;
use rust_dds::{adapt, mock::MockParticipant, participant::Participant, types::Domain};
use rust_dds::relay::{with_topic, Context, Message, Protocol};

#[tokio::main]
async fn main() {
    let p = MockParticipant::new(Domain(0)).unwrap();
    let node = adapt(p as Arc<dyn Participant>);

    let mut rx = node.subscribe(with_topic("vehicle/speed")).await.unwrap();

    node.send(
        Context::background(),
        Message::new(Protocol::Dds, "vehicle/speed", b"{\"kmh\":80}".to_vec()),
    )
    .await
    .unwrap();

    let msg = rx.recv().await.unwrap();
    println!("{:?}", msg.payload);
}
```

---

## CLI

```bash
rust-dds version
rust-dds version --format json
rust-dds capabilities
rust-dds status
```

---

## Unsubscribe

Stop delivery without closing the channel — drain buffered samples after unsubscribing:

```rust
let (rx, sub) = p.new_subscriber("t/sensor", QoS::default()).await.unwrap();
sub.unsubscribe();              // no more samples delivered
let s = rx.try_recv();         // drain any already-buffered samples
sub.close().await.unwrap();    // release resources
```

---

## Example use cases

| Domain | Topic example | QoS |
|---|---|---|
| Robotics | `robot/arm/joint_states` | BestEffort (100 Hz sensor) |
| Industrial | `plc/conveyor/speed` | Reliable (actuator command) |
| Vehicle networks | `vehicle/speed` | BestEffort |
| Simulation | `sim/entity/pose` | BestEffort |
| IoT | `building/floor3/temp` | Reliable |

---

## CI

| Job | Platforms | Notes |
|---|---|---|
| `test` | ubuntu, macos, windows × Rust 1.75/stable | Full test suite |
| `lint` | ubuntu | clippy -D warnings, rustfmt check |
| `dco` | PR only | Signed-off-by check |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for per-milestone goals.

**Released — v0.1**

- [x] `Participant`, `Publisher`, `Subscriber` traits
- [x] `MockParticipant` — in-process broker, zero dependencies
- [x] TransientLocal, back-pressure, sequence numbers, writer GUID
- [x] `adapt()` — RELAY v1.7 Node adapter
- [x] CLI binary

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits require a DCO sign-off (`Signed-off-by:`).

---

## License

Mozilla Public License v2.0 — see [LICENSE](LICENSE).
Copyright (c) 2026 Matt Jones.
