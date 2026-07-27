// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Regenerates `tests/fixtures/rtps_go_dds_reference.pcap` — the
//! "pcap-fixture conformance" deliverable of `ROADMAP.md`'s "Interop
//! testing" section. See `src/rtps/pcap.rs`'s module docs for the pcap
//! container format this writes.
//!
//! Run from the repository root:
//!
//! ```text
//! cargo run --example generate_rtps_pcap_fixture > tests/fixtures/rtps_go_dds_reference.pcap
//! ```
//!
//! # Provenance of every recorded message
//!
//! This generator does not invent new RTPS bytes. Every message below is
//! built from this crate's own `rtps::{spdp,sedp,message}` encode
//! functions applied to the exact same fixed reference values
//! (`GuidPrefix` `01..0c`, go-DDS's own vendor ID `0x0127`, unicast ports
//! `17410`/`17411`, topic `"Square"`, writer/reader entity numbers `1`)
//! that earlier Tier 1 sub-phases already independently verified
//! byte-for-byte against go-DDS's real encoder (never reimplemented) via a
//! package-local scratch Go test file, run once and deleted, never
//! committed to go-DDS. Each entry below cites the exact already-merged
//! test (and, transitively, that test's own doc-commented go-DDS
//! reproduction command) whose bytes it reuses unchanged:
//!
//! - **SPDP announcement**: `build_participant_data` + `encode_data_submessage(ENTITYID_SPDP_WRITER, ENTITYID_SPDP_READER, ...)` + `wrap_in_rtps_message`, byte-identical to `spdp.rs::tests::full_spdp_announcement_matches_go_dds_reference` (go-DDS repro: `go test ./rtps/... -run TestZZReproSPDPBytes -v`, go-DDS commit `3329f86`).
//! - **SEDP publication (writer) announcement**: `build_endpoint_data` + `encode_data_submessage(ENTITYID_SEDP_PUB_WRITER, ENTITYID_SEDP_PUB_READER, ...)` + `wrap_in_rtps_message`, byte-identical to `sedp.rs::tests::full_sedp_pub_announcement_matches_go_dds_reference` (go-DDS repro: `go test ./rtps/... -run TestZZReproSEDPBytes -v`, go-DDS commit `d61fd41`).
//! - **SEDP subscription (reader) announcement**: same primitives as the publication announcement above with `ENTITYID_SEDP_SUB_WRITER`/`ENTITYID_SEDP_SUB_READER` and the reader `EndpointInfo` from `sedp.rs::tests::build_endpoint_data_reader_matches_go_dds_reference` (same go-DDS repro run as the publication announcement — one Go program call, `isWriter: false`).
//! - **Plain DATA submessage**: `encode_data_submessage` + `wrap_in_rtps_message` for the fixed payload `[0xDE,0xAD,0xBE,0xEF,0x01,0x02]`, byte-identical to `participant.rs::tests::write_wire_message_matches_go_dds_reference`.
//! - **HEARTBEAT**: `encode_heartbeat_submessage` (submessage bytes byte-identical to `message.rs::tests::encode_heartbeat_submessage_matches_go_dds_reference`, go-DDS repro: `go test ./rtps/... -run TestZZReproReliableBytes -v`, go-DDS commit `e9b36f5`) wrapped via the same already-verified `wrap_in_rtps_message` used above — a composition of two independently-verified pure functions, not a new byte-exactness claim (same reasoning `RtpsWriter::write`'s own doc comment gives for composing already-verified primitives).
//! - **ACKNACK**: `encode_acknack_submessage`, byte-identical to `message.rs::tests::encode_acknack_submessage_matches_go_dds_reference`, wrapped the same way.
//! - **GAP**: `encode_gap_submessage`, byte-identical to `message.rs::tests::encode_gap_submessage_matches_go_dds_reference`, wrapped the same way.
//!
//! `src/rtps/pcap.rs`'s own tests decode this exact fixture back and
//! assert each entry both matches these same hex literals and decodes
//! successfully via this crate's `Header`/`SubmessageIter`/
//! `decode_*_submessage` functions — the regression-catching half of this
//! deliverable.

use std::io::Write;
use std::net::Ipv4Addr;

use rust_dds::rtps::guid::{
    entity_id_for_reader, entity_id_for_writer, EntityId, Guid, GuidPrefix,
    ENTITYID_SEDP_PUB_READER, ENTITYID_SEDP_PUB_WRITER, ENTITYID_SEDP_SUB_READER,
    ENTITYID_SEDP_SUB_WRITER, ENTITYID_SPDP_READER, ENTITYID_SPDP_WRITER, ENTITYID_UNKNOWN,
};
use rust_dds::rtps::message::{
    encode_acknack_submessage, encode_data_submessage, encode_gap_submessage,
    encode_heartbeat_submessage, wrap_in_rtps_message, AckNack, Gap, Header, Heartbeat,
    SequenceNumber, VendorId, PROTOCOL_VERSION_2_3,
};
use rust_dds::rtps::pcap::{encode_pcap_file, PcapPacket};
use rust_dds::rtps::sedp::{build_endpoint_data, EndpointInfo, SedpConfig};
use rust_dds::rtps::spdp::{build_participant_data, SpdpConfig};

/// go-DDS's own vendor ID (`0x0127`), used throughout this crate's
/// existing byte-exact reference tests for parity with real go-DDS output
/// (this crate's own vendor ID, [`rust_dds::rtps::message::VENDOR_ID_RUST_DDS`],
/// is `0x0128` and is deliberately not used here).
const GO_DDS_VENDOR_ID: VendorId = VendorId([0x01, 0x27]);

fn ascending_prefix() -> GuidPrefix {
    let mut b = [0u8; 12];
    for (i, v) in b.iter_mut().enumerate() {
        *v = (i + 1) as u8;
    }
    GuidPrefix(b)
}

fn header(prefix: GuidPrefix) -> Header {
    Header {
        protocol_version: PROTOCOL_VERSION_2_3,
        vendor_id: GO_DDS_VENDOR_ID,
        guid_prefix: prefix,
    }
}

fn main() {
    let prefix = ascending_prefix();
    let writer_eid = entity_id_for_writer(1);
    let reader_eid = entity_id_for_reader(2);
    let sedp_writer_eid = EntityId([0x00, 0x00, 0x01, 0x03]);
    let sedp_reader_eid = EntityId([0x00, 0x00, 0x01, 0x04]);
    let topic = "Square";

    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let announcer_meta_port = 17410u16;
    let announcer_data_port = 17411u16;
    let peer_meta_port = 27410u16;
    let mcast_port = 7400u16; // rtps::transport::meta_multicast_port(0)
    let mcast_addr = Ipv4Addr::new(239, 255, 0, 1); // rtps::transport::SPDP_MULTICAST_ADDR

    let mut packets = Vec::new();
    let mut ts_sec = 1_700_000_000u32;
    let mut next_ts = || {
        ts_sec += 1;
        ts_sec
    };

    // 1. SPDP announcement (multicast).
    {
        // build_participant_data embeds cfg.vendor_id as a PID_VENDOR_ID
        // parameter inside the payload itself (distinct from the RTPS
        // message header's own vendor_id field, set separately via
        // `header()` below) — SpdpConfig::new defaults it to this crate's
        // own VENDOR_ID_RUST_DDS (0x0128), so it must be overridden to
        // GO_DDS_VENDOR_ID here for byte-exact parity, exactly as
        // spdp.rs's own `reference_config()` test helper does.
        let mut cfg = SpdpConfig::new(0, prefix, announcer_meta_port, announcer_data_port);
        cfg.vendor_id = GO_DDS_VENDOR_ID;
        let payload = build_participant_data(&cfg);
        let submsg = encode_data_submessage(
            ENTITYID_SPDP_WRITER,
            ENTITYID_SPDP_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_meta_port,
            dst_addr: mcast_addr,
            dst_port: mcast_port,
            payload: msg,
        });
    }

    // 2. SEDP publication (writer) announcement (unicast, to a peer's meta port).
    {
        let cfg = SedpConfig::new(prefix, announcer_data_port);
        let info = EndpointInfo {
            guid: Guid {
                prefix,
                entity: sedp_writer_eid,
            },
            topic_name: topic.to_string(),
            is_writer: true,
        };
        let payload = build_endpoint_data(&cfg, &info);
        let submsg = encode_data_submessage(
            ENTITYID_SEDP_PUB_WRITER,
            ENTITYID_SEDP_PUB_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_meta_port,
            dst_addr: loopback,
            dst_port: peer_meta_port,
            payload: msg,
        });
    }

    // 3. SEDP subscription (reader) announcement.
    {
        let cfg = SedpConfig::new(prefix, announcer_data_port);
        let info = EndpointInfo {
            guid: Guid {
                prefix,
                entity: sedp_reader_eid,
            },
            topic_name: topic.to_string(),
            is_writer: false,
        };
        let payload = build_endpoint_data(&cfg, &info);
        let submsg = encode_data_submessage(
            ENTITYID_SEDP_SUB_WRITER,
            ENTITYID_SEDP_SUB_READER,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_meta_port,
            dst_addr: loopback,
            dst_port: peer_meta_port,
            payload: msg,
        });
    }

    // 4. Plain DATA submessage (user data path).
    {
        let payload = rust_dds::rtps::cdr::wrap_payload(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
        let submsg = encode_data_submessage(
            writer_eid,
            ENTITYID_UNKNOWN,
            SequenceNumber { high: 0, low: 1 },
            &payload,
        );
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_data_port,
            dst_addr: loopback,
            dst_port: announcer_data_port,
            payload: msg,
        });
    }

    // 5. HEARTBEAT.
    {
        let hb = Heartbeat {
            reader_entity_id: ENTITYID_UNKNOWN,
            writer_entity_id: writer_eid,
            first_sn: SequenceNumber { high: 0, low: 1 },
            last_sn: SequenceNumber { high: 0, low: 5 },
            count: 3,
        };
        let submsg = encode_heartbeat_submessage(hb);
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_data_port,
            dst_addr: loopback,
            dst_port: announcer_data_port,
            payload: msg,
        });
    }

    // 6. ACKNACK.
    {
        let an = AckNack {
            reader_entity_id: reader_eid,
            writer_entity_id: writer_eid,
            base: SequenceNumber { high: 0, low: 3 },
            bitmap: 0b101,
            count: 7,
        };
        let submsg = encode_acknack_submessage(an);
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_data_port,
            dst_addr: loopback,
            dst_port: announcer_data_port,
            payload: msg,
        });
    }

    // 7. GAP.
    {
        let g = Gap {
            reader_entity_id: reader_eid,
            writer_entity_id: writer_eid,
            gap_start: SequenceNumber { high: 0, low: 1 },
            gap_end: SequenceNumber { high: 0, low: 4 },
        };
        let submsg = encode_gap_submessage(g);
        let msg = wrap_in_rtps_message(header(prefix), &submsg);
        packets.push(PcapPacket {
            ts_sec: next_ts(),
            ts_usec: 0,
            src_addr: loopback,
            src_port: announcer_data_port,
            dst_addr: loopback,
            dst_port: announcer_data_port,
            payload: msg,
        });
    }

    let file_bytes = encode_pcap_file(&packets);
    std::io::stdout()
        .write_all(&file_bytes)
        .expect("write pcap bytes to stdout");
}
