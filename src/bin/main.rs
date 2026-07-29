// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! rust-dds CLI — version, capabilities, status, and convert.
//!
//! Output schemas conform to RELAY spec §12 (cli-version, cli-capabilities,
//! cli-status). `convert` implements the §11.2 tooling-conformance driver
//! (§20.3) so `relay interop` can exercise real DDS<->relay.Message
//! conversion instead of skipping it.

use std::io::Read;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

/// Bounds how much of stdin `convert` will read before parsing, so an
/// unbounded/adversarial input stream can't exhaust memory. Matches RELAY's
/// own reference `relay convert` driver's cap, comfortably above spec §16's
/// largest single-message payload.
const MAX_CONVERT_INPUT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "rust-dds",
    about = "DDS publish/subscribe library — RELAY conformant"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the library version (§12.1 cli-version schema).
    Version {
        #[arg(long, default_value = "text")]
        format: Format,
    },
    /// Print declared capabilities as JSON (§12.2 cli-capabilities schema).
    Capabilities,
    /// Print current runtime status (§12.3 cli-status schema).
    Status {
        #[arg(long, default_value = "text")]
        format: Format,
    },
    /// Convert a canonical DDS sample (JSON on stdin) to a relay.Message
    /// (JSON on stdout) — the §11.2 tooling-conformance driver used by
    /// `relay interop` (§20.2/§20.3). Only `--protocol DDS` is implemented;
    /// rust-dds does not adapt any other x-Net protocol.
    Convert {
        #[arg(long)]
        protocol: String,
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

// §12.1 cli-version — required: tool, version, spec_version, language, runtime.
// additionalProperties: false; relay_spec_version is NOT a valid field.
//fusa:req REQ-RELAY-004
//fusa:req REQ-DO-005
#[derive(Serialize)]
struct VersionOutput {
    tool: &'static str,
    protocol: &'static str,
    protocol_int: i32,
    version: &'static str,
    spec_version: &'static str,
    language: &'static str,
    runtime: &'static str,
}

// §12.2 cli-capabilities — required: kind, tool, version, spec_version,
// commands, transports, features, interfaces, optional_interfaces, adapt.
// additionalProperties: false.
//fusa:req REQ-RELAY-004
#[derive(Serialize)]
struct Capabilities {
    kind: &'static str,
    tool: &'static str,
    protocol: &'static str,
    protocol_int: i32,
    version: &'static str,
    spec_version: &'static str,
    commands: Vec<&'static str>,
    transports: Vec<&'static str>,
    features: Vec<&'static str>,
    interfaces: Vec<&'static str>,
    optional_interfaces: Vec<&'static str>,
    adapt: bool,
}

// §12.3 cli-status — required: tool, version, healthy, connected, endpoint, details.
// additionalProperties: false; "ok" is NOT a valid field.
//fusa:req REQ-RELAY-004
#[derive(Serialize)]
struct Status {
    tool: &'static str,
    protocol: &'static str,
    version: &'static str,
    healthy: bool,
    connected: bool,
    endpoint: &'static str,
    details: serde_json::Value,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Version { format } => {
            let v = VersionOutput {
                tool: "rust-dds",
                protocol: "DDS",
                protocol_int: 2,
                version: env!("CARGO_PKG_VERSION"),
                spec_version: rust_dds::RELAY_SPEC_VERSION,
                language: "rust",
                runtime: env!("RUSTC_VERSION"),
            };
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&v)
                        .expect("VersionOutput serialization is infallible")
                ),
                Format::Text => println!(
                    "rust-dds {} (RELAY spec v{}, protocol: DDS, runtime: {})",
                    v.version, v.spec_version, v.runtime
                ),
            }
        }
        Command::Capabilities => {
            let caps = Capabilities {
                kind: "capabilities",
                tool: "rust-dds",
                protocol: "DDS",
                protocol_int: 2,
                version: env!("CARGO_PKG_VERSION"),
                spec_version: rust_dds::RELAY_SPEC_VERSION,
                commands: vec!["version", "capabilities", "status", "convert"],
                transports: vec!["mock"],
                features: vec![
                    "transient_local",
                    "back_pressure",
                    "writer_guid",
                    "sequence_number",
                ],
                interfaces: vec!["Participant"],
                optional_interfaces: vec![],
                adapt: true,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&caps)
                    .expect("Capabilities serialization is infallible")
            );
        }
        Command::Status { format } => {
            let s = Status {
                tool: "rust-dds",
                protocol: "DDS",
                version: env!("CARGO_PKG_VERSION"),
                healthy: true,
                connected: false,
                endpoint: "",
                details: serde_json::json!({}),
            };
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&s).expect("Status serialization is infallible")
                ),
                Format::Text => println!(
                    "rust-dds {} — healthy: {}, connected: {}",
                    s.version, s.healthy, s.connected
                ),
            }
        }
        Command::Convert { protocol, format } => run_convert(&protocol, &format),
    }
}

/// Implements `convert --protocol P --format json`: reads one canonical
/// `dds.Sample` JSON value from stdin and writes the resulting
/// `relay.Message` as JSON on stdout. Exit `0` converted, `1` invalid input
/// (or unsupported protocol), `2` invalid args — matching RELAY's reference
/// `relay convert` driver (§11.2).
fn run_convert(protocol: &str, format: &str) {
    if format != "json" {
        eprintln!("rust-dds convert: unsupported format {format:?}");
        std::process::exit(2);
    }
    if !protocol.eq_ignore_ascii_case("dds") {
        eprintln!(
            "rust-dds convert: protocol {protocol:?} is not implemented by rust-dds (only DDS)"
        );
        std::process::exit(1);
    }

    let mut input = Vec::new();
    let mut limited = std::io::stdin().take(MAX_CONVERT_INPUT_BYTES + 1);
    if let Err(e) = limited.read_to_end(&mut input) {
        eprintln!("rust-dds convert: read stdin: {e}");
        std::process::exit(1);
    }
    if input.len() as u64 > MAX_CONVERT_INPUT_BYTES {
        eprintln!("rust-dds convert: stdin exceeds {MAX_CONVERT_INPUT_BYTES} byte limit");
        std::process::exit(2);
    }

    let sample: rust_dds::types::Sample = match serde_json::from_slice(&input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rust-dds convert: invalid canonical value: {e}");
            std::process::exit(1);
        }
    };

    let msg = rust_dds::adapt::to_message(&sample);
    println!(
        "{}",
        serde_json::to_string_pretty(&msg).expect("Message serialization is infallible")
    );
}

#[cfg(test)]
mod tests {
    //fusa:test REQ-RELAY-004
    //fusa:test REQ-RELAY-005
    //fusa:test REQ-RELAY-006
    //fusa:test REQ-DO-005
    #[test]
    fn version_output_has_required_fields() {
        let v = super::VersionOutput {
            tool: "rust-dds",
            protocol: "DDS",
            protocol_int: 2,
            version: "0.0.0",
            spec_version: "1.11",
            language: "rust",
            runtime: "rustc test",
        };
        let json = serde_json::to_string(&v).expect("serialization must not fail");
        assert!(json.contains("\"tool\""));
        assert!(json.contains("\"spec_version\""));
        assert!(json.contains("\"language\""));
        assert!(json.contains("\"runtime\""));
        assert!(!json.contains("relay_spec_version"));
    }

    //fusa:test REQ-RELAY-005
    #[test]
    fn capabilities_output_has_required_fields() {
        let caps = super::Capabilities {
            kind: "capabilities",
            tool: "rust-dds",
            protocol: "DDS",
            protocol_int: 2,
            version: "0.0.0",
            spec_version: "1.11",
            commands: vec!["version", "capabilities", "status"],
            transports: vec!["mock"],
            features: vec![],
            interfaces: vec!["Participant"],
            optional_interfaces: vec![],
            adapt: true,
        };
        let json = serde_json::to_string(&caps).expect("serialization must not fail");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"interfaces\""));
        assert!(json.contains("\"optional_interfaces\""));
        assert!(json.contains("\"commands\""));
    }

    //fusa:test REQ-RELAY-006
    #[test]
    fn status_output_has_required_fields() {
        let s = super::Status {
            tool: "rust-dds",
            protocol: "DDS",
            version: "0.0.0",
            healthy: true,
            connected: false,
            endpoint: "",
            details: serde_json::json!({}),
        };
        let json = serde_json::to_string(&s).expect("serialization must not fail");
        assert!(json.contains("\"healthy\""));
        assert!(json.contains("\"connected\""));
        assert!(json.contains("\"endpoint\""));
        assert!(json.contains("\"details\""));
        assert!(!json.contains("\"ok\""));
    }
}
