// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! rust-dds CLI — version, capabilities, and status queries.
//!
//! Output schemas conform to RELAY spec §12 (cli-version, cli-capabilities, cli-status).

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

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
                commands: vec!["version", "capabilities", "status"],
                transports: vec!["mock"],
                features: vec![
                    "transient_local",
                    "back_pressure",
                    "writer_guid",
                    "sequence_number",
                ],
                interfaces: vec!["Node"],
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
    }
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
            spec_version: "1.10",
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
            spec_version: "1.10",
            commands: vec!["version", "capabilities", "status"],
            transports: vec!["mock"],
            features: vec![],
            interfaces: vec!["Node"],
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
