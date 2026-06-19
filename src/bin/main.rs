// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! rust-dds CLI — version, capabilities, and status queries.
//!
//! Required by RELAY spec §11.1 for conformance verification.

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
    /// Print the library version.
    Version {
        #[arg(long, default_value = "text")]
        format: Format,
    },
    /// Print declared capabilities as JSON.
    Capabilities,
    /// Print current runtime status.
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

#[derive(Serialize)]
struct VersionOutput {
    version: &'static str,
    relay_spec_version: &'static str,
    protocol: &'static str,
}

#[derive(Serialize)]
struct Capabilities {
    protocol: &'static str,
    version: &'static str,
    relay_spec_version: &'static str,
    adapt: bool,
    transports: Vec<&'static str>,
    features: Vec<&'static str>,
}

#[derive(Serialize)]
struct Status {
    ok: bool,
    protocol: &'static str,
    version: &'static str,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Version { format } => {
            let v = VersionOutput {
                version: env!("CARGO_PKG_VERSION"),
                relay_spec_version: rust_dds::RELAY_SPEC_VERSION,
                protocol: "DDS",
            };
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Format::Text => println!(
                    "rust-dds {} (RELAY spec v{}, protocol: DDS)",
                    v.version, v.relay_spec_version
                ),
            }
        }
        Command::Capabilities => {
            let caps = Capabilities {
                protocol: "DDS",
                version: env!("CARGO_PKG_VERSION"),
                relay_spec_version: rust_dds::RELAY_SPEC_VERSION,
                adapt: true,
                transports: vec!["mock"],
                features: vec![
                    "transient_local",
                    "back_pressure",
                    "writer_guid",
                    "sequence_number",
                ],
            };
            println!("{}", serde_json::to_string_pretty(&caps).unwrap());
        }
        Command::Status { format } => {
            let s = Status {
                ok: true,
                protocol: "DDS",
                version: env!("CARGO_PKG_VERSION"),
            };
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&s).unwrap()),
                Format::Text => println!("rust-dds {} — ok", s.version),
            }
        }
    }
}
