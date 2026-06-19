// Copyright (c) 2026 Matt Jones. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Error types for rust-DDS.
//!
//! Mandatory RELAY sentinels (§5.1) plus DDS-specific variants (§5.4).

use thiserror::Error;

use crate::relay;

/// Unified error type for rust-DDS.
///
/// The four mandatory RELAY sentinel variants (Closed, NotConnected, Timeout,
/// PayloadTooLarge) map 1:1 to `relay::Error`. DDS-specific variants wrap the
/// nearest sentinel via [`Error::as_relay`].
//fusa:req REQ-ERR-001
#[derive(Debug, Error)]
pub enum Error {
    // ── Mandatory sentinels ──────────────────────────────────────────────────
    #[error("relay: closed")]
    Closed,
    #[error("relay: not connected")]
    NotConnected,
    #[error("relay: timeout")]
    Timeout,
    #[error("relay: payload too large")]
    PayloadTooLarge,

    // ── DDS-specific ─────────────────────────────────────────────────────────
    /// Domain value outside the valid 0–232 range.
    #[error("dds: domain out of range [0, 232]")]
    DomainOutOfRange,

    /// Empty or invalid topic name.
    #[error("dds: topic name must not be empty")]
    TopicEmpty,

    /// Publisher/subscriber QoS incompatibility.
    #[error("dds: QoS mismatch between publisher and subscriber")]
    QosMismatch,

    /// Sample not delivered before `QoS::deadline` expired.
    #[error("dds: deadline missed")]
    DeadlineMissed,

    /// Sample rejected due to resource limits.
    #[error("dds: sample rejected — resource limits exceeded")]
    SampleRejected,

    /// Resource limit exceeded.
    #[error("dds: resource limit exceeded")]
    ResourceLimits,

    /// Loan buffer unavailable or already committed.
    #[error("dds: loan buffer unavailable or invalid")]
    LoanBuffer,

    /// Topic ACL denied access.
    #[error("dds: access denied by topic ACL")]
    AccessDenied,

    /// Catch-all for internal or unexpected conditions.
    #[error("dds: {0}")]
    Other(String),
}

impl Error {
    /// Map to the nearest mandatory RELAY sentinel, if applicable.
    pub fn as_relay(&self) -> Option<relay::Error> {
        match self {
            Error::Closed | Error::LoanBuffer => Some(relay::Error::Closed),
            Error::NotConnected
            | Error::DomainOutOfRange
            | Error::TopicEmpty
            | Error::QosMismatch => Some(relay::Error::NotConnected),
            Error::Timeout | Error::DeadlineMissed => Some(relay::Error::Timeout),
            Error::PayloadTooLarge | Error::SampleRejected | Error::ResourceLimits => {
                Some(relay::Error::PayloadTooLarge)
            }
            _ => None,
        }
    }
}

impl From<relay::Error> for Error {
    fn from(e: relay::Error) -> Self {
        match e {
            relay::Error::Closed => Error::Closed,
            relay::Error::NotConnected => Error::NotConnected,
            relay::Error::Timeout => Error::Timeout,
            relay::Error::PayloadTooLarge => Error::PayloadTooLarge,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_sentinels_present() {
        let _ = Error::Closed;
        let _ = Error::NotConnected;
        let _ = Error::Timeout;
        let _ = Error::PayloadTooLarge;
    }

    #[test]
    fn as_relay_mapping() {
        assert_eq!(Error::Closed.as_relay(), Some(relay::Error::Closed));
        assert_eq!(
            Error::DomainOutOfRange.as_relay(),
            Some(relay::Error::NotConnected)
        );
        assert_eq!(
            Error::TopicEmpty.as_relay(),
            Some(relay::Error::NotConnected)
        );
        assert_eq!(
            Error::DeadlineMissed.as_relay(),
            Some(relay::Error::Timeout)
        );
        assert_eq!(
            Error::SampleRejected.as_relay(),
            Some(relay::Error::PayloadTooLarge)
        );
        assert_eq!(Error::AccessDenied.as_relay(), None);
    }

    #[test]
    fn from_relay_error() {
        assert!(matches!(Error::from(relay::Error::Closed), Error::Closed));
        assert!(matches!(
            Error::from(relay::Error::NotConnected),
            Error::NotConnected
        ));
        assert!(matches!(Error::from(relay::Error::Timeout), Error::Timeout));
        assert!(matches!(
            Error::from(relay::Error::PayloadTooLarge),
            Error::PayloadTooLarge
        ));
    }
}
