//! Hello messages and refusals exchanged during handshake.

use serde::{Deserialize, Serialize};

use crate::ids::DeviceId;
use crate::session::PlatformKind;

use super::{Feature, PROTOCOL_VERSION, SessionNonce, VersionMismatch};

/// What the dialer sends first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hello {
    /// The protocol version the sender speaks.
    pub protocol: u16,
    /// Which device is dialling.
    pub device_id: DeviceId,
    /// The name to show the user while they decide whether to pair.
    pub display_name: String,
    /// Which platform, so the acceptor can hide what the peer cannot do.
    pub platform: PlatformKind,
    /// The sender's build, for support conversations.
    pub app_version: String,
    /// A fresh value, echoed back by the acceptor.
    pub nonce: SessionNonce,
    /// What the sender can do.
    pub features: Vec<Feature>,
    /// The features without which the sender would rather not connect.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub requires: Vec<Feature>,
    /// The dialer's monotonic handshake counter.
    ///
    /// A counter rather than a timestamp because it needs no clock agreement, and a `Hello` whose
    /// counter is not newer than one already seen is a replay of a recorded connection attempt.
    pub sequence: u64,
    /// Which of the sender's addresses it can be reached on, best first.
    ///
    /// Lets the peer connect back over the fastest available path rather than the one it happened to
    /// be dialled on — a LAN address rather than a relay, once both are on the same network.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub endpoints: Vec<String>,
}

impl Hello {
    /// The longest display name accepted, matching a profile's.
    pub const MAX_DISPLAY_NAME: usize = 64;

    /// The most endpoints a peer may advertise.
    ///
    /// Bounded because this is attacker-controlled input that ends up driving connection attempts:
    /// an unbounded list is an unbounded amount of dialling on the receiver's behalf.
    pub const MAX_ENDPOINTS: usize = 8;

    /// Checks the announcement is well formed and speaks this version.
    ///
    /// # Errors
    ///
    /// [`VersionMismatch`] for a protocol this build cannot speak, or a description of the problem.
    pub fn validate(&self) -> Result<(), HelloError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(HelloError::Version(VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: self.protocol,
            }));
        }
        if self.device_id.is_nil() {
            return Err(HelloError::Malformed("device_id must not be nil"));
        }
        if self.nonce.is_zero() {
            return Err(HelloError::Malformed("nonce must not be zero"));
        }
        if self.endpoints.len() > Self::MAX_ENDPOINTS {
            return Err(HelloError::Malformed("too many endpoints advertised"));
        }
        for feature in &self.requires {
            if !self.features.contains(feature) {
                return Err(HelloError::Malformed(
                    "a required feature must also be among the offered ones",
                ));
            }
        }
        // The name and version rules are the profile's, so they live there rather than being
        // restated here where the two would eventually disagree.
        let profile = crate::session::PeerProfile {
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            platform: self.platform,
            app_version: self.app_version.clone(),
        };
        profile.validate().map_err(HelloError::Malformed)?;
        Ok(())
    }
}

/// Why a `Hello` was not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HelloError {
    /// The peer speaks a protocol this build cannot.
    #[error(transparent)]
    Version(VersionMismatch),

    /// The announcement is not well formed.
    #[error("malformed hello: {0}")]
    Malformed(&'static str),

    /// The peer required something this build cannot do.
    #[error("peer requires {} which this build does not offer", _0.as_str())]
    MissingRequired(Feature),
}

/// Why the acceptor refused the link outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RefusalReason {
    /// The peer speaks a protocol this build cannot.
    ProtocolMismatch,
    /// A required feature is missing.
    MissingRequiredFeature,
    /// The device is blocked by the user.
    Blocked,
    /// The acceptor is already at its connection limit.
    TooManyLinks,
    /// The announcement was not well formed.
    Malformed,
}

impl RefusalReason {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolMismatch => "protocol-mismatch",
            Self::MissingRequiredFeature => "missing-required-feature",
            Self::Blocked => "blocked",
            Self::TooManyLinks => "too-many-links",
            Self::Malformed => "malformed",
        }
    }

    /// Whether trying again could succeed.
    ///
    /// A refusal drives a retry decision, so this is what decides whether the dialer backs off and
    /// tries again or stops and tells the user. Retrying a block is not a transient failure; it is
    /// the user's decision being ignored once a second.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::TooManyLinks)
    }
}

/// What the acceptor sends back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelloAck {
    /// The protocol version the acceptor speaks.
    pub protocol: u16,
    /// The acceptor's device id.
    pub device_id: DeviceId,
    /// The name to show the user.
    pub display_name: String,
    /// Which platform.
    pub platform: PlatformKind,
    /// The acceptor's build.
    pub app_version: String,
    /// The dialer's nonce, echoed so the dialer knows this answers *its* attempt.
    pub nonce: SessionNonce,
    /// What the acceptor can do.
    pub features: Vec<Feature>,
    /// What the acceptor requires.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub requires: Vec<Feature>,
    /// Set when the link is refused; when present, nothing else about this message matters.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refusal: Option<RefusalReason>,
    /// The acceptor's own monotonic handshake counter, for the reverse direction.
    #[serde(default)]
    pub sequence: u64,
    /// Addresses the acceptor can be reached on.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub endpoints: Vec<String>,
}

impl HelloAck {
    /// Builds a refusal, which is a complete answer in itself.
    #[must_use]
    pub fn refuse(
        device_id: DeviceId,
        display_name: impl Into<String>,
        platform: PlatformKind,
        app_version: impl Into<String>,
        nonce: SessionNonce,
        reason: RefusalReason,
    ) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            device_id,
            display_name: display_name.into(),
            platform,
            app_version: app_version.into(),
            nonce,
            features: Vec::new(),
            requires: Vec::new(),
            refusal: Some(reason),
            sequence: 0,
            endpoints: Vec::new(),
        }
    }

    /// Whether the link was accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        self.refusal.is_none()
    }

    /// Checks the reply is usable and answers the attempt we made.
    ///
    /// # Errors
    ///
    /// A description if the nonce does not match, the protocol differs, or the reply is not well
    /// formed.
    pub fn validate(&self, sent_nonce: SessionNonce) -> Result<(), HelloError> {
        // The nonce check comes first. A reply to a different attempt must not be able to reach any
        // other conclusion, including "the peer refused us".
        if self.nonce != sent_nonce {
            return Err(HelloError::Malformed(
                "the reply echoes a different nonce, so it answers a different attempt",
            ));
        }
        if self.protocol != PROTOCOL_VERSION {
            return Err(HelloError::Version(VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: self.protocol,
            }));
        }
        if let Some(refusal) = self.refusal {
            return match refusal {
                RefusalReason::ProtocolMismatch => Err(HelloError::Version(VersionMismatch {
                    ours: PROTOCOL_VERSION,
                    theirs: self.protocol,
                })),
                _ => Err(HelloError::Malformed("the peer refused the link")),
            };
        }
        if self.device_id.is_nil() {
            return Err(HelloError::Malformed("device_id must not be nil"));
        }
        if self.display_name.trim().is_empty() {
            return Err(HelloError::Malformed("display_name must not be blank"));
        }
        for feature in &self.requires {
            if !self.features.contains(feature) {
                return Err(HelloError::Malformed(
                    "a required feature must also be among the offered ones",
                ));
            }
        }
        Ok(())
    }
}


