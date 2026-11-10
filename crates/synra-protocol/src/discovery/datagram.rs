use serde::{Deserialize, Serialize};

use crate::handshake::{Feature, PROTOCOL_VERSION};
use crate::ids::DeviceId;
use crate::session::PlatformKind;

/// The marker at the start of a query datagram.
pub const QUERY_MAGIC: &str = "SYNRA_DISCOVERY";

/// The marker at the start of an offline announcement.
pub const OFFLINE_MAGIC: &str = "SYNRA_OFFLINE";

/// The separator between a marker and its JSON body.
pub const MAGIC_SEPARATOR: char = '\n';

/// The largest discovery datagram accepted.
///
/// Bounded because this arrives from the network on a port that is open by design. Eight kilobytes is
/// far more than any legitimate announcement needs and small enough that a flood cannot exhaust a
/// receive buffer.
pub const MAX_DATAGRAM_LEN: usize = 8 * 1024;

/// The longest display name accepted in an announcement.
pub const MAX_ANNOUNCED_NAME: usize = 64;

/// Why a discovery datagram was not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The datagram carries neither marker and is not a response.
    #[error("datagram starts with no known marker")]
    UnknownKind,

    /// The datagram has no separator between the marker and its body.
    #[error("datagram has no separator after its marker")]
    MissingSeparator,

    /// The datagram is larger than [`MAX_DATAGRAM_LEN`].
    #[error("datagram of {len} bytes exceeds the ceiling {max}")]
    TooLarge {
        /// Observed size.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// The body is not valid UTF-8.
    #[error("datagram body is not valid UTF-8")]
    NotUtf8,

    /// The body is not valid JSON, or does not match the expected shape.
    #[error("{kind} body is not readable: {detail}")]
    Malformed {
        /// Which kind of datagram.
        kind: &'static str,
        /// What was wrong.
        detail: String,
    },

    /// The announcement speaks a protocol this build cannot.
    #[error("peer speaks protocol {theirs}, this build speaks {ours}")]
    VersionMismatch {
        /// The version this build speaks.
        ours: u16,
        /// The version announced.
        theirs: u16,
    },

    /// A field has an impossible value.
    #[error("{field} is not usable: {detail}")]
    InvalidField {
        /// Which field.
        field: &'static str,
        /// What was wrong.
        detail: String,
    },
}

/// A device's announcement of itself, as it appears in a query or a response.
///
/// The same type for both, because a response is a query's fields plus what the responder knows
/// about itself. Splitting them would mean two structures that must be kept in step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAnnouncement {
    /// Which device.
    pub device_id: DeviceId,
    /// The name to show a human.
    pub display_name: String,
    /// The protocol version.
    pub protocol: u16,
    /// The port its main connection listens on.
    pub port: u16,
    /// Which platform, when the responder knows.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub platform: Option<PlatformKind>,
    /// The sender's build, when the responder knows.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app_version: Option<String>,
    /// What the device can do, when the responder knows.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub features: Vec<Feature>,
}

impl DeviceAnnouncement {
    /// Checks the announcement is usable.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError`] naming the first problem.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(DiscoveryError::VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: self.protocol,
            });
        }
        if self.device_id.is_nil() {
            return Err(DiscoveryError::InvalidField {
                field: "device_id",
                detail: "must not be nil".to_owned(),
            });
        }
        if self.port == 0 {
            return Err(DiscoveryError::InvalidField {
                field: "port",
                detail: "must not be zero".to_owned(),
            });
        }
        if self.display_name.trim().is_empty() {
            return Err(DiscoveryError::InvalidField {
                field: "display_name",
                detail: "must not be blank".to_owned(),
            });
        }
        if self.display_name.chars().count() > MAX_ANNOUNCED_NAME {
            return Err(DiscoveryError::InvalidField {
                field: "display_name",
                detail: format!("longer than {MAX_ANNOUNCED_NAME} characters"),
            });
        }
        Ok(())
    }
}

/// A query, broadcast to find devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryQuery {
    /// Who is asking. The receiver uses it to ignore its own datagrams and to know who to reply to.
    pub device: DeviceAnnouncement,
}

/// A response, unicast back to the querier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResponse {
    /// Who answered.
    pub device: DeviceAnnouncement,
}

/// An announcement that a device is going away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineAnnouncement {
    /// Which device.
    pub device_id: DeviceId,
    /// When it left, in milliseconds since the epoch.
    pub timestamp: i64,
}

impl OfflineAnnouncement {
    /// Checks the announcement is usable.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::InvalidField`] for a nil device id.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.device_id.is_nil() {
            return Err(DiscoveryError::InvalidField {
                field: "device_id",
                detail: "must not be nil".to_owned(),
            });
        }
        Ok(())
    }
}

/// Any datagram the discovery layer can receive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryDatagram {
    /// A query.
    Query(DiscoveryQuery),
    /// A response.
    Response(DiscoveryResponse),
    /// An offline announcement.
    Offline(OfflineAnnouncement),
}

impl DiscoveryDatagram {
    /// Whether this was recognised at all.
    ///
    /// Always `true` for a value of this type: an unrecognised datagram is an error, not a variant.
    /// Present so a caller can write `if let` symmetry with the parser's error path.
    #[must_use]
    pub const fn is_recognised(&self) -> bool {
        true
    }

    /// The device the datagram concerns.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        match self {
            Self::Query(query) => query.device.device_id,
            Self::Response(response) => response.device.device_id,
            Self::Offline(offline) => offline.device_id,
        }
    }

    /// Parses a datagram received on the discovery port.
    ///
    /// The kind is decided by the marker, and a response is what is left when neither marker is
    /// present: it is a unicast reply to an address that just sent a query, so there is nothing else
    /// it could be.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError`] describing the first problem.
    pub fn parse(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        if bytes.len() > MAX_DATAGRAM_LEN {
            return Err(DiscoveryError::TooLarge {
                len: bytes.len(),
                max: MAX_DATAGRAM_LEN,
            });
        }
        let text = core::str::from_utf8(bytes).map_err(|_| DiscoveryError::NotUtf8)?;

        if let Some(body) = strip_magic(text, QUERY_MAGIC) {
            let announcement: DeviceAnnouncement =
                serde_json::from_str(body).map_err(|error| DiscoveryError::Malformed {
                    kind: "query",
                    detail: error.to_string(),
                })?;
            announcement.validate()?;
            return Ok(Self::Query(DiscoveryQuery {
                device: announcement,
            }));
        }

        if let Some(body) = strip_magic(text, OFFLINE_MAGIC) {
            let offline: OfflineAnnouncement =
                serde_json::from_str(body).map_err(|error| DiscoveryError::Malformed {
                    kind: "offline",
                    detail: error.to_string(),
                })?;
            offline.validate()?;
            return Ok(Self::Offline(offline));
        }

        // A response is bare JSON with no marker.
        let announcement: DeviceAnnouncement =
            serde_json::from_str(text).map_err(|_| DiscoveryError::UnknownKind)?;
        announcement.validate()?;
        Ok(Self::Response(DiscoveryResponse {
            device: announcement,
        }))
    }
}

/// Strips a marker and its separator, returning the body.
///
/// Returns `None` when the marker is absent, so a caller can try the next one.
fn strip_magic<'a>(text: &'a str, magic: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(magic)?;
    // The separator is required: without it, `SYNRA_DISCOVERY` followed directly by JSON would parse
    // as neither and be reported as an unknown datagram rather than a malformed query.
    rest.strip_prefix(MAGIC_SEPARATOR)
}
