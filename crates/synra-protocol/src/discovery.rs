//! Finding peers on the local network.
//!
//! Discovery answers one question — *what addresses might a Synra device be at?* — and deliberately
//! refuses to answer any other. In particular it never establishes identity. A UDP datagram's source
//! address is trivially forged, and its contents are unauthenticated, so anything a device claims
//! about itself here is a hint to be checked, not a fact to be trusted.
//!
//! That restraint is what makes the rest of the design simple: a device found this way is a
//! **candidate**, and only becomes a peer once a TCP connection has been made and a `Hello` exchanged
//! over it. The interface shows candidates under a separate heading for exactly that reason.
//!
//! # Two datagram kinds, one magic prefix each
//!
//! ```text
//! query    "SYNRA_DISCOVERY\n" + JSON { protocol, device_id, display_name, port }
//! response JSON { device_id, display_name, platform, app_version, protocol, features, port }
//! offline  "SYNRA_OFFLINE\n"   + JSON { device_id, timestamp }
//! ```
//!
//! A response has no magic prefix: it is a unicast reply to an address that just sent a query, so
//! there is nothing to disambiguate it from.
//!
//! # Unknown fields are ignored, and that is the opposite of the envelope rule
//!
//! [`crate::envelope::Envelope`] refuses unknown fields; these messages ignore them. The difference
//! is not inconsistency, it is what the two formats are for. An envelope is a contract: a peer that
//! sends an extra field is violating a protocol both sides agreed to, and accepting it would let two
//! implementations drift apart about what a valid message is.
//!
//! A discovery datagram is a broadcast rumour. Broadcast reaches every device on the network,
//! including ones running versions this build has never seen, and the cost of refusing an unfamiliar
//! field is that a device silently fails to be discoverable at all — a failure the user experiences
//! as "my phone can't see my laptop", with nothing in any log to explain it. So a datagram may say
//! more than we understand, and the extra is dropped.
//!
//! # Self-discovery is suppressed in exactly one place
//!
//! A device that answers its own broadcast appears in its own list. The check lives in
//! [`Discovery::admit`] and nowhere else. Spreading it over several layers produces the familiar
//! outcome: nobody can say which layer is doing the filtering, and a device discovers itself again
//! every time one is bypassed.

use core::fmt;
use core::net::IpAddr;
use core::time::Duration;

use serde::{Deserialize, Serialize};

use crate::handshake::{Feature, PROTOCOL_VERSION};
use crate::ids::DeviceId;
use crate::limits;
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
            return Err(DiscoveryError::TooLarge { len: bytes.len(), max: MAX_DATAGRAM_LEN });
        }
        let text = core::str::from_utf8(bytes).map_err(|_| DiscoveryError::NotUtf8)?;

        if let Some(body) = strip_magic(text, QUERY_MAGIC) {
            let announcement: DeviceAnnouncement =
                serde_json::from_str(body).map_err(|error| DiscoveryError::Malformed {
                    kind: "query",
                    detail: error.to_string(),
                })?;
            announcement.validate()?;
            return Ok(Self::Query(DiscoveryQuery { device: announcement }));
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
        Ok(Self::Response(DiscoveryResponse { device: announcement }))
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

/// Builds a query datagram.
///
/// # Errors
///
/// [`DiscoveryError`] if the announcement is not usable.
pub fn encode_query(device: &DeviceAnnouncement) -> Result<Vec<u8>, DiscoveryError> {
    device.validate()?;
    let body = serde_json::to_string(device).map_err(|error| DiscoveryError::Malformed {
        kind: "query",
        detail: error.to_string(),
    })?;
    Ok(format!("{QUERY_MAGIC}{MAGIC_SEPARATOR}{body}").into_bytes())
}

/// Builds a response datagram, which carries no marker.
///
/// # Errors
///
/// [`DiscoveryError`] if the announcement is not usable.
pub fn encode_response(device: &DeviceAnnouncement) -> Result<Vec<u8>, DiscoveryError> {
    device.validate()?;
    serde_json::to_vec(device).map_err(|error| DiscoveryError::Malformed {
        kind: "response",
        detail: error.to_string(),
    })
}

/// Builds an offline announcement datagram.
///
/// # Errors
///
/// [`DiscoveryError`] if the announcement is not usable.
pub fn encode_offline(offline: &OfflineAnnouncement) -> Result<Vec<u8>, DiscoveryError> {
    offline.validate()?;
    let body = serde_json::to_string(offline).map_err(|error| DiscoveryError::Malformed {
        kind: "offline",
        detail: error.to_string(),
    })?;
    Ok(format!("{OFFLINE_MAGIC}{MAGIC_SEPARATOR}{body}").into_bytes())
}

/// How much time and how many connections a scan may spend.
///
/// Defined once, here, and used by every platform. A per-platform timeout is precisely how "the same
/// code behaves differently on each device" starts: a value tuned on a desktop becomes a scan that
/// never finishes on a phone, and nothing in the source says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBudget {
    /// The whole budget, so the interface's "scanning" spinner has a bound.
    pub total: Duration,
    /// How long to listen for replies before probing.
    pub passive: Duration,
    /// How long one TCP probe may take.
    pub probe_timeout: Duration,
    /// How many probes may be in flight at once.
    pub probe_concurrency: usize,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            total: limits::SCAN_TOTAL,
            passive: limits::SCAN_PASSIVE,
            probe_timeout: limits::SCAN_PROBE_TIMEOUT,
            probe_concurrency: limits::SCAN_PROBE_CONCURRENCY,
        }
    }
}

impl ScanBudget {
    /// How long to wait between the repeated broadcast queries.
    #[must_use]
    pub const fn query_interval(&self) -> Duration {
        limits::DISCOVERY_QUERY_INTERVAL
    }

    /// How many times a query is broadcast.
    ///
    /// More than once because a single UDP datagram is lost often enough to matter: a device that
    /// misses the only query appears to be offline. Three attempts covers a one-off loss without
    /// turning discovery into a flood.
    #[must_use]
    pub const fn query_repeats(&self) -> u8 {
        limits::DISCOVERY_QUERY_REPEATS
    }

    /// How long the repeated queries take in total.
    #[must_use]
    pub const fn query_window(&self) -> Duration {
        // `Duration` multiplication by a `u32` is const-stable; the repeat count is a small constant.
        limits::DISCOVERY_QUERY_INTERVAL.saturating_mul(limits::DISCOVERY_QUERY_REPEATS as u32)
    }

    /// Checks the budget is usable.
    ///
    /// # Errors
    ///
    /// A description of the first inconsistency.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.total.is_zero() || self.passive.is_zero() || self.probe_timeout.is_zero() {
            return Err("every scan phase needs a non-zero limit, or a scan never ends");
        }
        if self.probe_concurrency == 0 {
            return Err("probe_concurrency must be non-zero, or no candidate is ever probed");
        }
        if self.passive > self.total {
            return Err("passive must not exceed total, or the probe phase never runs");
        }
        if self.query_window() > self.passive {
            return Err(
                "the repeated queries must fit inside the passive window, \
                 or a query is still going out after replies stopped being collected",
            );
        }
        Ok(())
    }

    /// Whether a set of candidates can be probed inside the budget.
    ///
    /// A scan that cannot finish is worse than one that reports fewer candidates: the interface
    /// shows "scanning" for the full budget and then reports a partial answer with no indication it
    /// was partial.
    #[must_use]
    pub fn can_probe(&self, candidate_count: usize) -> bool {
        let batches = candidate_count.div_ceil(self.probe_concurrency);
        let needed = self.probe_timeout.saturating_mul(batches as u32);
        needed <= self.total.saturating_sub(self.passive)
    }

    /// How long the probe phase has, once listening is done.
    #[must_use]
    pub const fn probe_window(&self) -> Duration {
        self.total.saturating_sub(self.passive)
    }
}

/// How much confidence there is in a device's identity.
///
/// Discovery cannot raise this above [`Self::Announced`]: a UDP datagram's contents are
/// unauthenticated, so anything it claims is a hint. Only a completed handshake — TCP, `Hello`, and
/// the challenge check — reaches [`Self::Handshaked`], and only that level may appear in the user's
/// device list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TrustLevel {
    /// An address that replied to a broadcast. The device id is unverified.
    Announced,
    /// A TCP connection was made and a `Hello` exchanged.
    Handshaked,
    /// The pairing token was accepted.
    Paired,
}

impl TrustLevel {
    /// Whether a device at this level may be shown as a peer.
    #[must_use]
    pub const fn is_displayable(self) -> bool {
        matches!(self, Self::Handshaked | Self::Paired)
    }
}

/// A device heard from, with the address it was heard from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// What the device claimed about itself, unverified.
    pub device: DeviceAnnouncement,
    /// Where the datagram came from.
    pub source: IpAddr,
    /// How much confidence there is in it.
    pub trust: TrustLevel,
}

impl Candidate {
    /// The address to connect to for the main link.
    #[must_use]
    pub const fn endpoint(&self) -> (IpAddr, u16) {
        (self.source, self.device.port)
    }

    /// Whether this candidate may appear in the user's device list.
    ///
    /// The rule that keeps a spoofed datagram from putting a fake device in the interface.
    #[must_use]
    pub const fn is_displayable(&self) -> bool {
        self.trust.is_displayable()
    }
}

/// Decides which datagrams to accept, and whether a candidate is this device itself.
///
/// One place for the self-check, per the module docs. A device that answers its own broadcast would
/// otherwise list itself, and a check spread over several layers is one that will be missed when a
/// new path is added.
#[derive(Debug, Clone)]
pub struct Discovery {
    /// This device's id.
    local_id: DeviceId,
    /// This device's own addresses, including IPv6.
    local_addresses: Vec<IpAddr>,
}

impl Discovery {
    /// Builds a filter for one device.
    #[must_use]
    pub const fn new(local_id: DeviceId, local_addresses: Vec<IpAddr>) -> Self {
        Self { local_id, local_addresses }
    }

    /// Whether a datagram should be acted on.
    ///
    /// Two conditions, and no others: the device id matches ours, or the source address is one of
    /// ours. The second catches the case the first cannot — a device that has not yet learned its own
    /// id, or a datagram whose advertised id differs from the interface it left by.
    #[must_use]
    pub fn admit(&self, datagram: &DiscoveryDatagram, source: IpAddr) -> bool {
        if datagram.device_id() == self.local_id {
            return false;
        }
        !self.local_addresses.contains(&source)
    }

    /// Records a device that has completed a handshake, raising its trust.
    ///
    /// The only way a device becomes displayable. Called by the handshake path, not by discovery.
    #[must_use]
    pub fn handshaked(candidate: Candidate) -> Candidate {
        Candidate { trust: TrustLevel::Handshaked, ..candidate }
    }

    /// This device's id.
    #[must_use]
    pub const fn local_id(&self) -> DeviceId {
        self.local_id
    }

    /// This device's own addresses.
    #[must_use]
    pub fn local_addresses(&self) -> &[IpAddr] {
        &self.local_addresses
    }
}

/// A device's compact name for logs.
///
/// Discovery runs before logging is necessarily configured, so this is a plain `Display` rather than
/// something that needs a subscriber.
impl fmt::Display for DeviceAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}, port {})", self.display_name, self.device_id, self.port)
    }
}

/// How many times an offline announcement is sent.
///
/// Best-effort, three times with a short gap: this runs while the process is shutting down, and a
/// device that dies without announcing itself is noticed by its peers anyway, via the heartbeat
/// timeout. More repeats would delay shutdown for a message that is only an optimisation.
#[must_use]
pub const fn offline_repeats() -> u8 {
    limits::OFFLINE_ANNOUNCE_REPEATS
}

/// The gap between offline announcements.
#[must_use]
pub const fn offline_interval() -> Duration {
    limits::OFFLINE_ANNOUNCE_INTERVAL
}


#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    fn device(id: DeviceId, port: u16) -> DeviceAnnouncement {
        DeviceAnnouncement {
            device_id: id,
            display_name: "laptop".to_owned(),
            protocol: PROTOCOL_VERSION,
            port,
            platform: Some(PlatformKind::Desktop),
            app_version: Some("1.0.0".to_owned()),
            features: vec![Feature::EventStream, Feature::LanDiscovery],
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    #[test]
    fn a_query_round_trips() {
        let original = device(DeviceId::new(), 32100);
        let bytes = encode_query(&original).expect("encodes");

        // The magic, a separator, then JSON.
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(text.starts_with(QUERY_MAGIC), "{text}");
        assert_eq!(text.chars().nth(QUERY_MAGIC.len()), Some(MAGIC_SEPARATOR));

        match DiscoveryDatagram::parse(&bytes).expect("parses") {
            DiscoveryDatagram::Query(query) => assert_eq!(query.device, original),
            other => panic!("expected a query, got {other:?}"),
        }
    }

    #[test]
    fn a_response_round_trips_with_no_marker() {
        let original = device(DeviceId::new(), 32100);
        let bytes = encode_response(&original).expect("encodes");

        // No magic: a response is a unicast reply, so there is nothing to disambiguate it from.
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(!text.contains(QUERY_MAGIC));

        match DiscoveryDatagram::parse(&bytes).expect("parses") {
            DiscoveryDatagram::Response(response) => assert_eq!(response.device, original),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn an_offline_announcement_round_trips() {
        let original = OfflineAnnouncement { device_id: DeviceId::new(), timestamp: 1_700_000_000_000 };
        let bytes = encode_offline(&original).expect("encodes");

        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(text.starts_with(OFFLINE_MAGIC), "{text}");

        match DiscoveryDatagram::parse(&bytes).expect("parses") {
            DiscoveryDatagram::Offline(offline) => assert_eq!(offline, original),
            other => panic!("expected an offline announcement, got {other:?}"),
        }
    }

    #[test]
    fn unknown_fields_in_a_discovery_datagram_are_ignored() {
        // The opposite of the envelope rule, and deliberately so: broadcast reaches devices running
        // versions we have never seen, and refusing an unfamiliar field means a device silently fails
        // to be discoverable at all.
        let body = format!(
            r#"{{"device_id":"{}","display_name":"phone","protocol":1,"port":32100,"somethingNew":true}}"#,
            DeviceId::new(),
        );
        let datagram = format!("{QUERY_MAGIC}\n{body}");
        match DiscoveryDatagram::parse(datagram.as_bytes()).expect("parses") {
            DiscoveryDatagram::Query(query) => assert_eq!(query.device.display_name, "phone"),
            other => panic!("expected a query, got {other:?}"),
        }
    }

    #[test]
    fn a_datagram_with_no_separator_is_not_a_query() {
        // Without the separator, `SYNRA_DISCOVERY{...}` would be neither a query nor valid JSON, and
        // reporting it as an unknown datagram is clearer than reporting a JSON error.
        let text = format!("{QUERY_MAGIC}{{\"device_id\":\"x\"}}");
        assert!(matches!(
            DiscoveryDatagram::parse(text.as_bytes()),
            Err(DiscoveryError::UnknownKind)
        ));
    }

    #[test]
    fn unparseable_datagrams_are_refused() {
        assert!(matches!(
            DiscoveryDatagram::parse(b"random noise"),
            Err(DiscoveryError::UnknownKind)
        ));
        assert!(matches!(
            DiscoveryDatagram::parse(b"SYNRA_DISCOVERY\n{not json}"),
            Err(DiscoveryError::Malformed { kind: "query", .. })
        ));
        assert!(matches!(
            DiscoveryDatagram::parse(b"SYNRA_OFFLINE\n{not json}"),
            Err(DiscoveryError::Malformed { kind: "offline", .. })
        ));
        // Invalid UTF-8 cannot be JSON either.
        assert!(matches!(
            DiscoveryDatagram::parse(&[0xFF, 0xFE]),
            Err(DiscoveryError::NotUtf8)
        ));
    }

    #[test]
    fn an_oversized_datagram_is_refused_before_parsing() {
        // The port is open by design, so the ceiling is what stops a flood from exhausting a receive
        // buffer.
        let mut bytes = vec![b'x'; MAX_DATAGRAM_LEN + 1];
        match DiscoveryDatagram::parse(&bytes) {
            Err(DiscoveryError::TooLarge { len, max }) => {
                assert_eq!(len, MAX_DATAGRAM_LEN + 1);
                assert_eq!(max, MAX_DATAGRAM_LEN);
            }
            other => panic!("expected a size refusal, got {other:?}"),
        }

        // Exactly at the ceiling is allowed through to the parser.
        bytes.truncate(MAX_DATAGRAM_LEN);
        assert!(matches!(
            DiscoveryDatagram::parse(&bytes),
            Err(DiscoveryError::UnknownKind)
        ));
    }

    #[test]
    fn an_announcement_from_another_protocol_version_is_refused() {
        let mut announcement = device(DeviceId::new(), 32100);
        announcement.protocol = 2;
        assert!(matches!(
            announcement.validate(),
            Err(DiscoveryError::VersionMismatch { ours: 1, theirs: 2 })
        ));
    }

    #[test]
    fn an_announcement_missing_essentials_is_refused() {
        /// Mutates one field, so a table of negative cases can be one loop.
        type Mutate = fn(&mut DeviceAnnouncement);
        let cases: &[(&str, Mutate)] = &[
            ("nil device", |a| a.device_id = DeviceId::from_uuid(uuid::Uuid::nil())),
            ("port zero", |a| a.port = 0),
            ("blank name", |a| a.display_name = "   ".to_owned()),
            ("long name", |a| a.display_name = "x".repeat(MAX_ANNOUNCED_NAME + 1)),
        ];

        for (label, mutate) in cases {
            let mut announcement = device(DeviceId::new(), 32100);
            mutate(&mut announcement);
            assert!(announcement.validate().is_err(), "{label} should be refused");
        }
    }

    #[test]
    fn optional_announcement_fields_may_be_absent() {
        // A bare query from a device that has not yet worked out its own platform is still useful:
        // the responder only needs an address and a port to reply.
        let announcement = DeviceAnnouncement {
            device_id: DeviceId::new(),
            display_name: "phone".to_owned(),
            protocol: PROTOCOL_VERSION,
            port: 32100,
            platform: None,
            app_version: None,
            features: Vec::new(),
        };
        assert_eq!(announcement.validate(), Ok(()));

        let bytes = encode_query(&announcement).expect("encodes");
        let text = String::from_utf8(bytes).expect("utf8");
        for absent in ["platform", "app_version", "features"] {
            assert!(!text.contains(absent), "{absent} should be omitted: {text}");
        }
    }

    #[test]
    fn a_device_never_admits_its_own_datagrams() {
        let local = DeviceId::new();
        let discovery = Discovery::new(local, vec![ip(5), ip(9)]);

        // By device id.
        let own = DiscoveryDatagram::Query(DiscoveryQuery { device: device(local, 32100) });
        assert!(!discovery.admit(&own, ip(50)), "this is us");

        // By source address, which catches a device that has not learned its own id yet, or one
        // whose advertised id differs from the interface the datagram left by.
        let other = DiscoveryDatagram::Query(DiscoveryQuery { device: device(DeviceId::new(), 32100) });
        assert!(!discovery.admit(&other, ip(5)), "that is one of our own addresses");

        // Somebody else.
        assert!(discovery.admit(&other, ip(50)));
    }

    #[test]
    fn the_self_check_is_the_only_one() {
        // The check has to be complete on its own: a caller that also filtered elsewhere would be
        // relying on a second layer, and the point of one place is that no such layer exists.
        let local = DeviceId::new();
        let discovery = Discovery::new(local, vec![ip(5)]);
        assert_eq!(discovery.local_id(), local);
        assert_eq!(discovery.local_addresses(), &[ip(5)]);

        // A datagram from ourselves is refused regardless of the source address.
        let own = DiscoveryDatagram::Offline(OfflineAnnouncement {
            device_id: local,
            timestamp: 0,
        });
        assert!(!discovery.admit(&own, ip(200)));
    }

    #[test]
    fn discovery_alone_can_never_make_a_device_displayable() {
        // The rule that keeps a spoofed datagram out of the interface: a candidate from UDP is a
        // hint, and only a completed handshake turns it into a peer.
        let candidate = Candidate {
            device: device(DeviceId::new(), 32100),
            source: ip(50),
            trust: TrustLevel::Announced,
        };
        assert!(!candidate.is_displayable(), "an announcement is not an identity");

        let promoted = Discovery::handshaked(candidate.clone());
        assert!(promoted.is_displayable());
        assert_eq!(promoted.device, candidate.device, "promotion changes only the trust");
        assert_eq!(promoted.endpoint(), (ip(50), 32100));

        assert!(TrustLevel::Handshaked < TrustLevel::Paired);
        assert!(!TrustLevel::Announced.is_displayable());
        assert!(TrustLevel::Paired.is_displayable());
    }

    #[test]
    fn the_default_scan_budget_is_self_consistent() {
        assert_eq!(ScanBudget::default().validate(), Ok(()));
    }

    #[test]
    fn the_default_scan_budget_reads_its_numbers_from_the_limits() {
        // One source per number. A per-platform timeout is how "the same code behaves differently on
        // each device" starts.
        let budget = ScanBudget::default();
        assert_eq!(budget.total, limits::SCAN_TOTAL);
        assert_eq!(budget.passive, limits::SCAN_PASSIVE);
        assert_eq!(budget.probe_timeout, limits::SCAN_PROBE_TIMEOUT);
        assert_eq!(budget.probe_concurrency, limits::SCAN_PROBE_CONCURRENCY);
        assert_eq!(budget.query_interval(), limits::DISCOVERY_QUERY_INTERVAL);
        assert_eq!(budget.query_repeats(), limits::DISCOVERY_QUERY_REPEATS);
    }

    #[test]
    fn a_degenerate_scan_budget_is_refused() {
        for budget in [
            ScanBudget { total: Duration::ZERO, ..ScanBudget::default() },
            ScanBudget { passive: Duration::ZERO, ..ScanBudget::default() },
            ScanBudget { probe_timeout: Duration::ZERO, ..ScanBudget::default() },
            ScanBudget { probe_concurrency: 0, ..ScanBudget::default() },
        ] {
            assert!(budget.validate().is_err());
        }

        // A passive window longer than the whole budget means the probe phase never runs, so
        // candidates are found and never checked.
        let passive_too_long = ScanBudget {
            passive: Duration::from_secs(60),
            total: Duration::from_secs(10),
            ..ScanBudget::default()
        };
        assert!(passive_too_long.validate().is_err());
    }

    #[test]
    fn repeated_queries_must_fit_inside_the_passive_window() {
        // Otherwise a query is still going out after replies stopped being collected, and its answer
        // arrives with nobody listening.
        let too_short = ScanBudget {
            passive: Duration::from_millis(10),
            total: Duration::from_secs(10),
            ..ScanBudget::default()
        };
        assert!(too_short.validate().is_err());

        let default = ScanBudget::default();
        assert!(
            default.query_window() <= default.passive,
            "the default must satisfy its own rule"
        );
    }

    #[test]
    fn the_probe_window_is_what_is_left_after_listening() {
        let budget = ScanBudget::default();
        assert_eq!(budget.probe_window(), budget.total - budget.passive);
    }

    #[test]
    fn a_budget_can_say_whether_it_can_finish_a_probe_set() {
        let budget = ScanBudget {
            total: Duration::from_secs(2),
            passive: Duration::from_millis(500),
            probe_timeout: Duration::from_millis(200),
            probe_concurrency: 10,
        };
        // 1500ms of probe window, 200ms per batch of 10.
        assert!(budget.can_probe(0));
        assert!(budget.can_probe(10));
        assert!(budget.can_probe(70), "7 batches is 1400ms");
        assert!(!budget.can_probe(80), "8 batches is 1600ms, past the window");
    }

    #[test]
    fn an_offline_announcement_needs_a_device() {
        let good = OfflineAnnouncement { device_id: DeviceId::new(), timestamp: 0 };
        assert_eq!(good.validate(), Ok(()));

        let nil = OfflineAnnouncement {
            device_id: DeviceId::from_uuid(uuid::Uuid::nil()),
            timestamp: 0,
        };
        assert!(nil.validate().is_err());
    }

    #[test]
    fn offline_announcements_are_best_effort() {
        // This runs while the process is shutting down, so it is bounded and short. More repeats
        // would delay shutdown for a message that is only an optimisation: a device that dies without
        // announcing itself is noticed anyway, via the heartbeat timeout.
        assert_eq!(offline_repeats(), limits::OFFLINE_ANNOUNCE_REPEATS);
        assert_eq!(offline_interval(), limits::OFFLINE_ANNOUNCE_INTERVAL);
        assert!(offline_repeats() <= 5, "shutdown must not be held up");
        let worst_case = offline_interval().saturating_mul(u32::from(offline_repeats()));
        assert!(worst_case < Duration::from_secs(1));
    }

    #[test]
    fn a_datagram_reports_the_device_it_concerns() {
        let id = DeviceId::new();
        let query = DiscoveryDatagram::Query(DiscoveryQuery { device: device(id, 32100) });
        assert_eq!(query.device_id(), id);
        assert!(query.is_recognised());

        let offline = DiscoveryDatagram::Offline(OfflineAnnouncement {
            device_id: id,
            timestamp: 0,
        });
        assert_eq!(offline.device_id(), id);
    }

    #[test]
    fn an_announcement_displays_readably_for_logs() {
        let announcement = device(DeviceId::new(), 32100);
        let text = announcement.to_string();
        assert!(text.contains("laptop"));
        assert!(text.contains("32100"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use core::net::Ipv4Addr;
    use proptest::prelude::*;

    proptest! {
        /// Any datagram that encodes parses back to itself. Discovery drives connection attempts, so
        /// a field lost or altered in round-tripping is a device reached at the wrong address.
        #[test]
        fn announcements_round_trip(
            port in 1u16..=u16::MAX,
            // Starts with an alphanumeric, so the name is never blank. A generator that could produce
            // all-whitespace would fail on `validate`, which is a different property's business.
            name in "[A-Za-z0-9][A-Za-z0-9 ]{0,39}",
            platform in proptest::option::of(Just(PlatformKind::Desktop)),
        ) {
            let announcement = DeviceAnnouncement {
                device_id: DeviceId::new(),
                display_name: name,
                protocol: PROTOCOL_VERSION,
                port,
                platform,
                app_version: None,
                features: vec![Feature::EventStream],
            };

            let bytes = encode_query(&announcement).expect("encodes");
            match DiscoveryDatagram::parse(&bytes).expect("parses") {
                DiscoveryDatagram::Query(query) => prop_assert_eq!(query.device, announcement),
                other => prop_assert!(false, "expected a query, got {:?}", other),
            }
        }

        /// Arbitrary bytes either parse or are refused with a reason. Discovery runs on an open UDP
        /// port, so an attacker controls this input completely and it must never panic.
        #[test]
        fn arbitrary_datagrams_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = DiscoveryDatagram::parse(&bytes);
        }

        /// A device's own datagrams are never admitted, whichever way it is identified.
        #[test]
        fn self_datagrams_are_never_admitted(last_octet in 1u8..=254, other in 1u8..=254) {
            let local = DeviceId::new();
            let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet));
            let discovery = Discovery::new(local, vec![local_ip]);

            // By id.
            let by_id = DiscoveryDatagram::Query(DiscoveryQuery {
                device: DeviceAnnouncement {
                    device_id: local,
                    display_name: "self".to_owned(),
                    protocol: PROTOCOL_VERSION,
                    port: 32100,
                    platform: None,
                    app_version: None,
                    features: Vec::new(),
                },
            });
            prop_assert!(!discovery.admit(&by_id, IpAddr::V4(Ipv4Addr::new(10, 0, 0, other))));

            // By address, even with an id we have never seen.
            let by_address = DiscoveryDatagram::Query(DiscoveryQuery {
                device: DeviceAnnouncement {
                    device_id: DeviceId::new(),
                    display_name: "stranger".to_owned(),
                    protocol: PROTOCOL_VERSION,
                    port: 32100,
                    platform: None,
                    app_version: None,
                    features: Vec::new(),
                },
            });
            prop_assert!(!discovery.admit(&by_address, local_ip));
        }
    }
}
