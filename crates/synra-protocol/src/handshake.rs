//! Link establishment: what two devices say to each other before anything else.
//!
//! A `Hello` is the first frame on every connection, in both directions. It carries the protocol
//! version, what each side can do, and enough evidence for the receiving side to decide whether it
//! already trusts the caller.
//!
//! # The handshake exists to fail early
//!
//! Everything checked here is something that would otherwise fail later, after the user has already
//! asked for something:
//!
//! * **Protocol version** — a peer from a different major version would send frames this build
//!   cannot read. Refusing at `Hello` turns that into one clear message instead of a stream of
//!   unreadable frames.
//! * **Features** — a peer that cannot do `TransferResume` would strand a partially transferred
//!   file. The intersection is computed once, here, so no later code has to ask.
//! * **Pairing** — an unpaired peer has no business sending anything. Checking at `Hello` means the
//!   rest of the kernel can assume every message on an established link came from a paired device.
//!
//! # Stale pairings heal themselves
//!
//! A pairing token can be valid for one device and unknown to the other — the one that forgot was
//! reset, reinstalled, or had its data cleared. The obvious handling, refusing the link, produces
//! the worst outcome available: two devices that each believe they are paired and no way to fix it
//! short of finding the unpair button.
//!
//! So the acceptor says *which kind* of mismatch it is ([`PairingState`]), and for
//! [`PairingState::Stale`] the dialer falls back to pairing again. The user gets a prompt — something
//! they can act on — instead of a connection that silently refuses.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::DeviceId;
use crate::limits;
use crate::session::PlatformKind;

/// The only protocol version this build speaks.
///
/// A single version with no compatibility layer. Two builds that disagree here do not talk; they
/// report it, and one of them is updated.
pub const PROTOCOL_VERSION: u16 = 1;

/// Identifies a protocol version this build cannot speak.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("peer speaks protocol {theirs}, this build speaks {ours}")]
pub struct VersionMismatch {
    /// The version this build speaks.
    pub ours: u16,
    /// The version the peer announced.
    pub theirs: u16,
}

/// A reconnection credential.
///
/// Thirty-two bytes of keyed hash, not the pairing secret itself. What goes on the wire proves the
/// sender knew the secret, so a token captured from a previous connection cannot be used to derive
/// the secret, and cannot be replayed against a different peer.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LinkToken([u8; Self::LEN]);

impl LinkToken {
    /// How many bytes a token is.
    pub const LEN: usize = 32;

    /// Builds a token from bytes that came out of a keyed hash.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh token, from the operating system's cryptographic random source.
    ///
    /// # Why this is not built the way [`SessionNonce::random`] is
    ///
    /// A nonce only has to be unique, so a UUID is the right tool and its timestamp is a feature: it sorts. A token is a
    /// **credential** — whoever holds it can open a link — so it has to be unpredictable, and a UUID's version and
    /// timestamp bits are neither random nor secret. `SessionNonce` is a `u128` of which roughly half the bits are
    /// structured; reusing that here would leave a secret with a guessable shape.
    ///
    /// # Why a failure to read randomness is not handled here
    ///
    /// Because there is no safe alternative: a token derived from anything else is worse than no token, and returning
    /// `Result` would push a decision onto every caller that has only one right answer. `OsRng` comes from the operating
    /// system, and a system that cannot supply it cannot run this kernel at all.
    #[must_use]
    pub fn random() -> Self {
        use rand_core::RngCore;

        let mut bytes = [0u8; Self::LEN];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The raw bytes, for comparison against a stored token.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Lowercase hex, which is how it appears on the wire.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(Self::LEN * 2);
        for byte in self.0 {
            // Writing into a `String` cannot fail, and two hex digits per byte is unambiguous.
            let _ = fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
        }
        out
    }

    /// Parses the hex form.
    ///
    /// # Errors
    ///
    /// A description if the text is not [`Self::LEN`] bytes of hex.
    pub fn from_hex(text: &str) -> Result<Self, &'static str> {
        if text.len() != Self::LEN * 2 {
            return Err("a link token is 64 hex characters");
        }
        let mut bytes = [0u8; Self::LEN];
        // Destructuring pairs rather than indexing: `indexing_slicing` is denied workspace-wide, and
        // a decoder for a credential should not rely on an annotation claiming it will not panic.
        for (index, [high, low]) in text.as_bytes().as_chunks::<2>().0.iter().copied().enumerate() {
            let high = hex_digit(high).ok_or("link token is not hex")?;
            let low = hex_digit(low).ok_or("link token is not hex")?;
            if let Some(slot) = bytes.get_mut(index) {
                *slot = (high << 4) | low;
            }
        }
        Ok(Self(bytes))
    }
}

/// Decodes one hex digit.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A token is a credential, so it must not appear in logs or panic messages.
impl fmt::Debug for LinkToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately not the value: a token in a log is a token in every log aggregator and bug
        // report that collects them.
        f.write_str("LinkToken(<redacted>)")
    }
}

impl Serialize for LinkToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for LinkToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// A per-connection random value, so two connections are never confusable.
///
/// Sent by the dialer and echoed by the acceptor. Proves the reply belongs to *this* attempt rather
/// than to a delayed one, and gives every link a value that cannot be predicted from the last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionNonce(pub u128);

impl SessionNonce {
    /// A fresh nonce.
    #[must_use]
    pub fn random() -> Self {
        Self(uuid::Uuid::now_v7().as_u128())
    }

    /// Whether this is the all-zero value, which is never a valid nonce.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }
}

/// A capability a link can negotiate.
///
/// Additive only. A new variant means a new optional capability, never a change to how an existing
/// one behaves, and a peer that does not list a feature simply does not get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Feature {
    /// Resume a transfer that was interrupted, from the blocks the receiver already has.
    TransferResume,
    /// Push live events to a user interface. Without it, an interface polls.
    EventStream,
    /// Run the same plugin on both devices, so the pair acts as one workspace.
    PluginMirroring,
    /// Share the clipboard between paired devices.
    ClipboardSync,
    /// Answer a request for a diagnostic bundle.
    DiagnosticsBundle,
    /// Find peers on the local network without a configured address.
    LanDiscovery,
    /// Report progress for a transfer in flight.
    TransferProgress,
}

impl Feature {
    /// Every feature this build understands.
    ///
    /// A slice rather than a match so that negotiation, the wire-name tests, and the catalogue guard
    /// all read from one list. Adding a variant without adding it here is caught by
    /// [`tests::feature_list_is_exhaustive`].
    pub const ALL: &'static [Self] = &[
        Self::TransferResume,
        Self::EventStream,
        Self::PluginMirroring,
        Self::ClipboardSync,
        Self::DiagnosticsBundle,
        Self::LanDiscovery,
        Self::TransferProgress,
    ];

    /// The name used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransferResume => "transfer-resume",
            Self::EventStream => "event-stream",
            Self::PluginMirroring => "plugin-mirroring",
            Self::ClipboardSync => "clipboard-sync",
            Self::DiagnosticsBundle => "diagnostics-bundle",
            Self::LanDiscovery => "lan-discovery",
            Self::TransferProgress => "transfer-progress",
        }
    }

    /// Parses a wire name.
    ///
    /// Returns `None` for a name this build does not know, which is not an error: a newer peer may
    /// offer capabilities we simply do not use.
    #[must_use]
    pub fn from_str_opt(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|feature| feature.as_str() == name)
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The features both sides can use, and the ones this side cannot do without.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Agreed {
    /// The features present in both lists.
    pub common: Vec<Feature>,
    /// Features this side required that the peer does not have.
    ///
    /// Non-empty means the link is refused. A required feature is one without which this side would
    /// behave incorrectly rather than merely less well: continuing would produce a wrong result
    /// instead of an error.
    pub missing_required: Vec<Feature>,
}

impl Agreed {
    /// Whether every required feature is available.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.missing_required.is_empty()
    }

    /// Whether a feature can be used on this link.
    ///
    /// The only correct way to ask. A caller that consulted its own list instead would assume a
    /// capability the peer never offered.
    #[must_use]
    pub fn supports(&self, feature: Feature) -> bool {
        self.common.contains(&feature)
    }
}

/// Negotiates the feature intersection.
///
/// Duplicates in either list are harmless: the result is a set. That is deliberate, so a caller
/// assembling a list from two sources does not have to de-duplicate before asking whether a link can
/// work.
///
/// The result is sorted by wire name rather than left in input order. Two negotiations of the same
/// pair must compare equal — the list is stored on the link and compared when a second connection is
/// considered, and an order that depended on which side dialled would make identical links look
/// different.
#[must_use]
pub fn negotiate(ours: &[Feature], theirs: &[Feature], required: &[Feature]) -> Agreed {
    let mut common: Vec<Feature> = Vec::new();
    for feature in ours {
        if theirs.contains(feature) && !common.contains(feature) {
            common.push(*feature);
        }
    }
    common.sort_unstable_by_key(|feature| feature.as_str());

    let missing_required = required
        .iter()
        .copied()
        .filter(|feature| !common.contains(feature))
        .collect();

    Agreed { common, missing_required }
}

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
    /// Present when reconnecting to a device this one has paired with before.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token: Option<LinkToken>,
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

/// How well the acceptor recognises the dialer's pairing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PairingState {
    /// The token matches a pairing this device still holds.
    Current,
    /// The dialer presented a token, but this device has no record of that pairing.
    ///
    /// The case that must not be treated as a refusal: this device was reset, reinstalled, or had
    /// its data cleared while the other still believed the pair existed. Reporting it lets the dialer
    /// re-pair, which the user can act on.
    Stale,
    /// The dialer presented no token, so it is pairing for the first time.
    Unknown,
}

impl PairingState {
    /// Whether the link may carry business messages.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Current)
    }

    /// Whether the dialer should fall back to pairing.
    #[must_use]
    pub const fn needs_pairing(self) -> bool {
        !self.is_trusted()
    }
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
    /// How the acceptor reads the dialer's token.
    pub pairing: PairingState,
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
            // A refused link is not paired, whatever the token said.
            pairing: PairingState::Unknown,
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

/// What the dialer does next, once a reply has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NextStep {
    /// The link is established and the pairing is current.
    Established(Agreed),
    /// The peer accepted, but this device must pair again before business messages can flow.
    ///
    /// Not a failure: this is the self-healing path, and the caller is expected to prompt rather than
    /// report an error.
    RePair {
        /// What the acceptor offered, so the features are not renegotiated after pairing.
        agreed: Agreed,
    },
    /// Do not connect, and do not retry on its own.
    Refused(RefusalReason),
    /// Try again later.
    Retry {
        /// Why, for the log.
        reason: RefusalReason,
    },
}

/// Decides what to do with a checked reply.
///
/// The whole handshake decision in one function, so it is testable without a socket and exists in one
/// place rather than being spread through the connect loop.
#[must_use]
pub fn next_step(ack: &HelloAck, ours: &[Feature], required: &[Feature]) -> NextStep {
    if let Some(refusal) = ack.refusal {
        return match refusal.is_retryable() {
            true => NextStep::Retry { reason: refusal },
            false => NextStep::Refused(refusal),
        };
    }

    let agreed = negotiate(ours, &ack.features, required);
    if !agreed.is_usable() {
        // The peer accepted but cannot do something this side needs. Refusing here rather than
        // proceeding means the failure surfaces at connection time, where it can be explained,
        // instead of at the moment the missing capability was first required.
        return NextStep::Refused(RefusalReason::MissingRequiredFeature);
    }

    match ack.pairing {
        PairingState::Current => NextStep::Established(agreed),
        PairingState::Stale | PairingState::Unknown => NextStep::RePair { agreed },
    }
}

/// Replay protection for handshakes.
///
/// A recorded `Hello` replayed at a peer would otherwise look like a fresh attempt from the same
/// device. The sequence numbers are per device, monotonic, and small enough to persist: all that
/// matters is that a value is never accepted twice.
#[derive(Debug, Default)]
pub struct SequenceGuard {
    seen: u64,
}

impl SequenceGuard {
    /// A guard that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { seen: 0 }
    }

    /// A guard resuming from a persisted value.
    #[must_use]
    pub const fn resume(seen: u64) -> Self {
        Self { seen }
    }

    /// The highest sequence accepted so far, for persisting.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.seen
    }

    /// Accepts a sequence number, or reports it as a replay.
    ///
    /// Strictly greater rather than greater-or-equal: a peer that restarted its counter — from a
    /// restored backup, say — has to re-pair, and treating a repeated value as fresh would let a
    /// recorded attempt through. The equal case is exactly what a replay produces.
    ///
    /// # Errors
    ///
    /// [`ReplayError`] when the value is not newer than one already seen.
    pub const fn accept(&mut self, sequence: u64) -> Result<(), ReplayError> {
        if sequence <= self.seen {
            return Err(ReplayError { sequence, seen: self.seen });
        }
        self.seen = sequence;
        Ok(())
    }
}

/// A handshake sequence number that was not newer than one already seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("handshake sequence {sequence} is not newer than {seen}, so this is a replay")]
pub struct ReplayError {
    /// The value offered.
    pub sequence: u64,
    /// The highest value already accepted.
    pub seen: u64,
}

/// How long a link may stay in each handshake phase.
///
/// A `Hello` that arrives and is never answered holds a connection slot and a file descriptor. With
/// no limit, an attacker exhausts either by connecting and going quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeBudget {
    /// How long to wait for a peer's `Hello` after accepting a connection.
    pub await_hello: core::time::Duration,
    /// How long the dialer waits for a `HelloAck`.
    pub await_ack: core::time::Duration,
    /// How long a link may sit paired-but-not-established.
    pub await_pairing: core::time::Duration,
}

impl Default for HandshakeBudget {
    fn default() -> Self {
        Self {
            await_hello: limits::HELLO_TIMEOUT,
            await_ack: limits::HELLO_TIMEOUT,
            // Long enough to find the phone and tap accept, short enough that a forgotten prompt
            // does not hold a slot all afternoon.
            await_pairing: core::time::Duration::from_secs(120),
        }
    }
}

impl HandshakeBudget {
    /// Checks the budget is usable.
    ///
    /// # Errors
    ///
    /// A description if any phase has no limit.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.await_hello.is_zero() || self.await_ack.is_zero() || self.await_pairing.is_zero() {
            return Err("every handshake phase needs a non-zero limit, or a quiet peer holds a slot");
        }
        Ok(())
    }
}

/// What a link has agreed to, once it is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAgreement {
    /// The peer's device id.
    pub peer: DeviceId,
    /// The peer's name, as it announced itself.
    pub peer_display_name: String,
    /// Which platform it runs.
    pub peer_platform: PlatformKind,
    /// The features both sides can use.
    pub agreed: Agreed,
    /// Whether the pairing was already current.
    pub paired: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    fn hello() -> Hello {
        Hello {
            protocol: PROTOCOL_VERSION,
            device_id: DeviceId::new(),
            display_name: "laptop".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "1.0.0".to_owned(),
            nonce: SessionNonce(1),
            features: Feature::ALL.to_vec(),
            requires: Vec::new(),
            token: None,
            sequence: 1,
            endpoints: Vec::new(),
        }
    }

    fn accepted_ack(nonce: SessionNonce, pairing: PairingState) -> HelloAck {
        HelloAck {
            protocol: PROTOCOL_VERSION,
            device_id: DeviceId::new(),
            display_name: "phone".to_owned(),
            platform: PlatformKind::Android,
            app_version: "1.0.0".to_owned(),
            nonce,
            features: Feature::ALL.to_vec(),
            requires: Vec::new(),
            pairing,
            refusal: None,
            sequence: 1,
            endpoints: Vec::new(),
        }
    }

    #[test]
    fn a_link_token_never_prints_its_value() {
        // A token in a log is a token in every log aggregator and bug report that collects them.
        let token = LinkToken::from_bytes([0xAB; LinkToken::LEN]);
        let debug = format!("{token:?}");
        assert!(!debug.contains("ab"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    #[test]
    fn a_link_token_round_trips_through_hex() {
        let token = LinkToken::from_bytes([0x5A; LinkToken::LEN]);
        let hex = token.to_hex();
        assert_eq!(hex.len(), LinkToken::LEN * 2);
        assert_eq!(LinkToken::from_hex(&hex).expect("round trips"), token);

        // Uppercase is accepted: hex arrives from logs and config files in both cases.
        assert_eq!(LinkToken::from_hex(&hex.to_uppercase()).expect("accepts uppercase"), token);

        assert!(LinkToken::from_hex("nope").is_err());
        assert!(LinkToken::from_hex(&"z".repeat(64)).is_err());
        assert!(LinkToken::from_hex(&"a".repeat(63)).is_err());
    }

    #[test]
    fn a_link_token_round_trips_through_json() {
        let token = LinkToken::from_bytes([0x11; LinkToken::LEN]);
        let json = serde_json::to_string(&token).expect("serialises");
        // Hex text, not an array of 32 numbers.
        assert!(json.starts_with("\"1111"), "{json}");
        let back: LinkToken = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, token);

        assert!(serde_json::from_str::<LinkToken>("\"short\"").is_err());
    }

    #[test]
    fn a_valid_hello_passes_validation() {
        assert_eq!(hello().validate(), Ok(()));
    }

    #[test]
    fn a_hello_from_another_protocol_version_is_refused() {
        let mut hello = hello();
        hello.protocol = 2;
        assert!(matches!(hello.validate(), Err(HelloError::Version(_))));
    }

    #[test]
    fn a_hello_missing_essentials_is_refused() {
        /// Mutates one field of a hello, so a table of negative cases can be one loop.
        type Mutate = fn(&mut Hello);
        let cases: &[(&str, Mutate)] = &[
            ("nil device", |h| h.device_id = DeviceId::from_uuid(uuid::Uuid::nil())),
            ("zero nonce", |h| h.nonce = SessionNonce(0)),
            ("blank name", |h| h.display_name = "  ".to_owned()),
            ("long name", |h| h.display_name = "x".repeat(Hello::MAX_DISPLAY_NAME + 1)),
            ("blank version", |h| h.app_version = String::new()),
        ];

        for (label, mutate) in cases {
            let mut hello = hello();
            mutate(&mut hello);
            assert!(hello.validate().is_err(), "{label} should be refused");
        }
    }

    #[test]
    fn too_many_endpoints_is_refused() {
        // The list drives connection attempts on the receiver, so it is bounded input.
        let mut hello = hello();
        hello.endpoints = (0..=Hello::MAX_ENDPOINTS)
            .map(|i| format!("10.0.0.{i}:32100"))
            .collect();
        assert!(hello.validate().is_err());

        hello.endpoints.truncate(Hello::MAX_ENDPOINTS);
        assert_eq!(hello.validate(), Ok(()));
    }

    #[test]
    fn a_required_feature_must_also_be_offered() {
        // Otherwise the announcement contradicts itself, and negotiation would report a feature as
        // missing that the peer never claimed to have.
        let mut hello = hello();
        hello.features = vec![Feature::EventStream];
        hello.requires = vec![Feature::TransferResume];
        assert!(hello.validate().is_err());

        hello.requires = vec![Feature::EventStream];
        assert_eq!(hello.validate(), Ok(()));
    }

    #[test]
    fn negotiation_intersects_the_two_lists() {
        let ours = [Feature::EventStream, Feature::ClipboardSync, Feature::LanDiscovery];
        let theirs = [Feature::EventStream, Feature::LanDiscovery, Feature::TransferResume];
        let agreed = negotiate(&ours, &theirs, &[]);

        assert!(agreed.is_usable());
        assert!(agreed.supports(Feature::EventStream));
        assert!(agreed.supports(Feature::LanDiscovery));
        assert!(!agreed.supports(Feature::ClipboardSync), "the peer does not offer it");
        assert!(!agreed.supports(Feature::TransferResume), "we do not offer it");
    }

    #[test]
    fn a_missing_required_feature_makes_the_link_unusable() {
        let agreed = negotiate(&[Feature::EventStream], &[Feature::TransferResume], &[Feature::EventStream]);

        assert!(!agreed.is_usable());
        assert_eq!(agreed.missing_required, vec![Feature::EventStream]);
        // And it is not in `common`, so a caller that forgot to check `is_usable` still cannot
        // accidentally use it.
        assert!(!agreed.supports(Feature::EventStream));
    }

    #[test]
    fn duplicates_in_either_list_are_harmless() {
        let agreed = negotiate(
            &[Feature::EventStream, Feature::EventStream],
            &[Feature::EventStream, Feature::EventStream],
            &[],
        );
        assert_eq!(agreed.common, vec![Feature::EventStream]);
    }

    #[test]
    fn negotiation_does_not_depend_on_list_order() {
        // The list is stored on the link and compared when a second connection is considered, so an
        // order that depended on which side dialled would make identical links look different.
        let a = negotiate(
            &[Feature::EventStream, Feature::LanDiscovery],
            &[Feature::LanDiscovery, Feature::EventStream],
            &[],
        );
        let b = negotiate(
            &[Feature::LanDiscovery, Feature::EventStream],
            &[Feature::EventStream, Feature::LanDiscovery],
            &[],
        );
        assert_eq!(a.common, b.common);
        assert_eq!(
            a.common,
            vec![Feature::EventStream, Feature::LanDiscovery],
            "sorted by wire name: event-stream before lan-discovery"
        );
    }

    #[test]
    fn an_empty_intersection_is_not_an_error_by_itself() {
        // Two devices with nothing in common can still exchange messages; they just cannot use any
        // optional capability. Only a *required* feature makes the link unusable.
        let agreed = negotiate(&[Feature::EventStream], &[Feature::ClipboardSync], &[]);
        assert!(agreed.is_usable());
        assert!(agreed.common.is_empty());
    }

    #[test]
    fn feature_list_is_exhaustive() {
        // A variant added without a wire name, or two sharing one, makes the format ambiguous. This
        // is the guard for a `#[non_exhaustive]` enum, where the compiler cannot help.
        let mut seen = std::collections::HashSet::new();
        for feature in Feature::ALL {
            assert!(seen.insert(feature.as_str()), "duplicate wire name for {feature:?}");
            assert_eq!(Feature::from_str_opt(feature.as_str()), Some(*feature));
            assert_eq!(feature.to_string(), feature.as_str());

            let json = serde_json::to_string(feature).expect("serialises");
            assert_eq!(json, format!("\"{}\"", feature.as_str()));
            let back: Feature = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, *feature);
        }
        assert_eq!(Feature::from_str_opt("teleportation"), None);
        assert_eq!(Feature::ALL.len(), seen.len());
    }

    #[test]
    fn a_hello_round_trips_through_json() {
        let mut hello = hello();
        hello.token = Some(LinkToken::from_bytes([7; LinkToken::LEN]));
        hello.features = vec![Feature::EventStream, Feature::TransferResume];
        hello.requires = vec![Feature::EventStream];
        hello.endpoints = vec!["192.168.1.5:32100".to_owned(), "[::1]:32100".to_owned()];

        let json = serde_json::to_string(&hello).expect("serialises");
        assert!(json.contains("\"deviceId\""), "{json}");
        let back: Hello = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, hello);
    }

    #[test]
    fn optional_hello_fields_are_omitted_not_null() {
        let json = serde_json::to_string(&hello()).expect("serialises");
        for absent in ["\"token\"", "\"requires\"", "\"endpoints\""] {
            assert!(!json.contains(absent), "{absent} should be omitted: {json}");
        }
    }

    #[test]
    fn an_unknown_hello_field_is_refused() {
        let mut value = serde_json::to_value(hello()).expect("value");
        value
            .as_object_mut()
            .expect("an object")
            .insert("extra".to_owned(), serde_json::json!(1));
        assert!(serde_json::from_value::<Hello>(value).is_err());
    }

    #[test]
    fn an_ack_must_echo_the_nonce() {
        let nonce = SessionNonce(0x1234);
        let ack = accepted_ack(nonce, PairingState::Current);
        assert_eq!(ack.validate(nonce), Ok(()));

        // A reply to a different attempt must not reach any other conclusion — including "the peer
        // refused us", which is why this check comes first.
        assert!(matches!(
            ack.validate(SessionNonce(0x9999)),
            Err(HelloError::Malformed(_))
        ));
    }

    #[test]
    fn a_refusal_acknowledges_the_attempt_without_being_trusted() {
        let nonce = SessionNonce(1);
        let ack = HelloAck::refuse(
            DeviceId::new(),
            "phone",
            PlatformKind::Android,
            "1.0.0",
            nonce,
            RefusalReason::TooManyLinks,
        );

        assert!(!ack.is_accepted());
        assert!(!ack.pairing.is_trusted(), "a refused link is never paired");
        assert!(ack.validate(nonce).is_err(), "the caller must be told");
    }

    #[test]
    fn a_retryable_refusal_asks_for_a_retry_and_a_block_does_not() {
        let nonce = SessionNonce(1);

        let busy = HelloAck::refuse(
            DeviceId::new(),
            "phone",
            PlatformKind::Android,
            "1.0.0",
            nonce,
            RefusalReason::TooManyLinks,
        );
        assert!(matches!(
            next_step(&busy, Feature::ALL, &[]),
            NextStep::Retry { reason: RefusalReason::TooManyLinks }
        ));

        // Retrying a block is not a transient failure; it is the user's decision ignored once a
        // second.
        let blocked = HelloAck::refuse(
            DeviceId::new(),
            "phone",
            PlatformKind::Android,
            "1.0.0",
            nonce,
            RefusalReason::Blocked,
        );
        assert!(matches!(
            next_step(&blocked, Feature::ALL, &[]),
            NextStep::Refused(RefusalReason::Blocked)
        ));
    }

    #[test]
    fn a_stale_pairing_leads_to_re_pairing_rather_than_a_refusal() {
        // The scenario: this device was reset while the peer still believed the pair existed. The
        // user must get a prompt they can act on, not a connection that quietly refuses.
        let nonce = SessionNonce(1);
        let ack = accepted_ack(nonce, PairingState::Stale);

        assert!(ack.validate(nonce).is_ok(), "it is a valid acceptance");
        match next_step(&ack, Feature::ALL, &[]) {
            NextStep::RePair { agreed } => {
                assert!(agreed.supports(Feature::EventStream), "features are not renegotiated later");
            }
            other => panic!("expected a re-pair, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_pairing_leads_to_pairing() {
        let ack = accepted_ack(SessionNonce(1), PairingState::Unknown);
        assert!(matches!(next_step(&ack, Feature::ALL, &[]), NextStep::RePair { .. }));
        assert!(PairingState::Unknown.needs_pairing());
        assert!(!PairingState::Current.needs_pairing());
        assert!(PairingState::Stale.needs_pairing());
    }

    #[test]
    fn a_current_pairing_establishes_the_link() {
        let ack = accepted_ack(SessionNonce(1), PairingState::Current);
        match next_step(&ack, Feature::ALL, &[]) {
            NextStep::Established(agreed) => assert!(agreed.is_usable()),
            other => panic!("expected an established link, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_cannot_meet_our_requirement_is_refused_before_use() {
        let nonce = SessionNonce(1);
        let mut ack = accepted_ack(nonce, PairingState::Current);
        ack.features = vec![Feature::ClipboardSync];

        // Without a requirement the link is fine.
        assert!(matches!(next_step(&ack, Feature::ALL, &[]), NextStep::Established(_)));

        // With one it is not, and the failure surfaces here rather than at the moment the missing
        // capability was first needed.
        assert!(matches!(
            next_step(&ack, Feature::ALL, &[Feature::EventStream]),
            NextStep::Refused(RefusalReason::MissingRequiredFeature)
        ));
    }

    #[test]
    fn a_sequence_guard_accepts_only_newer_values() {
        let mut guard = SequenceGuard::new();
        assert_eq!(guard.accept(1), Ok(()));
        assert_eq!(guard.highest(), 1);

        assert_eq!(guard.accept(2), Ok(()));
        assert!(guard.accept(2).is_err(), "the same value again is a replay");
        assert!(guard.accept(1).is_err(), "an older value is a replay");

        assert_eq!(guard.accept(100), Ok(()));
        assert_eq!(guard.highest(), 100);
    }

    #[test]
    fn a_sequence_guard_resumes_from_a_persisted_value() {
        // After a restart the guard must not accept what it accepted before, or every attempt
        // recorded during the previous run becomes replayable.
        let mut guard = SequenceGuard::resume(500);
        assert!(guard.accept(500).is_err());
        assert!(guard.accept(499).is_err());
        assert_eq!(guard.accept(501), Ok(()));
    }

    #[test]
    fn replay_errors_name_both_values() {
        let mut guard = SequenceGuard::resume(10);
        let error = guard.accept(3).expect_err("a replay");
        assert_eq!(error.sequence, 3);
        assert_eq!(error.seen, 10);
        assert!(error.to_string().contains("replay"));
    }

    #[test]
    fn handshake_budgets_must_bound_every_phase() {
        assert_eq!(HandshakeBudget::default().validate(), Ok(()));

        for budget in [
            HandshakeBudget { await_hello: Duration::ZERO, ..HandshakeBudget::default() },
            HandshakeBudget { await_ack: Duration::ZERO, ..HandshakeBudget::default() },
            HandshakeBudget { await_pairing: Duration::ZERO, ..HandshakeBudget::default() },
        ] {
            assert!(budget.validate().is_err());
        }
    }

    #[test]
    fn the_default_hello_timeout_matches_the_protocol_limit() {
        // Two sources for the same number is how they drift apart.
        assert_eq!(HandshakeBudget::default().await_hello, limits::HELLO_TIMEOUT);
        assert_eq!(HandshakeBudget::default().await_ack, limits::HELLO_TIMEOUT);
    }

    #[test]
    fn refusal_reasons_round_trip_and_report_retryability() {
        for reason in [
            RefusalReason::ProtocolMismatch,
            RefusalReason::MissingRequiredFeature,
            RefusalReason::Blocked,
            RefusalReason::TooManyLinks,
            RefusalReason::Malformed,
        ] {
            let json = serde_json::to_string(&reason).expect("serialises");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
            let back: RefusalReason = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, reason);
        }

        assert!(RefusalReason::TooManyLinks.is_retryable());
        assert!(!RefusalReason::Blocked.is_retryable());
        assert!(!RefusalReason::ProtocolMismatch.is_retryable());
        assert!(!RefusalReason::MissingRequiredFeature.is_retryable());
        assert!(!RefusalReason::Malformed.is_retryable());
    }

    #[test]
    fn pairing_states_round_trip() {
        for state in [PairingState::Current, PairingState::Stale, PairingState::Unknown] {
            let json = serde_json::to_string(&state).expect("serialises");
            let back: PairingState = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, state);
        }
    }

    #[test]
    fn session_nonces_are_never_zero() {
        for _ in 0..64 {
            assert!(!SessionNonce::random().is_zero());
        }
        assert!(SessionNonce(0).is_zero());
        assert_eq!(SessionNonce(0xFF).to_hex().len(), 32);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_features() -> impl Strategy<Value = Vec<Feature>> {
        proptest::collection::vec(0usize..Feature::ALL.len(), 0..8).prop_map(|indexes| {
            indexes
                .into_iter()
                .filter_map(|index| Feature::ALL.get(index).copied())
                .collect()
        })
    }

    proptest! {
        /// Negotiation is commutative and never invents a feature. A link agreeing on something the
        /// peer cannot do is the failure this function exists to prevent.
        #[test]
        fn negotiation_is_commutative_and_sound(
            ours in arbitrary_features(),
            theirs in arbitrary_features(),
            required in arbitrary_features(),
        ) {
            let forward = negotiate(&ours, &theirs, &required);
            let backward = negotiate(&theirs, &ours, &required);

            prop_assert_eq!(forward.common.len(), backward.common.len());
            for feature in &forward.common {
                prop_assert!(theirs.contains(feature), "agreed to something the peer lacks");
                prop_assert!(ours.contains(feature), "agreed to something we lack");
            }

            // Every required feature is either available or reported missing, never both and never
            // neither.
            for feature in &required {
                let available = forward.supports(*feature);
                let missing = forward.missing_required.contains(feature);
                prop_assert!(available != missing, "a required feature must be one or the other");
            }
            prop_assert_eq!(forward.is_usable(), forward.missing_required.is_empty());
        }

        /// A token survives the round trip through its hex form for any bytes. Hex encoding is where
        /// a bug silently corrupts a credential.
        #[test]
        fn tokens_round_trip_through_hex(bytes in proptest::array::uniform32(any::<u8>())) {
            let token = LinkToken::from_bytes(bytes);
            let hex = token.to_hex();
            prop_assert_eq!(hex.len(), LinkToken::LEN * 2);
            prop_assert_eq!(LinkToken::from_hex(&hex).expect("round trips"), token);
        }

        /// A rebuildable hello either validates or reports why. It never panics, and anything that
        /// validates survives a trip through JSON unchanged.
        #[test]
        fn hellos_validate_and_round_trip(
            protocol in 0u16..3,
            sequence in any::<u64>(),
            features in arbitrary_features(),
            name_len in 0usize..80,
        ) {
            let hello = Hello {
                protocol,
                device_id: DeviceId::new(),
                display_name: "x".repeat(name_len),
                platform: PlatformKind::Desktop,
                app_version: "1.0.0".to_owned(),
                nonce: SessionNonce(1),
                features,
                requires: Vec::new(),
                token: None,
                sequence,
                endpoints: Vec::new(),
            };

            if hello.validate().is_ok() {
                let json = serde_json::to_string(&hello).expect("serialises");
                let back: Hello = serde_json::from_str(&json).expect("deserialises");
                prop_assert_eq!(back, hello);
            }
            else {
                // A rejected hello is rejected for a reason, never by panicking.
                prop_assert!(hello.validate().is_err());
            }
        }

        /// A sequence guard accepts each value at most once, whatever order they arrive in.
        ///
        /// `SequenceGuard::new()` starts at zero and only accepts strictly greater values, so zero is
        /// legitimately rejected without ever having been accepted. The property tracks that
        /// baseline rather than assuming an empty history.
        #[test]
        fn a_sequence_guard_accepts_each_value_at_most_once(
            values in proptest::collection::vec(any::<u64>(), 0..40)
        ) {
            let mut guard = SequenceGuard::new();
            let mut accepted: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for value in values {
                if guard.accept(value).is_ok() {
                    prop_assert!(accepted.insert(value), "accepted {value} twice");
                }
                else if value > 0 {
                    // A positive value can only be refused if it is not newer than the high-water
                    // mark, which means it was accepted before.
                    prop_assert!(
                        accepted.contains(&value) || value <= guard.highest(),
                        "rejected {value} for no reason",
                    );
                }
            }
            prop_assert_eq!(guard.highest(), accepted.iter().copied().max().unwrap_or(0));
        }
    }
}

    #[test]
    fn a_fresh_link_token_is_unpredictable_and_not_the_zero_value() {
        // Two tokens in a row must differ: a token that repeated would let one paired device's credential open another's
        // link, and a token of zero is what an absent one decays to on the wire, so the real thing must never be it.
        let first = LinkToken::random();
        let second = LinkToken::random();
        assert_ne!(first, second);
        assert_ne!(first.as_bytes(), &[0u8; LinkToken::LEN]);
        assert_ne!(second.as_bytes(), &[0u8; LinkToken::LEN]);

        // And it survives the text form that carries it through a pairing answer into the database.
        let text = first.to_hex();
        assert_eq!(text.len(), LinkToken::LEN * 2);
        assert_eq!(LinkToken::from_hex(&text).expect("a fresh token parses back"), first);
    }