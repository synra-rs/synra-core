//! Typed identifiers.
//!
//! # Why newtypes
//!
//! Every id in this protocol is a UUID, so without wrappers they are interchangeable and the
//! compiler will happily let a `TransferId` be passed where a `RequestId` belongs. That mistake
//! does not fail at the call site; it fails later, as a message nobody can correlate, and it costs
//! an afternoon. Wrapping each one costs a line of code and makes the mistake impossible to write.
//!
//! # Why UUIDv7
//!
//! Time-ordered. Sorting log lines needs no extra column, SQLite primary-key inserts stay
//! append-mostly rather than scattering across the B-tree, and a debug dump of ids reads in the
//! order things happened.
//!
//! # Parsing is strict
//!
//! [`DeviceId::from_str`] and friends reject anything that is not a UUID. There is no "generate a
//! fallback if parsing fails" branch anywhere in this crate: a code path that silently invents an
//! identifier turns a malformed message into a plausible-looking one, which is far harder to find
//! than an error.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Length limit for a [`PluginSlug`].
pub const MAX_PLUGIN_SLUG_LEN: usize = 48;

/// Length limit for a [`PluginId`].
pub const MAX_PLUGIN_ID_LEN: usize = 128;

/// Failure to parse or construct an identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The text is not a UUID.
    #[error("not a UUID")]
    NotUuid,

    /// The text is empty.
    #[error("empty")]
    Empty,

    /// The text is longer than the type allows.
    #[error("too long: {len} > {max}")]
    TooLong {
        /// Observed length in bytes.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },

    /// A character outside the permitted set.
    #[error("invalid character {ch:?} at byte {index}")]
    InvalidCharacter {
        /// The offending character.
        ch: char,
        /// Byte offset where it was found.
        index: usize,
    },

    /// A plugin id is missing its scope.
    #[error("plugin id must be scoped, e.g. @synra-plugin/chat")]
    Unscoped,

    /// The nil UUID, which is never valid as an identifier.
    #[error("nil identifier")]
    Nil,
}

macro_rules! uuid_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps an existing UUID.
            ///
            /// Use this when the value came from a trusted source that already validated it. To
            /// validate untrusted text, use [`FromStr`].
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Whether this is the nil UUID.
            ///
            /// Nil is rejected when parsing, so a value that answers `true` here can only have been
            /// built through [`Self::from_uuid`] or deserialised from a peer that sent one.
            #[must_use]
            pub const fn is_nil(self) -> bool {
                self.0.is_nil()
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(s).map_err(|_| IdError::NotUuid)?;
                if uuid.is_nil() {
                    return Err(IdError::Nil);
                }
                Ok(Self(uuid))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

/// A device. Stable across restarts; it is the identity pairing is recorded against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
    /// Generates a fresh device id.
    ///
    /// Called once, when a device first runs, and then persisted. A device that regenerates its id
    /// on every start appears to its peers as a new device each time, and every pairing is lost.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    /// Whether this is the nil UUID.
    #[must_use]
    pub const fn is_nil(self) -> bool {
        self.0.is_nil()
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for DeviceId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s).map_err(|_| IdError::NotUuid)?;
        if uuid.is_nil() {
            return Err(IdError::Nil);
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

uuid_newtype!(
    /// One send. Used to correlate an acknowledgement and a request with its reply.
    ///
    /// A retry **reuses** the same `RequestId`; that is what makes redelivery idempotent rather than
    /// duplicating the work.
    RequestId
);

uuid_newtype!(
    /// One large-object transfer session.
    ///
    /// Not interchangeable with [`RequestId`]: a transfer spans many frames, each with its own
    /// request id, all sharing one transfer id.
    TransferId
);

uuid_newtype!(
    /// One intent — an action the user asked for, tracked from decision to result.
    IntentId
);

uuid_newtype!(
    /// One discovery scan, so late replies from a previous scan can be discarded.
    ScanId
);

uuid_newtype!(
    /// One file-sync session, grouping transfers that belong together.
    SessionId
);

impl RequestId {
    /// Generates a fresh request id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferId {
    /// Generates a fresh transfer id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for TransferId {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentId {
    /// Generates a fresh intent id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for IntentId {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanId {
    /// Generates a fresh scan id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ScanId {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionId {
    /// Generates a fresh session id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// A trace, shared by every step of one user action.
///
/// A 128-bit value rendered as 32 hex digits, matching the W3C trace-context format, so an existing
/// tracing back end needs no special case for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TraceId(pub u128);

impl TraceId {
    /// Generates a fresh trace.
    #[must_use]
    pub fn new() -> Self {
        Self(random_u128())
    }

    /// The 32-digit lowercase hex form.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }

    /// Whether this is the all-zero trace, which is never valid.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl FromStr for TraceId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(IdError::NotUuid);
        }
        // `from_str_radix` needs a string it can consume; the length check above already rejected
        // anything that could overflow.
        let value = u128::from_str_radix(s, 16).map_err(|_| IdError::NotUuid)?;
        if value == 0 {
            return Err(IdError::Nil);
        }
        Ok(Self(value))
    }
}

/// A random `u128`, from the OS entropy source.
///
/// `uuid` is already a dependency and its v7 generator draws from the same source, so this avoids
/// pulling in `rand` for one call.
fn random_u128() -> u128 {
    // `now_v7` embeds a timestamp in the high bits; XOR-ing two of them, one shifted, spreads the
    // timestamp across the whole word so successive traces do not share a long prefix.
    let a = Uuid::now_v7().as_u128();
    let b = Uuid::now_v7().as_u128().rotate_left(64);
    let mut value = a ^ b;
    // Never zero, so `TraceId::is_zero` is a reliable "unset" check.
    if value == 0 {
        value = 1;
    }
    value
}

/// A plugin's package name, in npm scope form.
///
/// Rule: `@scope/name`. The scope is required — an unscoped plugin id would put every plugin in one
/// flat namespace, and the first collision would be unfixable without renaming a published plugin.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PluginId(String);

impl PluginId {
    /// Parses and validates a plugin id.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Empty`], [`IdError::TooLong`], [`IdError::Unscoped`] or
    /// [`IdError::InvalidCharacter`].
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > MAX_PLUGIN_ID_LEN {
            return Err(IdError::TooLong { len: s.len(), max: MAX_PLUGIN_ID_LEN });
        }
        let rest = s.strip_prefix('@').ok_or(IdError::Unscoped)?;
        let (scope, name) = rest.split_once('/').ok_or(IdError::Unscoped)?;
        if scope.is_empty() || name.is_empty() {
            return Err(IdError::Unscoped);
        }
        // Slashes beyond the one separator are not part of the grammar.
        if name.contains('/') {
            return Err(IdError::Unscoped);
        }
        // `base` is where each part starts in the whole string: the scope begins right after `@`,
        // and the name right after `/`.
        validate_slug_like(scope, 1)?;
        validate_slug_like(name, 2 + scope.len())?;
        Ok(Self(s.to_owned()))
    }

    /// The whole id, including the scope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part after the slash.
    #[must_use]
    pub fn name(&self) -> &str {
        // `parse` guarantees a single slash with non-empty halves, so this cannot fail.
        self.0.split_once('/').map_or(&self.0, |(_, name)| name)
    }

    /// The part between `@` and the slash.
    #[must_use]
    pub fn scope(&self) -> &str {
        self.0
            .strip_prefix('@')
            .and_then(|rest| rest.split_once('/'))
            .map_or("", |(scope, _)| scope)
    }

    /// The slug used in this plugin's event namespace.
    ///
    /// `@synra-plugin/chat` becomes `chat`, and `@imba97/synra-plugin-notes` becomes `notes`, so the
    /// wire name stays short and readable while the package name stays conventional.
    #[must_use]
    pub fn wire_slug(&self) -> PluginSlug {
        let name = self.name();
        let trimmed = name.strip_prefix("synra-plugin-").unwrap_or(name);
        // `PluginId::parse` already restricted the name to the slug character set, so this cannot
        // fail; the fallback keeps the function total rather than panicking.
        PluginSlug::parse(trimmed).unwrap_or(PluginSlug(compact_str::CompactString::from("plugin")))
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for PluginId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PluginId> for String {
    fn from(value: PluginId) -> Self {
        value.0
    }
}

/// Validates the `[a-z0-9][a-z0-9-]*` form.
///
/// `base` is the byte offset at which `part` starts in the string being reported on, so an error
/// message points at a position the reader can find. It is passed in rather than derived from
/// lengths: the length difference gives the right answer only for a part at the *end* of the whole
/// string, which is not where a plugin id's scope lives.
fn validate_slug_like(part: &str, base: usize) -> Result<(), IdError> {
    let mut chars = part.char_indices();

    match chars.next() {
        None => return Err(IdError::Empty),
        Some((offset, ch)) if !(ch.is_ascii_lowercase() || ch.is_ascii_digit()) => {
            return Err(IdError::InvalidCharacter { ch, index: base + offset });
        }
        Some(_) => {}
    }

    for (offset, ch) in chars {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
            return Err(IdError::InvalidCharacter { ch, index: base + offset });
        }
    }
    Ok(())
}

/// The short name a plugin owns on the wire, used in `_plugin.<slug>.…` event names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PluginSlug(compact_str::CompactString);

impl PluginSlug {
    /// Parses and validates a slug.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Empty`], [`IdError::TooLong`] or [`IdError::InvalidCharacter`]. A leading
    /// digit is allowed; a leading or trailing hyphen is not.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > MAX_PLUGIN_SLUG_LEN {
            return Err(IdError::TooLong { len: s.len(), max: MAX_PLUGIN_SLUG_LEN });
        }
        validate_slug_like(s, 0)?;
        // A trailing hyphen reads as a truncation and is easy to produce by accident when building
        // a slug from a package name.
        if s.ends_with('-') {
            return Err(IdError::InvalidCharacter {
                ch: '-',
                index: s.len() - 1,
            });
        }
        Ok(Self(compact_str::CompactString::from(s)))
    }

    /// The slug text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PluginSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl TryFrom<String> for PluginSlug {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PluginSlug> for String {
    fn from(value: PluginSlug) -> Self {
        value.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_ids_are_time_ordered() {
        let first = DeviceId::new();
        // UUIDv7 puts a millisecond timestamp in the high bits, so successive ids ascend. This is
        // the property the module docs rely on for log ordering.
        let second = DeviceId::new();
        assert!(first <= second, "{first} should not exceed {second}");
    }

    #[test]
    fn ids_round_trip_through_text() {
        let id = RequestId::new();
        let parsed: RequestId = id.to_string().parse().expect("round trips");
        assert_eq!(parsed, id);
    }

    #[test]
    fn ids_round_trip_through_json_as_bare_strings() {
        // `serde(transparent)` matters: a peer expects `"0193…"`, not `{"0": …}`.
        let id = DeviceId::new();
        let json = serde_json::to_string(&id).expect("serialises");
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let back: DeviceId = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, id);
    }

    #[test]
    fn parsing_rejects_non_uuids() {
        assert_eq!("not-a-uuid".parse::<DeviceId>(), Err(IdError::NotUuid));
        assert_eq!("".parse::<DeviceId>(), Err(IdError::NotUuid));
        // A valid-looking but truncated uuid.
        assert_eq!("0193abcd-0000-7000".parse::<DeviceId>(), Err(IdError::NotUuid));
    }

    #[test]
    fn parsing_rejects_the_nil_uuid() {
        let nil = "00000000-0000-0000-0000-000000000000";
        assert_eq!(nil.parse::<DeviceId>(), Err(IdError::Nil));
        assert_eq!(nil.parse::<TraceId>(), Err(IdError::NotUuid));
    }

    #[test]
    fn different_id_types_are_not_interchangeable() {
        // Compile-time in practice; this test documents the intent. If `RequestId` and `TransferId`
        // were both plain `Uuid`, the two locals below would be assignable to each other.
        let request = RequestId::new();
        let transfer = TransferId::new();
        assert_ne!(request.as_uuid(), transfer.as_uuid());
    }

    #[test]
    fn trace_id_hex_is_32_digits() {
        let trace = TraceId::new();
        let hex = trace.to_hex();
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(trace.to_string(), hex);
    }

    #[test]
    fn trace_id_never_zero() {
        for _ in 0..64 {
            assert!(!TraceId::new().is_zero());
        }
    }

    #[test]
    fn trace_id_round_trips_through_hex() {
        let trace = TraceId::new();
        let parsed: TraceId = trace.to_hex().parse().expect("round trips");
        assert_eq!(parsed, trace);
    }

    #[test]
    fn trace_id_rejects_wrong_length_and_zero() {
        assert!("abc".parse::<TraceId>().is_err());
        assert!("0".repeat(32).parse::<TraceId>().is_err());
        assert!("z".repeat(32).parse::<TraceId>().is_err());
    }

    #[test]
    fn plugin_id_requires_a_scope() {
        assert_eq!(PluginId::parse("chat"), Err(IdError::Unscoped));
        assert_eq!(PluginId::parse("@synra-plugin"), Err(IdError::Unscoped));
        assert_eq!(PluginId::parse("@synra-plugin/"), Err(IdError::Unscoped));
        assert_eq!(PluginId::parse("@/chat"), Err(IdError::Unscoped));
        // A second slash is outside the grammar.
        assert_eq!(PluginId::parse("@a/b/c"), Err(IdError::Unscoped));
    }

    #[test]
    fn plugin_id_splits_into_scope_and_name() {
        let id = PluginId::parse("@synra-plugin/github-bridge").expect("valid");
        assert_eq!(id.scope(), "synra-plugin");
        assert_eq!(id.name(), "github-bridge");
        assert_eq!(id.as_str(), "@synra-plugin/github-bridge");
    }

    #[test]
    fn plugin_id_rejects_bad_characters() {
        assert!(matches!(
            PluginId::parse("@Synra/chat"),
            Err(IdError::InvalidCharacter { ch: 'S', .. })
        ));
        assert!(matches!(
            PluginId::parse("@synra/chat_bot"),
            Err(IdError::InvalidCharacter { ch: '_', .. })
        ));
        // A leading hyphen is not a valid start.
        assert!(matches!(
            PluginId::parse("@synra/-chat"),
            Err(IdError::InvalidCharacter { ch: '-', .. })
        ));
    }

    #[test]
    fn plugin_id_points_at_the_offending_character() {
        // The offset must be into the whole string, or an error message sends the reader to the
        // wrong place. `@ok/baD`: `@`=0 `o`=1 `k`=2 `/`=3 `b`=4 `a`=5 `D`=6.
        let err = PluginId::parse("@ok/baD").expect_err("invalid");
        assert_eq!(err, IdError::InvalidCharacter { ch: 'D', index: 6 });

        // And in the scope half.
        let err = PluginId::parse("@oK/chat").expect_err("invalid");
        assert_eq!(err, IdError::InvalidCharacter { ch: 'K', index: 2 });
    }

    #[test]
    fn plugin_id_enforces_length() {
        let long = format!("@{}", "a".repeat(MAX_PLUGIN_ID_LEN));
        assert!(matches!(PluginId::parse(&long), Err(IdError::TooLong { .. })));
    }

    #[test]
    fn wire_slug_strips_the_conventional_prefix() {
        assert_eq!(
            PluginId::parse("@synra-plugin/chat").expect("valid").wire_slug().as_str(),
            "chat"
        );
        assert_eq!(
            PluginId::parse("@imba97/synra-plugin-notes").expect("valid").wire_slug().as_str(),
            "notes"
        );
        // A name without the prefix is used as-is.
        assert_eq!(
            PluginId::parse("@acme/formatter").expect("valid").wire_slug().as_str(),
            "formatter"
        );
    }

    #[test]
    fn plugin_slug_validation() {
        assert!(PluginSlug::parse("chat").is_ok());
        assert!(PluginSlug::parse("chat-2").is_ok());
        assert!(PluginSlug::parse("2chat").is_ok());

        assert_eq!(PluginSlug::parse(""), Err(IdError::Empty));
        assert!(matches!(
            PluginSlug::parse("-chat"),
            Err(IdError::InvalidCharacter { ch: '-', .. })
        ));
        assert!(matches!(
            PluginSlug::parse("chat-"),
            Err(IdError::InvalidCharacter { ch: '-', .. })
        ));
        assert!(matches!(
            PluginSlug::parse("Chat"),
            Err(IdError::InvalidCharacter { ch: 'C', .. })
        ));
        assert!(matches!(
            PluginSlug::parse("a".repeat(MAX_PLUGIN_SLUG_LEN + 1).as_str()),
            Err(IdError::TooLong { .. })
        ));
    }

    #[test]
    fn plugin_id_and_slug_round_trip_through_json() {
        let id = PluginId::parse("@synra-plugin/chat").expect("valid");
        let json = serde_json::to_string(&id).expect("serialises");
        assert_eq!(json, "\"@synra-plugin/chat\"");
        let back: PluginId = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, id);

        // An invalid id must not deserialise: validation happens on the way in, so a value of this
        // type is always well-formed.
        assert!(serde_json::from_str::<PluginId>("\"chat\"").is_err());
    }
}
