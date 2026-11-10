//! Trace identifiers and their wire representation.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::IdError;

/// A trace, shared by every step of one user action.
///
/// A 128-bit value rendered as 32 hex digits, matching the W3C trace-context format, so an existing
/// tracing back end needs no special case for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TraceId(pub u128);

// ★ `TraceId` serialises as **32 hex digits**, not as the number it holds.
//
// It derived `Serialize` over its `u128` to begin with, with `#[serde(transparent)]` — so a trace went over the wire as a
// bare 128-bit JSON number. Three things were wrong with that at once:
//
// 1. the type's own documentation says "a 128-bit value **rendered as 32 hex digits**, matching the W3C trace-context
//    format" — and a number is not that;
// 2. `synra-js` publishes `export type TraceId = string` (`wire.d.ts`), so the Rust side and the TypeScript side disagreed
//    about the type of the same field;
// 3. a JSON number of 128 bits is not representable: `serde_json::Value` refuses it outright with "number out of range",
//    and JavaScript's `JSON.parse` would silently round it — a trace id that is *nearly* right is worse than none, because
//    it correlates the wrong steps and looks like it worked.
//
// The hex form is what W3C trace context uses and what the rest of this type already assumed.
impl Serialize for TraceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TraceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        // ★ At most 32 digits, and every one of them hex. Leading zeros are allowed to be absent so that a value written
        // by hand — `"1"` — reads back as the same trace rather than being refused for not being padded.
        if text.is_empty() || text.len() > 32 || !text.chars().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(format!(
                "`{text}` is not a trace: at most 32 hex digits"
            )));
        }
        u128::from_str_radix(&text, 16).map(TraceId).map_err(serde::de::Error::custom)
    }
}

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


