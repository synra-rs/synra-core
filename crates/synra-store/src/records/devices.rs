//! Paired and discovered device rows.

use serde::{Deserialize, Serialize};

use super::{parse_features, required, to_bool, RowError};

/// A device the kernel has paired with.
///
/// # Why `blocked` is a field and not a separate table
///
/// Because it is a property of the pairing, not a list of its own: a blocked device is one that is paired and refused,
/// and a second table would admit a row for a device that is not paired — which is a state the kernel has no behaviour
/// for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    /// The peer's stable identifier.
    pub device_id: String,
    /// What to show a person.
    pub display_name: String,
    /// What the peer said it is.
    pub platform: String,
    /// The features the peer announced at pairing time.
    ///
    /// Stored so a link can be set up without re-negotiating. A JSON array of feature names.
    pub features: Vec<String>,
    /// When the pairing happened.
    pub paired_at_ms: i64,
    /// When the peer was last seen.
    pub last_seen_ms: i64,
    /// Where the peer was last reached, as `host:port`, when this side has ever known.
    ///
    /// `None` rather than an empty string: a device paired over something other than a socket has no address, and a
    /// blank field in a device list is a value somebody reads as a fact.
    pub address: Option<String>,
    /// Whether this device is refused.
    pub blocked: bool,
}

impl DeviceRow {
    /// Builds a row from the text columns `paired_devices` declares, in their order.
    ///
    /// # Why the text columns are one value
    ///
    /// Because they are the ones a query selects as a group and a reader reads as a group, and eight positional
    /// arguments is where a caller starts getting them wrong — the compiler cannot tell `platform` from `features`,
    /// and both are `Option<&str>`. The integers stay separate: there are three of them, they are not interchangeable
    /// with the strings, and a struct for them would be a struct with no other reason to exist.
    ///
    /// # Errors
    ///
    /// [`RowError`] when a `NOT NULL` column is empty, a `CHECK (x IN (0, 1))` column holds something else, or
    /// `features` is not a JSON array of strings.
    ///
    /// # Why the `features` parse is a refusal rather than a fallback
    ///
    /// An unparseable `features` column is a row the kernel cannot build a link from. Falling back to "no features"
    /// would produce a device that pairs and then fails every transfer with a message about a missing feature — pointing
    /// at the peer rather than at the row that is wrong.
    pub fn from_columns(text: DeviceText<'_>, numbers: DeviceNumbers) -> Result<Self, RowError> {
        Ok(Self {
            device_id: required(text.device_id, "device_id")?.to_owned(),
            display_name: required(text.display_name, "display_name")?.to_owned(),
            platform: required(text.platform, "platform")?.to_owned(),
            features: parse_features(required(text.features, "features")?)?,
            paired_at_ms: required(numbers.paired_at_ms, "paired_at_ms")?,
            last_seen_ms: required(numbers.last_seen_ms, "last_seen_ms")?,
            // Optional, and empty is absent: the column was added by a migration, so a row written before it has no
            // value at all, and the write path stores nothing rather than an empty string.
            address: text.address.filter(|address| !address.is_empty()).map(str::to_owned),
            blocked: to_bool(numbers.blocked, "blocked")?,
        })
    }

    /// Whether this device is one the kernel would send to.
    ///
    /// The question the kernel actually asks, so it is a method rather than a condition written at each call site.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        !self.blocked
    }
}

/// The text columns of a `paired_devices` row, as a query returns them.
///
/// Optional in every field because a column the `SELECT` omitted reads as `NULL`, which is what makes a mistake in the
/// column list a named refusal rather than a swapped value.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceText<'a> {
    /// The peer's identifier.
    pub device_id: Option<&'a str>,
    /// Its display name.
    pub display_name: Option<&'a str>,
    /// Its platform.
    pub platform: Option<&'a str>,
    /// Its features, as JSON.
    pub features: Option<&'a str>,
    /// Where it was last reached, when the column is there.
    pub address: Option<&'a str>,
}

/// The integer columns of a `paired_devices` row.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceNumbers {
    /// When the pairing happened.
    pub paired_at_ms: Option<i64>,
    /// When the peer was last seen.
    pub last_seen_ms: Option<i64>,
    /// Whether it is blocked, as the schema's `0`/`1`.
    pub blocked: Option<i64>,
}

/// A sighting of a device this kernel has not paired with.
///
/// The write shape, as opposed to [`SeenDeviceRow`] which is what comes back out. Separate types because one is a claim
/// made by something that heard an announcement and the other is a row the database produced — and a caller that could
/// build a row by hand would be able to invent a `first_seen_ms` that predates the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seen {
    /// The device, as the announcement stated it.
    pub device_id: String,
    /// The name it announced.
    pub display_name: String,
    /// Its platform, as the string the column holds.
    pub platform: String,
    /// When it was heard.
    pub seen_at_ms: i64,
    /// Which path heard it, for a user who needs to know where a device is.
    pub source: String,
}

/// A device the kernel has merely heard from.
///
/// # Why this is a separate type from [`DeviceRow`]
///
/// Because the two have different lifetimes and different columns, and one type would carry the union: a seen device has
/// no pairing time and a `source`, and a paired device has `blocked`. Merging them would make every column about pairing
/// optional, and then nothing in the type would say which fields a paired device is guaranteed to have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenDeviceRow {
    /// The peer's identifier.
    pub device_id: String,
    /// What it called itself.
    pub display_name: String,
    /// What it said it is.
    pub platform: String,
    /// When it was first heard from.
    pub first_seen_ms: i64,
    /// When it was last heard from.
    pub last_seen_ms: i64,
    /// How it was heard from.
    ///
    /// A string rather than an enum, because the discovery layer's set of sources is its own and a variant added there
    /// would be a migration here. What the column is used for is a diagnostic — "where did this name come from" — and a
    /// string answers that without the schema having an opinion.
    pub source: String,
}

impl SeenDeviceRow {

    /// Builds a row from the columns `devices_seen` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        device_id: Option<&str>,
        display_name: Option<&str>,
        platform: Option<&str>,
        first_seen_ms: Option<i64>,
        last_seen_ms: Option<i64>,
        source: Option<&str>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            device_id: required(device_id, "device_id")?.to_owned(),
            display_name: required(display_name, "display_name")?.to_owned(),
            platform: required(platform, "platform")?.to_owned(),
            first_seen_ms: required(first_seen_ms, "first_seen_ms")?,
            last_seen_ms: required(last_seen_ms, "last_seen_ms")?,
            source: required(source, "source")?.to_owned(),
        })
    }
}


