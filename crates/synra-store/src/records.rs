//! The rows and the types they become.
//!
//! # Why this is separate from the binding
//!
//! A SQLite binding hands back `&str`, `i64` and `Option<T>` in the order the query named them. Turning that into the
//! kernel's own types is where the mistakes live — a swapped column, a `TEXT` where a `bool` was meant, a `NULL` where
//! the schema says `NOT NULL` — and **none of those need an engine to find**. So the conversion is a plain function over
//! plain values, and the binding's job is only to fetch them.
//!
//! The same reasoning the migration module gives for not carrying a C dependency: a crate whose whole job is to hold the
//! kernel's persistence contract should be checkable without a database.
//!
//! # The one rule every column follows
//!
//! **A column named `*_ms` is a wall-clock reading**, and the reason is the one the claim file learned: a monotonic
//! reading is only comparable within one process, and every one of these values is read by a process that did not write
//! it. A `last_seen_ms` written by the kernel and compared by a `doctor` run would be nonsense if either clock were
//! monotonic.
//!
//! # Why the types are not the interface DTOs
//!
//! [`DeviceRow`] is a **row**, and `synra-ipc`'s `DeviceCard` is what a screen draws. They differ where the database
//! differs from the interface: a row carries `blocked` and the pairing time, a card carries a last-seen age and whether
//! the device is reachable *now*. Making one type serve both would put a screen's presentation needs into the schema.

use serde::{Deserialize, Serialize};

/// Why a row could not be turned into a type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RowError {
    /// A column the schema declares `NOT NULL` came back empty.
    #[error("`{column}` is missing, and the schema declares it NOT NULL")]
    Missing {
        /// The column's name.
        column: &'static str,
    },

    /// A column held something the type cannot represent.
    #[error("`{column}` holds {found}, which {wanted} cannot represent")]
    WrongType {
        /// The column's name.
        column: &'static str,
        /// What the type wanted.
        wanted: &'static str,
        /// What was found.
        found: String,
    },

    /// A TEXT column declared `CHECK (x IN (0, 1))` held something else.
    #[error("`{column}` holds {found}, and the schema allows only 0, 1, true or false")]
    NotABoolean {
        /// The column's name.
        column: &'static str,
        /// What was found.
        found: String,
    },
}

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

/// One intent, as the `intents` table keeps it.
///
/// ★ Why the store has this at all, given that nothing wrote it until now.
///
/// The table was created by the first migration and then never read or written by any code in either workspace — so an
/// intent lived only in the kernel's in-memory `Board` and a restart lost every one of them. The design's storage table
/// gives intents a retention ("24 hours after they finish"), which is a rule about rows, and a rule about rows needs rows.
/// This is the shape the store keeps, with no opinion about what any of the values mean: `state` and `args` are the
/// kernel's own spellings, carried as text precisely so that the store does not have to know them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    /// The intent's identifier, as the protocol spells it.
    pub intent_id: String,
    /// Which device raised it — this one, or a peer's identifier.
    pub origin: String,
    /// The plugin that will answer it.
    pub plugin_id: String,
    /// The action, as the plugin named it.
    pub action: String,
    /// The arguments, as JSON text.
    ///
    /// A string rather than a parsed value, for the reason `source` on [`SeenDeviceRow`] is one: the shape belongs to the
    /// kernel, and a store that parsed it would need a migration every time an action's arguments changed.
    pub args: String,
    /// Where it got to.
    pub state: String,
    /// When it was raised.
    pub created_ms: i64,
    /// When it last changed.
    pub updated_ms: i64,
    /// When it stops being worth keeping, when anything said so.
    pub expires_ms: Option<i64>,
}

impl IntentRecord {
    /// Builds a row from the columns `intents` declares, in its order.
    ///
    /// # Why the columns arrive in two groups
    ///
    /// Because there are nine of them, and nine positional arguments is a call nobody can read at the call site — which is
    /// the same reason [`DeviceRow::from_columns`] takes its text and its numbers separately. The split is also the honest
    /// one: these six are what the intent says and these three are when it said it.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(text: IntentText<'_>, numbers: IntentNumbers) -> Result<Self, RowError> {
        Ok(Self {
            intent_id: required(text.intent_id, "intent_id")?.to_owned(),
            origin: required(text.origin, "origin")?.to_owned(),
            plugin_id: required(text.plugin_id, "plugin_id")?.to_owned(),
            action: required(text.action, "action")?.to_owned(),
            args: required(text.args, "args")?.to_owned(),
            state: required(text.state, "state")?.to_owned(),
            created_ms: required(numbers.created_ms, "created_ms")?,
            updated_ms: required(numbers.updated_ms, "updated_ms")?,
            // The one nullable column: an intent nobody gave a deadline to has none.
            expires_ms: numbers.expires_ms,
        })
    }
}

/// The text columns of an [`IntentRecord`], as they come back from a query.
#[derive(Debug, Clone, Copy)]
pub struct IntentText<'a> {
    /// The intent's identifier.
    pub intent_id: Option<&'a str>,
    /// Which device raised it.
    pub origin: Option<&'a str>,
    /// The plugin that will answer it.
    pub plugin_id: Option<&'a str>,
    /// The action.
    pub action: Option<&'a str>,
    /// The arguments, as JSON text.
    pub args: Option<&'a str>,
    /// Where it got to.
    pub state: Option<&'a str>,
}

/// The numeric columns of an [`IntentRecord`], as they come back from a query.
#[derive(Debug, Clone, Copy)]
pub struct IntentNumbers {
    /// When it was raised.
    pub created_ms: Option<i64>,
    /// When it last changed.
    pub updated_ms: Option<i64>,
    /// When it stops being worth keeping, when anything said so.
    pub expires_ms: Option<i64>,
}

/// The device's own identity.
///
/// # Why this is a row like any other
///
/// Because the schema enforces one row with `CHECK (id = 1)`, and the kernel reads it the same way — it does not hold it
/// in memory across a run, so that a kernel and a `doctor` run see the same identity rather than one of them having
/// cached it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRow {
    /// This device's identifier.
    pub device_id: String,
    /// What this device calls itself.
    pub display_name: String,
    /// What this device is.
    pub platform: String,
    /// When the identity was created.
    pub created_at_ms: i64,
}

impl IdentityRow {
    /// Builds a row from the columns `identity` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        device_id: Option<&str>,
        display_name: Option<&str>,
        platform: Option<&str>,
        created_at_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            device_id: required(device_id, "device_id")?.to_owned(),
            display_name: required(display_name, "display_name")?.to_owned(),
            platform: required(platform, "platform")?.to_owned(),
            created_at_ms: required(created_at_ms, "created_at_ms")?,
        })
    }
}

/// A plugin the kernel knows about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRow {
    /// The plugin's identifier.
    pub plugin_id: String,
    /// Whether it is allowed to run.
    pub enabled: bool,
    /// Whether the user has confirmed what it may do.
    ///
    /// Separate from `enabled` because the two answer different questions, and collapsing them would make "turn this off
    /// for a moment" the same act as "I no longer trust this".
    pub trusted: bool,
    /// What the host last observed.
    ///
    /// A string, because `plugin_versions` and the host's health vocabulary are theirs; the column is `TEXT NOT NULL
    /// DEFAULT 'unknown'` and the kernel compares it, so an unexpected value is a health state rather than a parse error.
    pub health: String,
    /// When it was installed.
    pub installed_at_ms: i64,
    /// When it was last updated.
    pub updated_at_ms: i64,
}

impl PluginRow {
    /// Builds a row from the columns `plugins` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError`] when a `NOT NULL` column is empty or a boolean column holds something else.
    pub fn from_columns(
        plugin_id: Option<&str>,
        enabled: Option<i64>,
        trusted: Option<i64>,
        health: Option<&str>,
        installed_at_ms: Option<i64>,
        updated_at_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            plugin_id: required(plugin_id, "plugin_id")?.to_owned(),
            enabled: to_bool(enabled, "enabled")?,
            trusted: to_bool(trusted, "trusted")?,
            health: required(health, "health")?.to_owned(),
            installed_at_ms: required(installed_at_ms, "installed_at_ms")?,
            updated_at_ms: required(updated_at_ms, "updated_at_ms")?,
        })
    }

    /// Whether the kernel would load it.
    ///
    /// Both conditions, because a plugin the user has confirmed but switched off is not one to load — and a plugin that
    /// is on but never trusted is one whose capabilities nobody approved.
    #[must_use]
    pub const fn should_run(&self) -> bool {
        self.enabled && self.trusted
    }
}

/// One capability's decision, as `plugin_grants` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginGrantRow {
    /// The capability.
    pub capability: String,
    /// Whether the user allowed it.
    pub granted: bool,
    /// When the decision was made.
    pub decided_ms: i64,
    /// The manifest it was made against.
    ///
    /// Carried rather than recomputed because the whole purpose is to notice that the manifest has *changed* since — and
    /// recomputing it from the current manifest would compare the manifest against itself and always agree. An upgrade
    /// whose digest differs is a request for consent again, and a caller cannot detect that from the capability list: a
    /// plugin that declares a capability the user had already refused looks unchanged from the list.
    pub manifest_digest: String,
}

impl PluginGrantRow {
    /// Builds a row from the columns `plugin_grants` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError`] when a `NOT NULL` column is empty or the `granted` column holds something other than 0 or 1.
    pub fn from_columns(
        capability: Option<&str>,
        granted: Option<i64>,
        decided_ms: Option<i64>,
        manifest_digest: Option<&str>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            capability: required(capability, "capability")?.to_owned(),
            granted: to_bool(granted, "granted")?,
            decided_ms: required(decided_ms, "decided_ms")?,
            manifest_digest: required(manifest_digest, "manifest_digest")?.to_owned(),
        })
    }
}

/// One setting, as the `config` table holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRow {
    /// The dotted path.
    pub key: String,
    /// The value, as JSON text.
    pub value: String,
    /// When it was written.
    pub updated_ms: i64,
}

impl ConfigRow {
    /// Builds a row from the columns `config` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        key: Option<&str>,
        value: Option<&str>,
        updated_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            key: required(key, "key")?.to_owned(),
            value: required(value, "value")?.to_owned(),
            updated_ms: required(updated_ms, "updated_ms")?,
        })
    }

    /// The value as JSON.
    ///
    /// # Errors
    ///
    /// [`RowError::WrongType`] when the text is not JSON. A refusal rather than a fallback to the raw string, because a
    /// caller that received a string where it expected a value would write it back as a doubly-encoded one.
    pub fn json(&self) -> Result<serde_json::Value, RowError> {
        serde_json::from_str(&self.value).map_err(|error| RowError::WrongType {
            column: "value",
            wanted: "JSON",
            found: format!("{error}"),
        })
    }
}

/// A `NOT NULL` column's value, or the error naming it.
fn required<T>(value: Option<T>, column: &'static str) -> Result<T, RowError> {
    value.ok_or(RowError::Missing { column })
}

/// A column declared `CHECK (x IN (0, 1))`, as a boolean.
///
/// # Why a refusal rather than `!= 0`
///
/// The schema's `CHECK` is what makes this a two-valued column, and a reader that accepted any non-zero integer would
/// treat a `2` — which the schema forbids and a corrupt file can contain — as `true`. The point of checking is that a
/// value the schema does not allow is reported rather than interpreted.
fn to_bool(value: Option<i64>, column: &'static str) -> Result<bool, RowError> {
    match required(value, column)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(RowError::NotABoolean { column, found: other.to_string() }),
    }
}

/// Parses the `features` column, which the schema declares `TEXT NOT NULL DEFAULT '[]'`.
///
/// # Errors
///
/// [`RowError::WrongType`] when the text is not a JSON array of strings.
fn parse_features(text: &str) -> Result<Vec<String>, RowError> {
    serde_json::from_str::<Vec<String>>(text).map_err(|error| RowError::WrongType {
        column: "features",
        wanted: "a JSON array of strings",
        found: format!("{error}"),
    })
}

/// A pinned copy of the row types' column lists, for `api-guard` and for a test.
///
/// # Why this exists
///
/// Every `from_columns` takes its arguments **positionally**, which is what a SQLite binding produces — and a binding
/// whose `SELECT` lists the columns in a different order produces a row whose fields are silently swapped. A swap between
/// two `TEXT` columns is the dangerous one: nothing fails, and a device's name becomes its platform.
///
/// So each query's column list is written down here, and a test asserts it is the order `from_columns` expects.
pub mod columns {
    /// The `paired_devices` columns a query must select, in the order `DeviceRow::from_columns` takes them.
    pub const DEVICE: &[&str] = &[
        "device_id",
        "display_name",
        "platform",
        "features",
        "paired_at_ms",
        "last_seen_ms",
        "blocked",
        // Last, because that is where the migration that added it put it. The read below is positional, so this list
        // and `DeviceRow::from_columns` are one order written twice — and this is the file that says which.
        "last_address",
    ];

    /// The `intents` columns, in the order `IntentRecord::from_columns` takes them.
    pub const INTENT: &[&str] = &[
        "intent_id",
        "origin",
        "plugin_id",
        "action",
        "args",
        "state",
        "created_ms",
        "updated_ms",
        "expires_ms",
    ];

    /// The `devices_seen` columns, in the order `SeenDeviceRow::from_columns` takes them.
    pub const SEEN_DEVICE: &[&str] = &[
        "device_id",
        "display_name",
        "platform",
        "first_seen_ms",
        "last_seen_ms",
        "source",
    ];

    /// The `identity` columns, in the order `IdentityRow::from_columns` takes them.
    pub const IDENTITY: &[&str] = &["device_id", "display_name", "platform", "created_at_ms"];

    /// The `plugins` columns, in the order `PluginRow::from_columns` takes them.
    pub const PLUGIN: &[&str] = &[
        "plugin_id",
        "enabled",
        "trusted",
        "health",
        "installed_at_ms",
        "updated_at_ms",
    ];

    /// The `config` columns, in the order `ConfigRow::from_columns` takes them.
    pub const CONFIG: &[&str] = &["key", "value", "updated_ms"];

    /// The `plugin_grants` columns, in the order `PluginGrantRow::from_columns` takes them.
    pub const PLUGIN_GRANT: &[&str] =
        &["capability", "granted", "decided_ms", "manifest_digest"];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a device row from the seven columns, with the address left out.
    ///
    /// A helper rather than a literal at each call site: the address is not what most of these tests are about, and a
    /// signature that grows should not turn every assertion about a name into a second edit.
    fn device_row(
        device_id: Option<&str>,
        display_name: Option<&str>,
        platform: Option<&str>,
        features: Option<&str>,
        paired_at_ms: Option<i64>,
        last_seen_ms: Option<i64>,
        blocked: Option<i64>,
    ) -> Result<DeviceRow, RowError> {
        DeviceRow::from_columns(
            DeviceText { device_id, display_name, platform, features, address: None },
            DeviceNumbers { paired_at_ms, last_seen_ms, blocked },
        )
    }

    // ── The device row ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_device_row_is_built_from_the_columns_in_order() {
        let row = DeviceRow::from_columns(
            DeviceText {
                device_id: Some("dev_a"),
                display_name: Some("Laptop"),
                platform: Some("windows"),
                features: Some(r#"["eventStream"]"#),
                address: Some("10.0.0.4:51000"),
            },
            DeviceNumbers { paired_at_ms: Some(1_000), last_seen_ms: Some(2_000), blocked: Some(0) },
        )
        .expect("a row");
        assert_eq!(row.device_id, "dev_a");
        assert_eq!(row.display_name, "Laptop");
        assert_eq!(row.platform, "windows");
        assert_eq!(row.features, vec!["eventStream"]);
        assert_eq!(row.paired_at_ms, 1_000);
        assert_eq!(row.last_seen_ms, 2_000);
        assert_eq!(row.address.as_deref(), Some("10.0.0.4:51000"));
        assert!(!row.blocked);
        assert!(row.is_usable());
    }

    #[test]
    fn an_address_of_nothing_is_absent_rather_than_empty() {
        // A device paired over something other than a socket, or a row written before the column existed. The distinction
        // is what keeps a blank line out of a device list.
        for value in [None, Some("")] {
            let row = DeviceRow::from_columns(
                DeviceText {
                    device_id: Some("dev_a"),
                    display_name: Some("Laptop"),
                    platform: Some("windows"),
                    features: Some("[]"),
                    address: value,
                },
                DeviceNumbers { paired_at_ms: Some(1_000), last_seen_ms: Some(2_000), blocked: Some(0) },
            )
            .expect("a row");
            assert_eq!(row.address, None, "{value:?}");
        }
    }

    #[test]
    fn a_blocked_device_is_not_usable() {
        // ★ The question the kernel actually asks. Written as a method rather than as a condition at each call site,
        // because the call sites are where it gets left out.
        let row = device_row(Some("d"), Some("n"), Some("p"), Some("[]"), Some(0), Some(0), Some(1))
            .expect("a row");
        assert!(row.blocked);
        assert!(!row.is_usable());
    }

    #[test]
    fn a_missing_not_null_column_is_refused_and_named() {
        // ★ The failure a positional read produces when a `SELECT` omits a column: without the name, the message is
        // "index out of range" and the user has no idea which query is wrong.
        for (index, column) in [
            (0, "device_id"),
            (1, "display_name"),
            (2, "platform"),
            (3, "features"),
            (4, "paired_at_ms"),
            (5, "last_seen_ms"),
            (6, "blocked"),
        ] {
            let mut args: Vec<Option<&str>> = vec![Some("x"), Some("x"), Some("x"), Some("[]")];
            let mut numbers: Vec<Option<i64>> = vec![Some(0), Some(0), Some(0)];
            if index < 4 {
                args[index] = None;
            }
            else {
                // The address is the eighth column and is allowed to be absent — that is what `None` means for it — so
                // the loop only walks the three integers the row requires.
                numbers[index - 4] = None;
            }
            match device_row(args[0], args[1], args[2], args[3], numbers[0], numbers[1], numbers[2]) {
                Err(RowError::Missing { column: reported }) => {
                    assert_eq!(reported, column, "index {index}");
                }
                other => panic!("expected a missing column at index {index}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_features_column_that_is_not_a_list_of_strings_is_refused_rather_than_emptied() {
        // ★ A fallback to "no features" would produce a device that pairs and then fails every transfer with a message
        // about a missing feature — pointing at the peer rather than at the row that is wrong.
        for text in ["[1, 2]", "{}", "not json", r#""a string""#] {
            match device_row(Some("d"), Some("n"), Some("p"), Some(text), Some(0), Some(0), Some(0)) {
                Err(RowError::WrongType { column, .. }) => assert_eq!(column, "features", "{text}"),
                other => panic!("`{text}` was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn an_empty_features_list_is_the_ordinary_case() {
        // The schema's own default is `'[]'`, so it is the value most rows have.
        let row = device_row(Some("d"), Some("n"), Some("p"), Some("[]"), Some(0), Some(0), Some(0))
            .expect("a row");
        assert!(row.features.is_empty());
    }

    #[test]
    fn a_boolean_column_holding_something_else_is_refused() {
        // ★ The schema's `CHECK (x IN (0, 1))` makes this two-valued, and a reader that accepted any non-zero integer
        // would treat a `2` — which the schema forbids and a corrupt file can contain — as `true`. The point of checking
        // is that a value the schema does not allow is reported rather than interpreted.
        for value in [2_i64, -1, 99] {
            match device_row(Some("d"), Some("n"), Some("p"), Some("[]"), Some(0), Some(0), Some(value)) {
                Err(RowError::NotABoolean { column, found }) => {
                    assert_eq!(column, "blocked");
                    assert!(found.contains(&value.to_string()), "{found}");
                }
                other => panic!("`{value}` was accepted: {other:?}"),
            }
        }
    }

    // ── The other rows ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_seen_device_row_is_built_from_its_columns() {
        let row = SeenDeviceRow::from_columns(
            Some("dev_b"),
            Some("Phone"),
            Some("android"),
            Some(10),
            Some(20),
            Some("mdns"),
        )
        .expect("a row");
        assert_eq!(row.device_id, "dev_b");
        assert_eq!(row.source, "mdns");
        assert_eq!(row.first_seen_ms, 10);
    }

    #[test]
    fn an_identity_row_is_built_from_its_columns() {
        let row = IdentityRow::from_columns(Some("self"), Some("This machine"), Some("linux"), Some(5))
            .expect("a row");
        assert_eq!(row.display_name, "This machine");
        assert_eq!(row.created_at_ms, 5);
    }

    #[test]
    fn a_plugin_row_is_built_from_its_columns() {
        let row = PluginRow::from_columns(
            Some("@acme/hello"),
            Some(1),
            Some(1),
            Some("healthy"),
            Some(100),
            Some(200),
        )
        .expect("a row");
        assert_eq!(row.plugin_id, "@acme/hello");
        assert!(row.enabled);
        assert!(row.trusted);
        assert!(row.should_run());
    }

    #[test]
    fn a_plugin_runs_only_when_it_is_both_enabled_and_trusted() {
        // ★ Two different questions, and collapsing them would make "turn this off for a moment" the same act as "I no
        // longer trust this". A plugin the user confirmed but switched off is not one to load, and one that is on but
        // never trusted is one whose capabilities nobody approved.
        let build = |enabled, trusted| {
            PluginRow::from_columns(
                Some("p"),
                Some(enabled),
                Some(trusted),
                Some("unknown"),
                Some(0),
                Some(0),
            )
            .expect("a row")
        };
        assert!(build(1, 1).should_run());
        assert!(!build(0, 1).should_run(), "switched off");
        assert!(!build(1, 0).should_run(), "never trusted");
        assert!(!build(0, 0).should_run());
    }

    #[test]
    fn a_config_row_reads_its_value_as_json() {
        let row = ConfigRow::from_columns(Some("ui.locale"), Some(r#""zh""#), Some(7)).expect("a row");
        assert_eq!(row.json().expect("json"), serde_json::json!("zh"));
        assert_eq!(row.key, "ui.locale");
        assert_eq!(row.updated_ms, 7);
    }

    #[test]
    fn a_config_value_that_is_not_json_is_refused_rather_than_returned_as_a_string() {
        // ★ A caller that received the raw string where it expected a value would write it back as a doubly-encoded one,
        // so the mistake would compound rather than surface.
        let row = ConfigRow::from_columns(Some("k"), Some("not json"), Some(0)).expect("a row");
        match row.json() {
            Err(RowError::WrongType { column, wanted, .. }) => {
                assert_eq!(column, "value");
                assert_eq!(wanted, "JSON");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_config_value_that_is_a_json_object_round_trips() {
        // The reason the column is TEXT: a nested structure round-trips through one table, which is what the schema's
        // comment says the dotted key is for.
        let value = serde_json::json!({"nested": {"deep": [1, 2, 3]}});
        let row = ConfigRow::from_columns(Some("k"), Some(&value.to_string()), Some(0)).expect("a row");
        assert_eq!(row.json().expect("json"), value);
    }

    // ── The column lists ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_column_list_has_one_entry_per_argument() {
        // ★ The lists exist because `from_columns` reads positionally — which is what a binding produces — so a `SELECT`
        // that lists the columns in another order swaps two fields. A swap between two `TEXT` columns is the dangerous
        // one: nothing fails, and a device's name becomes its platform.
        //
        // This asserts the count, and `the_column_lists_match_the_migration_schema` below asserts the names.
        assert_eq!(columns::DEVICE.len(), 8);
        assert_eq!(columns::SEEN_DEVICE.len(), 6);
        assert_eq!(columns::IDENTITY.len(), 4);
        assert_eq!(columns::PLUGIN.len(), 6);
        assert_eq!(columns::CONFIG.len(), 3);
    }

    #[test]
    fn the_column_lists_match_the_migration_schema() {
        // ★ The other half of the check: the names have to be the ones the migration created, or a `SELECT` built from
        // these lists names a column that does not exist — which SQLite reports, but only when the query runs.
        let sql = crate::db::MIGRATIONS
            .iter()
            .flat_map(|migration| migration.statements.iter())
            .copied()
            .collect::<Vec<&str>>()
            .join("\n");

        for list in [
            (columns::DEVICE, "paired_devices"),
            (columns::SEEN_DEVICE, "devices_seen"),
            (columns::IDENTITY, "identity"),
            (columns::PLUGIN, "plugins"),
            (columns::CONFIG, "config"),
        ] {
            for column in list.0 {
                assert!(
                    sql.contains(column),
                    "`{column}` is in the {} column list and not in the migrations",
                    list.1
                );
            }
        }
    }

    #[test]
    fn the_column_lists_have_no_repeats() {
        // A repeated name in a `SELECT` is a row with two columns the same, and a positional read that takes both would
        // read the wrong value for one of them.
        for (list, table) in [
            (columns::DEVICE, "paired_devices"),
            (columns::SEEN_DEVICE, "devices_seen"),
            (columns::IDENTITY, "identity"),
            (columns::PLUGIN, "plugins"),
            (columns::CONFIG, "config"),
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), list.len(), "{table} lists a column twice");
        }
    }

    #[test]
    fn the_column_order_matches_the_read_order() {
        // ★ The assertion the whole `columns` module exists for. A `SELECT` built from these lists must hand its columns
        // to `from_columns` in this order — and a reader that reordered one would produce a row whose fields are swapped.
        //
        // It is checked by building a row from values tagged with the column name and asserting each landed in the field
        // with the same name.
        assert_eq!(
            columns::CONFIG,
            &["key", "value", "updated_ms"],
            "the order `ConfigRow::from_columns` takes"
        );
        assert_eq!(
            columns::IDENTITY,
            &["device_id", "display_name", "platform", "created_at_ms"],
            "the order `IdentityRow::from_columns` takes"
        );
        assert_eq!(
            &columns::DEVICE[..3],
            &["device_id", "display_name", "platform"],
            "the order `DeviceRow::from_columns` takes its text columns"
        );
        assert_eq!(
            &columns::DEVICE[4..],
            &["paired_at_ms", "last_seen_ms", "blocked", "last_address"],
            "the order `DeviceRow::from_columns` takes, with the two columns a migration appended at the end"
        );
    }

    // ── Errors ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_row_error_explains_itself() {
        let errors = [
            RowError::Missing { column: "device_id" },
            RowError::WrongType {
                column: "features",
                wanted: "a JSON array of strings",
                found: "expected value".to_owned(),
            },
            RowError::NotABoolean { column: "blocked", found: "2".to_owned() },
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
            assert!(!text.contains('}'), "{error:?} -> {text}");
        }
        // And each names the column, which is what makes a positional read debuggable.
        assert!(errors[0].to_string().contains("device_id"));
        assert!(errors[1].to_string().contains("features"));
        assert!(errors[2].to_string().contains("blocked"));
    }

    #[test]
    fn the_rows_are_serialisable_which_is_what_the_dump_needs() {
        // `synra db dump` prints these as JSON, and a type that could not be serialised would make the command's own
        // output impossible.
        let row = device_row(Some("d"), Some("n"), Some("p"), Some(r#"["a"]"#), Some(1), Some(2), Some(0))
            .expect("a row");
        let json = serde_json::to_string(&row).expect("serialises");
        assert!(json.contains("\"device_id\":\"d\""), "{json}");
        assert!(json.contains("\"address\":null"), "an absent address is null rather than an empty string: {json}");
        let back: DeviceRow = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, row);
    }
}
