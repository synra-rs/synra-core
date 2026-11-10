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

mod config;
mod devices;
mod identity;
mod intents;
mod plugins;
mod sync;

pub use config::ConfigRow;
pub use devices::{DeviceNumbers, DeviceRow, DeviceText, Seen, SeenDeviceRow};
pub use identity::{AuditRecord, IdentityRow};
pub use intents::{ActiveVersion, IntentRecord};
pub use plugins::{PluginActionRow, PluginGrantRow, PluginRow};
pub use sync::{SyncLogRow, SyncRow};

/// A `NOT NULL` column's value, or the error naming it.
pub(super) fn required<T>(value: Option<T>, column: &'static str) -> Result<T, RowError> {
    value.ok_or(RowError::Missing { column })
}

/// A column declared `CHECK (x IN (0, 1))`, as a boolean.
///
/// # Why a refusal rather than `!= 0`
///
/// The schema's `CHECK` is what makes this a two-valued column, and a reader that accepted any non-zero integer would
/// treat a `2` — which the schema forbids and a corrupt file can contain — as `true`. The point of checking is that a
/// value the schema does not allow is reported rather than interpreted.
pub(super) fn to_bool(value: Option<i64>, column: &'static str) -> Result<bool, RowError> {
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
pub(super) fn parse_features(text: &str) -> Result<Vec<String>, RowError> {
    serde_json::from_str::<Vec<String>>(text).map_err(|error| RowError::WrongType {
        column: "features",
        wanted: "a JSON array of strings",
        found: format!("{error}"),
    })
}

/// A pinned copy of the row types' column lists, for `synra-error-guard` and for a test.
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

    /// The `sync_log` columns, in the order `SyncLogRow::from_columns` takes them.
    pub const SYNC_LOG: &[&str] =
        &["sync_id", "plugin_id", "peer_device", "started_at_ms", "finished_at_ms", "document"];

    /// The `sync_records` columns, in the order `SyncRow::from_columns` takes them.
    ///
    /// The table's own order, and its primary key is `(plugin_id, peer_device)` — so this is a **current state** per
    /// device, not a log. See the note on `SyncRow`.
    pub const SYNC: &[&str] = &["plugin_id", "peer_device", "version", "digest", "synced_at_ms"];

    /// The `plugin_audit` columns, in the order `AuditRecord::from_columns` takes them.
    ///
    /// `id` is deliberately absent: it is the autogenerated identity of the row, and nothing reads it. Selecting it would
    /// be a column every reader has to skip past.
    pub const AUDIT: &[&str] =
        &["plugin_id", "capability", "outcome", "at_ms", "elapsed_ms", "trace_id"];

    /// The `intents` columns, in the order `IntentRecord::from_columns` takes them.
    pub const INTENT: &[&str] = &[
        "intent_id",
        "state",
        "created_ms",
        "updated_ms",
        "origin_device",
        "request_id",
        "document",
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

