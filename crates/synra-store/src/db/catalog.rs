//! The tables this build's schema defines.
/// The tables this build's schema defines.
///
/// A list rather than a query, so a test can assert that every table the design document names is created by
/// some migration. A table named in the document and missing from the schema is a feature that fails at its
/// first use.
pub const TABLES: &[&str] = &[
    "identity",
    "paired_devices",
    "devices_seen",
    "plugins",
    "plugin_versions",
    "plugin_update_checks",
    "plugin_grants",
    "plugin_actions",
    "plugin_deps",
    "plugin_audit",
    "sync_records",
    "transfer_sessions",
    "intents",
    "config",
];
