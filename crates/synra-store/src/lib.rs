//! Persistence: where the kernel's state lives and how it is protected.
//!
//! Four concerns, kept apart because they fail in different ways:
//!
//! * [`paths`] — the directory layout. Wrong here and a file is written where nothing reads it.
//! * [`db`] — the schema and its migrations. Wrong here and a user's data is a shape no code expects.
//! * [`sandbox`] — what a plugin may reach. Wrong here and one plugin reads another's data, or the user's.
//! * [`secrets`] — keys and tokens. Wrong here and a credential is on disk in a form somebody else can read.
//!
//! # What is not here
//!
//! No SQLite binding. The design document names `rusqlite`, and the application layer uses it; what this crate
//! defines is the *contract* — which pragmas, which migrations in which order, what a version means — so that
//! contract can be tested without a C dependency and so swapping the binding does not change what the schema is.
//!
//! # The sandbox is the security-critical part
//!
//! Everything else here is about correctness. [`sandbox`] is about a plugin being unable to read a file it was
//! not given, and its implementation is the one place in this crate where the obvious approach — resolve, check
//! the prefix, then open — is wrong for a reason worth reading about.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod db;
pub mod records;
pub mod sqlite;
pub mod paths;
pub mod sandbox;
pub mod secrets;

pub use db::{Health, Migration, MigrationOutcome, SchemaError, SchemaState, latest_version};
pub use records::{
    ActiveVersion, ConfigRow, DeviceRow, IdentityRow, PluginActionRow, PluginGrantRow, PluginRow, RowError, Seen,
    SeenDeviceRow, columns,
};
// `Paired` is here because `SynraDb::pair_device` takes one: a public method whose argument type is not exported is
// a method no caller outside this crate can call at all.
pub use sqlite::{ConfigChange, DbError, Paired, SynraDb, migration_versions};
pub use sqlite::{PublisherRow, TRUST_REVOKED, TRUST_SEEN, TRUST_TRUSTED};
mod plugin_files;

pub use plugin_files::{PluginFiles, remove_tree};
pub use paths::{DB_FILE_NAME, PathError, Paths, is_within, sanitise_component};
pub use sandbox::{CACHE, FILES, PluginDataRoot, SandboxMeta, SUBDIRECTORIES};
pub use secrets::{
    MemoryBackend, SecretBackend, SecretBackendKind, SecretBytes, SecretError, SecretKey,
    SecretStrength,
};
