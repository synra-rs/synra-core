//! The schema a database must end up in, as data rather than as a binding call.
//!
//! # Why this is a directory and not a file
//!
//! Because the migration list is five hundred lines of SQL that no reader wants to scroll past, and because the four
//! questions this module answers — what the schema *is*, which version a database is at, how sound it is, and which
//! tables therefore exist — are asked by different callers. In one file the integrity interpretation sat four hundred
//! lines below `SchemaState`.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `migrations` | one schema step, the list of them, and the pragmas they assume |
//! | `state` | which version a database is at |
//! | `schema` | why an operation failed, and what may be applied |
//! | `version` | the migration-version table, whose name two places must agree on |
//! | `health` | how sound a database is, and what an integrity result means |
//! | `catalog` | the tables this build's schema defines |
//! | `outcome` | how a migration outcome reads in a log line |

mod catalog;
mod health;
mod migrations;
mod outcome;
mod plugin_authority;
mod schema;
mod state;
mod version;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use catalog::TABLES;
pub use health::{Health, interpret_integrity};
pub use migrations::{MIGRATIONS, Migration, PRAGMAS, latest_version};
pub use schema::{MigrationOutcome, SchemaError, apply, check_migration_list};
pub use state::{SchemaState, schema_state};
pub use version::{VERSION_TABLE, VERSION_TABLE_NAME};
