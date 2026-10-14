//! The migration-version table, whose name two places must agree on.
/// The statements that create the migration-version table.
///
/// Created before anything else, because the first migration needs somewhere to record that it ran. The name
/// matches what `rusqlite_migration` uses, so the two can be swapped without a data migration.
pub const VERSION_TABLE_NAME: &str = "__rusqlite_migration";

/// The statement that creates the version table.
///
/// # Why there are two constants
///
/// A `CREATE TABLE` statement is not a table name, and the first version of this was one constant used as both: the
/// binding wrote `INSERT INTO CREATE TABLE IF NOT EXISTS …`, which SQLite reported as a syntax error near `CREATE`. The
/// name is now its own constant and the statement is built from it, so the two cannot spell the table differently.
pub const VERSION_TABLE: &str = concat!(
    "CREATE TABLE IF NOT EXISTS ",
    "__rusqlite_migration",
    " (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL
)"
);
