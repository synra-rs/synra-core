//! One schema step, the list of them, and the pragmas they assume.
/// One schema step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The version this step produces, counting from one.
    pub version: u32,
    /// A short name, for a log line.
    pub name: &'static str,
    /// The statements, run in order.
    pub statements: &'static [&'static str],
}

mod initial;
mod plugin;
mod tail;

pub(crate) use initial::*;
pub(crate) use plugin::*;
pub(crate) use tail::*;

/// The statements that create the schema, in order.
///
/// The steps are grouped by the feature they introduced, while this array keeps the schema's historical order.
pub const MIGRATIONS: &[Migration] = &[
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8,
    V9,
    V10,
    V11,
    V12,
    V13,
    V14,
    V15,
    V16,
    V17
];

/// The schema version this build expects.
#[must_use]
pub fn latest_version() -> u32 {
    MIGRATIONS.last().map_or(0, |migration| migration.version)
}

/// The pragmas that must be in force.
///
/// A list rather than a sequence of calls, so a caller can apply them through whichever binding it uses and a
/// test can assert the set without a database. The comments give the reason, because a pragma whose reason is
/// not written down is one somebody removes as redundant.
pub const PRAGMAS: &[(&str, &str)] = &[
    // Write-ahead logging: readers do not block the writer, which matters because the interface reads the
    // audit and metrics tables while the kernel writes them.
    ("journal_mode", "WAL"),
    // Trust receipts and revocations must not acknowledge commits that can disappear on a power cut.
    // WAL recovery preserves consistency with NORMAL, but only FULL syncs the WAL at every commit.
    ("synchronous", "FULL"),
    // Off by default in SQLite, and the kernel's schema relies on cascades: without this, deleting a plugin
    // leaves its versions, grants and dependencies behind forever.
    ("foreign_keys", "ON"),
    // Five seconds, so a brief lock from another connection waits rather than failing the operation. A longer
    // wait would make the interface appear hung; a shorter one would surface as spurious errors.
    ("busy_timeout", "5000"),
    // Temporary tables in memory, because they are used for sorting a query's results and a disk round trip for
    // something that fits in memory is pure cost.
    ("temp_store", "MEMORY"),
    // 256 MiB of memory-mapped reads: the database is small, and mapping it removes a copy from every read.
    ("mmap_size", "268435456"),
];

