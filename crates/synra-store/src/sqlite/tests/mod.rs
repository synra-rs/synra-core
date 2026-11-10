//! SQLite storage tests share a freshly migrated in-memory database.

use super::SynraDb;

mod diagnostics;
mod discovery;
mod grants;
mod migrations;
mod pairing;
mod plugin_actions;
mod records;
mod retention;
mod settings;
mod sync;

/// A database with every migration applied.
fn migrated() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db
}
