//! `synra db` — the commands that read the database directly.
//!
//! # Why these do not go through the kernel
//!
//! Because they exist for the user whose kernel will not start. `db integrity` is what they run when they suspect
//! damage, and it would be useless if it needed a working kernel to answer — the same reason `doctor` reads the
//! directories rather than asking about them.
//!
//! # Why this module was missing
//!
//! The three subcommands were parsed, documented, and had argument tests — and every invocation ended in "this command
//! reads the database directly, which is not implemented yet". The store side already existed (`health` and the typed
//! readers); what was absent was this branch. A command a user can see and cannot run is worse than one that is not
//! there, because the first looks like a broken installation.

use synra_store::{Paths, SynraDb};

use crate::args::{DbAction, DbArgs};
use crate::session::CommandOutcome;

mod backup;
mod inspect;

use backup::{backup, export, import, restore};
use inspect::{dump, integrity};

/// Runs a `db` subcommand.
///
/// # Errors
///
/// Never. A failure is a [`CommandOutcome::Failed`], because every reason here — a database that will not open, damage,
/// a destination that exists — is something the user is meant to read and act on rather than a condition the caller
/// branches on.
#[must_use]
pub fn outcome(format: Option<crate::args::OutputFormat>, args: &DbArgs) -> CommandOutcome {
    outcome_at(&crate::session::data_root(), format, args)
}

/// The same, with the data root supplied.
///
/// # Why the root is a parameter
///
/// Because reading `SYNRA_DATA_DIR` is not testable from inside a process: `std::env::set_var` is `unsafe` in edition
/// 2024 — another thread may be reading the environment — and this workspace forbids `unsafe`. So the caller reads it and
/// the decision takes the value, which leaves the interesting part, what the command does with a database, testable
/// against a directory a test owns.
#[must_use]
pub fn outcome_at(
    root: &std::path::Path,
    format: Option<crate::args::OutputFormat>,
    args: &DbArgs,
) -> CommandOutcome {
    let paths = Paths::under(root);
    // ★ Restore runs before the database is opened. Opening it applies pragmas and runs any pending migration — against
    // the file a user has just asked to replace, on the assumption that it opens at all. A recovery path that needs the
    // broken database to be healthy is not a recovery path.
    if let DbAction::Restore { path } = &args.action {
        return restore(root, &paths, format, path);
    }
    if let DbAction::Import { path } = &args.action {
        return import(root, &paths, format, path);
    }
    let opened = SynraDb::open(&paths.db_path()).and_then(|mut db| {
        db.migrate()?;
        Ok(db)
    });
    let db = match opened {
        Ok(db) => db,
        Err(error) => {
            // ★ Named the path as well as the reason. "Could not open the database" sends a user looking for a
            // permission problem in the wrong directory; the path is the one fact that makes it actionable.
            return CommandOutcome::Failed(format!(
                "{} could not be opened: {error}",
                paths.db_path().display()
            ));
        }
    };

    match &args.action {
        DbAction::Integrity => integrity(format, &db),
        DbAction::Backup { path } => backup(format, &db, path),
        DbAction::Export { path } => export(format, &db, &paths, path),
        DbAction::Dump { table } => dump(format, &db, table.as_deref()),
        // Handled before the database was opened; see `outcome_at`.
        DbAction::Restore { .. } | DbAction::Import { .. } => {
            unreachable!("restore and import return before the database is opened")
        }
    }
}

#[cfg(test)]
mod tests;
