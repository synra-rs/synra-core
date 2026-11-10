//! Copies and replaces a database while keeping recovery separate from opening it.

use synra_store::{Paths, SynraDb, sqlite::now_ms};

use crate::session::CommandOutcome;

/// Replaces the database with a backup.
pub(super) fn restore(
    root: &std::path::Path,
    paths: &Paths,
    format: Option<crate::args::OutputFormat>,
    backup: &std::path::Path,
) -> CommandOutcome {
    if let Some(refusal) = replacement_refusal(root, backup, "restoring") {
        return refusal;
    }
    let report = match synra_store::restore_from(backup, &paths.db_path()) {
        Ok(report) => report,
        Err(error) => return CommandOutcome::Failed(error.to_string()),
    };
    match format {
        Some(crate::args::OutputFormat::Json) => CommandOutcome::json(
            serde_json::json!({
                "restoredFrom": backup.display().to_string(),
                "database": paths.db_path().display().to_string(),
                "previous": report.previous.as_ref().map(|path| path.display().to_string()),
            })
            .to_string(),
        ),
        _ => CommandOutcome::Lines(vec![
            match &report.previous {
                Some(previous) => format!(
                    "restored {}; the database that was there is now {}",
                    backup.display(),
                    previous.display()
                ),
                None => format!("restored {}; there was no database to replace", backup.display()),
            },
        ]),
    }
}

/// Writes a consistent copy of the database.
pub(super) fn backup(
    format: Option<crate::args::OutputFormat>,
    db: &SynraDb,
    path: &std::path::Path,
) -> CommandOutcome {
    if let Err(error) = db.backup_to(path) {
        return CommandOutcome::Failed(error.to_string());
    }
    match format {
        Some(crate::args::OutputFormat::Json) => {
            CommandOutcome::json(serde_json::json!({ "written": path.display().to_string() }).to_string())
        }
        _ => CommandOutcome::Lines(vec![format!("wrote {}", path.display())]),
    }
}

/// Writes a `.synrabackup` container.
pub(super) fn export(
    format: Option<crate::args::OutputFormat>,
    db: &SynraDb,
    paths: &Paths,
    path: &std::path::Path,
) -> CommandOutcome {
    let summary = match synra_store::export_backup(db, &paths.plugins_dir(), path, now_ms()) {
        Ok(summary) => summary,
        Err(error) => return CommandOutcome::Failed(error.to_string()),
    };
    match format {
        Some(crate::args::OutputFormat::Json) => CommandOutcome::json(
            serde_json::json!({
                "written": path.display().to_string(),
                "plugins": summary.plugins,
                "bytes": summary.bytes,
            })
            .to_string(),
        ),
        _ => CommandOutcome::Lines(vec![format!(
            "wrote {} ({} plugin(s), {} bytes)",
            path.display(),
            summary.plugins,
            summary.bytes
        )]),
    }
}

/// Replaces the database with the one inside a container.
pub(super) fn import(
    root: &std::path::Path,
    paths: &Paths,
    format: Option<crate::args::OutputFormat>,
    archive: &std::path::Path,
) -> CommandOutcome {
    if let Some(refusal) = replacement_refusal(root, archive, "importing") {
        return refusal;
    }
    let report = match synra_store::import_backup(archive, &paths.db_path()) {
        Ok(report) => report,
        Err(error) => return CommandOutcome::Failed(error.to_string()),
    };
    let previous = report.previous.as_ref().map(|path| path.display().to_string());
    match format {
        Some(crate::args::OutputFormat::Json) => CommandOutcome::json(
            serde_json::json!({
                "importedFrom": archive.display().to_string(),
                "previous": previous,
                "plugins": report.plugins,
            })
            .to_string(),
        ),
        _ => {
            let mut lines = vec![match &previous {
                Some(previous) => format!(
                    "imported {}; the database that was there is now {previous}",
                    archive.display()
                ),
                None => format!("imported {}; there was no database to replace", archive.display()),
            }];
            if !report.plugins.is_empty() {
                lines.push("reinstall these plugins:".to_owned());
                for plugin in &report.plugins {
                    let source = plugin
                        .source
                        .as_deref()
                        .map(|origin| format!(" (from {origin})"))
                        .unwrap_or_default();
                    lines.push(format!(
                        "  {} {}{source}",
                        plugin.plugin_id,
                        plugin.version.as_deref().unwrap_or("(unknown version)")
                    ));
                }
            }
            CommandOutcome::Lines(lines)
        }
    }
}

/// Checks whether a file can replace the database without opening the database itself.
fn replacement_refusal(
    root: &std::path::Path,
    source: &std::path::Path,
    operation: &str,
) -> Option<CommandOutcome> {
    if synra_control::Client::connect(root).is_ok() {
        return Some(CommandOutcome::Failed(format!(
            "a kernel is running; stop it before {operation}, because replacing the database under an open connection is not a recovery"
        )));
    }
    if !source.is_file() {
        return Some(CommandOutcome::Failed(format!("{} is not a file", source.display())));
    }
    None
}
