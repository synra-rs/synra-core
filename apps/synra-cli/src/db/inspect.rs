//! Read-only reports about database health and stored rows.

use synra_store::{Health, SynraDb};

use crate::session::CommandOutcome;

/// Reports what the engine says about the database.
pub(super) fn integrity(format: Option<crate::args::OutputFormat>, db: &SynraDb) -> CommandOutcome {
    let health = match db.health() {
        Ok(health) => health,
        Err(error) => return CommandOutcome::Failed(format!("the check could not run: {error}")),
    };

    match format {
        Some(crate::args::OutputFormat::Json) => {
            let value = serde_json::json!({
                "health": health_name(&health),
                "detail": health_detail(&health),
            });
            match health {
                // ★ `Sound` is `ok`, the other two are not. `Unknown` is not a pass: the check did not run, and a script
                // that read it as "fine" would be told the database is healthy by a check that never looked.
                Health::Sound => CommandOutcome::json(value.to_string()),
                _ => CommandOutcome::json_failure(value.to_string()),
            }
        }
        _ => match &health {
            Health::Sound => CommandOutcome::Lines(vec!["the database is sound".to_owned()]),
            Health::Corrupt { detail } => CommandOutcome::Failed(format!(
                "the database is damaged: {detail}\nrestore from a backup with `synra db backup` having been run before this happened"
            )),
            Health::Unknown { detail } => {
                CommandOutcome::Failed(format!("the check could not run: {detail}"))
            }
            // ★ `Health` is `#[non_exhaustive]`, so a variant added later is matched here rather than failing to
            // compile. It is reported as unknown rather than as sound: a state this build does not recognise is not a
            // pass, and saying "sound" would be the one answer that hides it.
            _ => CommandOutcome::Failed("the database reported a state this build does not recognise".to_owned()),
        },
    }
}

/// Reads the tables a debugger wants.
///
/// # Why every table goes through one map
///
/// Because the single-table path and `all` answer the same question about the same six tables, and two lists would drift:
/// a table added to one and not the other is a `db dump --table x` that works while `db dump` silently omits it. The map
/// is the only list.
pub(super) fn dump(format: Option<crate::args::OutputFormat>, db: &SynraDb, table: Option<&str>) -> CommandOutcome {
    let tables = |name: &str| -> Option<Result<serde_json::Value, String>> {
        match name {
            "identity" => Some(json(db.identity())),
            "devices" => Some(json(db.paired_devices())),
            "seen" => Some(json(db.seen_devices())),
            "plugins" => Some(json(db.plugins())),
            "grants" => Some(grants(db)),
            "config" => Some(json(db.config())),
            _ => None,
        }
    };
    const NAMES: [&str; 6] = ["identity", "devices", "seen", "plugins", "grants", "config"];

    let value = match table {
        // ★ An unknown table is refused rather than answered with an empty object. A dump that returned `{}` for a typo
        // would read as "this table is empty", which is a fact about the user's data rather than about their spelling.
        Some(other) => match tables(other) {
            Some(Ok(value)) => value,
            Some(Err(error)) => {
                return CommandOutcome::Failed(format!("{other} could not be read: {error}"));
            }
            None => {
                return CommandOutcome::Failed(format!(
                    "`{other}` is not a table this command knows; try {} or all",
                    NAMES.join(", ")
                ));
            }
        },
        // One object rather than a list of tables: the reader is a person with a JSON viewer, and the table name is the
        // useful key. A table that cannot be read is reported by name so the rest of the dump is still usable.
        None => {
            let mut all = serde_json::Map::new();
            for name in NAMES {
                match tables(name) {
                    Some(Ok(value)) => {
                        all.insert(name.to_owned(), value);
                    }
                    Some(Err(error)) => {
                        all.insert(name.to_owned(), serde_json::json!({ "error": error }));
                    }
                    None => {}
                }
            }
            serde_json::Value::Object(all)
        }
    };

    match format {
        Some(crate::args::OutputFormat::Json) => CommandOutcome::json(value.to_string()),
        // ★ Text output is the JSON anyway. A hand-written table renderer would be a second implementation of the same
        // facts, and the one thing `db dump` is for is being pasted into a bug report.
        _ => CommandOutcome::Lines(vec![value.to_string()]),
    }
}

/// Every plugin's decisions, keyed by plugin.
///
/// `plugin_grants` takes one identifier, so a dump of the table is one read per plugin. That is a deliberate shape
/// rather than a gap: the table is keyed by `(plugin_id, capability)` and a reader asking about one plugin is the
/// ordinary case, so the query that exists is the one the rest of the system makes.
fn grants(db: &SynraDb) -> Result<serde_json::Value, String> {
    let plugins = db.plugins().map_err(|error| error.to_string())?;
    let mut by_plugin = serde_json::Map::new();
    for plugin in plugins {
        let rows = db.plugin_grants(&plugin.plugin_id).map_err(|error| error.to_string())?;
        let value = serde_json::to_value(rows).map_err(|error| error.to_string())?;
        by_plugin.insert(plugin.plugin_id.clone(), value);
    }
    Ok(serde_json::Value::Object(by_plugin))
}

/// Serialises a reader's answer, reporting a failure as text.
fn json<T: serde::Serialize>(rows: Result<T, synra_store::DbError>) -> Result<serde_json::Value, String> {
    let rows = rows.map_err(|error| error.to_string())?;
    serde_json::to_value(rows).map_err(|error| error.to_string())
}

/// The name of a health result, for JSON.
const fn health_name(health: &Health) -> &'static str {
    match health {
        Health::Sound => "sound",
        Health::Corrupt { .. } => "corrupt",
        Health::Unknown { .. } => "unknown",
        _ => "unrecognised",
    }
}

/// What a health result says, when it says anything.
fn health_detail(health: &Health) -> Option<&str> {
    match health {
        Health::Sound => None,
        Health::Corrupt { detail } | Health::Unknown { detail } => Some(detail),
        _ => None,
    }
}
