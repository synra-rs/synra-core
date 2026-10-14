use std::path::{Path, PathBuf};

use synra_control::Refusal;
use synra_protocol::error::ErrorCode;

use super::Runtime;

impl Runtime {
    /// The `status` answer.
    ///
    /// # Why this carries the missing-layer note
    ///
    /// `status` is the one command a user runs to find out what is going on, so it is where "the kernel is up and this
    /// part is not built" belongs. A status that reported a healthy daemon and nothing else would leave a user
    /// wondering why the next command refuses.
    ///
    /// The note is empty today, which is a statement and not an omission: it emptied as `database`, `discovery` and
    /// `session` became real, and each removal was made because the feature worked rather than because the list was
    /// inconvenient. Adding a name back means a command genuinely refuses for a missing layer.
    pub(super) fn status_value(&self, now_ms: u64) -> serde_json::Value {
        // ★ The schema version and the row counts are read rather than described. A status that said "database: ok"
        // without asking would be a status that cannot be wrong — and therefore one that cannot tell a user anything.
        let schema = self.db.recorded_version().ok().flatten();
        let counts = self.db.counts().ok().map(|rows| {
            rows.into_iter()
                .map(|(table, count)| (table, serde_json::json!(count)))
                .collect::<serde_json::Map<String, serde_json::Value>>()
        });

        serde_json::json!({
            "state": "running",
            "version": self.version,
            "dataDir": self.data_dir.to_string_lossy(),
            "pluginsDir": self.plugins_dir.to_string_lossy(),
            "transportPort": self.listen_port,
            "discoveryPort": self.discovery_port,
            "uptimeMs": now_ms.saturating_sub(self.started_at_ms),
            "deviceId": self.identity.device_id.to_string(),
            "deviceName": self.identity.display_name,
            "schemaVersion": schema,
            "schemaKnown": synra_store::SynraDb::known_version(),
            "tables": counts,
            // ★ Present rather than omitted, so a client can print it. An absent field would be indistinguishable from
            // an older kernel that does not have the concept.
            //
            // It is empty, and that is the honest answer: nothing the daemon offers refuses because a layer is missing.
            // `database`, `discovery` and `session` were each listed here while they were unbuilt — and by the time
            // `send --text` and `send --file` both moved real bytes, this list still named `session`, telling a user that a
            // working feature was absent. That is the failure mode of a hand-maintained list, and the reason the test below
            // asserts the **exact** contents rather than a superset.
            "notImplemented": [],
        })
    }

    /// What is installed in the plugins directory.
    ///
    /// # Why this is real while `devices` is not
    ///
    /// The plugins directory is a directory, and listing it needs no layer that is missing. A plugin is a directory
    /// with a `manifest.json` in it, so the listing is a listing — reported as it is, with no claim about whether the
    /// kernel has *loaded* any of them, which it has not.
    pub(super) fn plugins_value(&self) -> Result<serde_json::Value, Refusal> {
        // ★ The database is the source of truth for what is *installed*, and the directory is where the artifacts are.
        // The first version of this listed the directory, which answered a different question: a plugin whose directory
        // is there but whose row is not has never been installed by the kernel, and one whose row is there and whose
        // directory is gone has been removed from disk behind its back. Both are states a user needs to see.
        let rows = self.db.plugins().map_err(|error| {
            Refusal::new(ErrorCode::Internal, format!("could not read the plugins table: {error}"))
        })?;

        let mut installed: Vec<serde_json::Value> = Vec::new();
        for row in rows {
            // The manifest is read for the title, and its absence is reported rather than skipped: a row whose artifact
            // is gone is something the user should see, because the plugin will fail the next time it is called.
            let manifest_path = self.plugins_dir.join(&row.plugin_id).join("manifest.json");
            let manifest = std::fs::read_to_string(&manifest_path)
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());

            installed.push(serde_json::json!({
                "id": row.plugin_id,
                "title": manifest
                    .as_ref()
                    .and_then(|value| value.get("title"))
                    .and_then(serde_json::Value::as_str),
                "enabled": row.enabled,
                "trusted": row.trusted,
                "health": row.health,
                "installedAtMs": row.installed_at_ms,
                "updatedAtMs": row.updated_at_ms,
                // ★ Reported rather than assumed. A row whose directory is gone is one `should_run` would say yes to and
                // the host would fail to load.
                "artifactPresent": manifest_path.exists(),
            }));
        }

        Ok(serde_json::json!({
            "plugins": installed,
            // ★ `false`, so a client does not present an installed plugin as one that is running. The kernel has loaded
            // nothing: there is no Wasm host wired to this daemon yet.
            "loaded": false,
        }))
    }

    /// The tail of the daemon's log.
    ///
    /// # The cost of filtering text
    ///
    /// Quiet mode hides a line that contains `DEBUG` or `TRACE` as a word — which is right for a level and wrong for a
    /// message that names one, so `INFO turning DEBUG off` is hidden. A text filter over a text log cannot tell the two
    /// apart, and the alternatives were worse here: keeping only lines that *start* with a level would pin this to one
    /// log format, and the format is the daemon's own. `--verbose` is the way to see everything.
    ///
    /// # Why this reads a directory rather than a file
    ///
    /// The log directory is what the kernel writes to, and a file there may be rotated or absent. Reading the newest
    /// file is the useful answer for a user asking "what happened", and reporting that there is none is the honest one
    /// for a fresh installation.
    pub(super) fn logs_value(&self, lines: usize, verbose: bool) -> Result<serde_json::Value, Refusal> {
        // The log lives in the cache directory beside the data directory, which is where `Paths` puts it.
        let log_dir = self.data_dir.join("logs");
        let Some(newest) = newest_file(&log_dir) else {
            return Ok(serde_json::json!({"lines": [], "source": serde_json::Value::Null}));
        };

        let text = std::fs::read_to_string(&newest).map_err(|error| {
            Refusal::new(
                ErrorCode::Internal,
                format!("could not read {}: {error}", newest.display()),
            )
        })?;

        // Filtered rather than requested from the writer: the level is in the line, and a filter here keeps the daemon
        // from needing an index of its own log.
        //
        // ★ The level is matched as a **token** rather than with `contains(" DEBUG ")`, which was the first version and
        // was wrong: a line may begin with the level — `DEBUG detail` — and then there is no space before it. What
        // follows the level is a space or the end of the line, and a line has a timestamp in front of it in the real
        // log, which is why the token is found by splitting rather than by position.
        let wanted: Vec<&str> = text
            .lines()
            .filter(|line| verbose || !is_debug_or_trace(line))
            .collect();
        let start = wanted.len().saturating_sub(lines);
        let tail: &[&str] = wanted.get(start..).unwrap_or(&[]);

        Ok(serde_json::json!({
            "lines": tail,
            "source": newest.to_string_lossy(),
            "total": wanted.len(),
        }))
    }
}

/// Whether a log line is at `DEBUG` or `TRACE`.
///
/// # Why a token rather than a substring
///
/// A line may begin with the level, so there is no space before it — `DEBUG detail` — and a search for `" DEBUG "` finds
/// nothing. It may also have a timestamp in front, so the level is not the first word either. Splitting the line into
/// words handles both, and the level is the word itself rather than something that merely contains it.
pub(super) fn is_debug_or_trace(line: &str) -> bool {
    line.split_whitespace().any(|word| word == "DEBUG" || word == "TRACE")
}

/// The newest file in a directory, if there is one.
fn newest_file(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}
