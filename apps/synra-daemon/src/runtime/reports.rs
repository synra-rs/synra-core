
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
        // ★ The log's counters are gauges in the same report, so a reader of `status` sees the same numbers `synra logs`
        // names. `None` (logging not running) writes no gauges rather than zeroes, which keeps "not running" distinguishable
        // from "running and quiet".
        if let Some(stats) = &self.log_stats {
            for (name, value) in [
                ("log_lines", stats.lines()),
                ("log_dropped", stats.dropped()),
                ("log_write_errors", stats.write_errors()),
            ] {
                self.metrics.gauge_set(
                    &synra_observe::metrics::SeriesKey::new(name, Vec::new()),
                    i64::try_from(value).unwrap_or(i64::MAX),
                );
            }
        }
        // ★ The schema version and the row counts are read rather than described. A status that said "database: ok"
        // without asking would be a status that cannot be wrong — and therefore one that cannot tell a user anything.
        let schema = self.db().recorded_version().ok().flatten();
        let counts = self.db().counts().ok().map(|rows| {
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
            // ★ The gate's counters, which is the first thing in this report that a plugin *did* rather than
            // something the daemon was configured with.
            //
            // Reported as series rather than as a total, because a total is the one shape that cannot answer the question
            // the design's `gate_*` metrics exist for: which capability plugins keep asking for and not having. A count
            // with no label would say "somebody was refused" and nothing about what to do.
            "metrics": self.metrics_value(),
        })
    }

    /// The counters, as the recorder's own snapshot.
    ///
    /// # Why this serialises rather than shapes
    ///
    /// Because `MetricsSnapshot`, `SeriesValue`, `SeriesKey` and `Value` already derive `serde::Serialize` with
    /// `rename_all = "camelCase"` — they were built to cross this boundary, and the first version of this method took the
    /// snapshot apart and rebuilt it as a list of `{name, labels, value}` objects. That is the same data with a second
    /// spelling: a reader would have had to know both, and nothing kept the two in step.
    ///
    /// Serialising the recorder's own type means the shape a client sees **is** the shape the recorder produces, with the
    /// series already sorted by rendered key and every label carried as a label. A counter arrives as
    /// `{"kind":"counter","value":1}`, which is what tells a client how to draw it rather than leaving it to guess.
    pub(super) fn metrics_value(&self) -> serde_json::Value {
        serde_json::to_value(self.metrics.snapshot()).unwrap_or(serde_json::Value::Null)
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
        let rows = self.db().plugins().map_err(|error| {
            Refusal::new(ErrorCode::Internal, format!("could not read the plugins table: {error}"))
        })?;

        // ★ The two plugin gauges, set where the truth is read. The daemon has no install command, so this listing is the
        // only place its recorder can learn how many plugins exist — and a daemon whose `plugins_installed` stayed absent
        // would make the metrics panel describe a kernel with no plugins at all.
        self.metrics.gauge_set(
            &synra_observe::metrics::SeriesKey::new("plugins_installed", []),
            i64::try_from(rows.len()).unwrap_or(i64::MAX),
        );
        self.metrics.gauge_set(
            &synra_observe::metrics::SeriesKey::new("plugins_active", []),
            i64::try_from(rows.iter().filter(|row| row.enabled).count()).unwrap_or(i64::MAX),
        );

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
                // ★ Two healths, because they are two different facts.
                //
                // `health` is the row: what was recorded when the plugin was installed or last checked, and it survives a
                // restart. `liveHealth` is the ladder **now** — `good`, `overreaching`, `degraded`, `faulted` — and it is
                // the one that moves when a plugin starts trapping. Until this field existed the ladder had no reader at
                // all: the daemon reported the row and nothing reported the rung, so a plugin could degrade to `faulted`
                // and the interface would still say what it said at install time.
                //
                // `null` for a plugin that is not loaded, which is a different fact from "healthy".
                "health": row.health,
                "liveHealth": self
                    .plugins
                    .lock()
                    .health_of(&row.plugin_id),
                "installedAtMs": row.installed_at_ms,
                "updatedAtMs": row.updated_at_ms,
                // ★ Reported rather than assumed. A row whose directory is gone is one `should_run` would say yes to and
                // the host would fail to load.
                "artifactPresent": manifest_path.exists(),
            }));
        }

        // ★ Reported rather than assumed, and no longer a constant.
        //
        // This used to be a hardcoded `"loaded": false` with a comment saying the kernel had loaded nothing. That was
        // true when it was written, and it stayed true — which is the problem with a constant that is right: it cannot
        // report the day it stops being right, so the day a plugin host was wired up, this line would have kept telling
        // users their installed plugins were not running.
        //
        // What it reports now is what the load pass actually did, including which plugins it could not load and why.
        // A user with one broken plugin can act on that; a user told only "nothing is loaded" cannot.
        // ★ Copied out under a short lock rather than held across the JSON.
        //
        // The summary is four small values, and holding the guard while building a `serde_json::Value` would keep every
        // other thread that wants to load a plugin out for the length of a serialization — which is exactly the class
        // of bug this lint exists to catch, and the reason it is denied in this workspace rather than warned about.
        let (loaded_count, loaded_ids, refusals, safe_mode) = {
            let loads = self.plugin_loads.lock();
            let ids: Vec<String> = loads.loaded.iter().map(ToString::to_string).collect();
            let refusals: Vec<serde_json::Value> = loads
                .refused
                .iter()
                .map(|refused| serde_json::json!({"id": refused.plugin_id, "reason": refused.reason}))
                .collect();
            (loads.len(), ids, refusals, loads.safe_mode.clone())
        };

        Ok(serde_json::json!({
            "plugins": installed,
            // Whether anything is askable right now, which is what a client means by "running".
            "loaded": loaded_count > 0,
            "loadedCount": loaded_count,
            "loadedIds": loaded_ids,
            "notLoaded": refusals,
            // ★ Why nothing is loaded, when the daemon chose not to start plugins.
            //
            // Without this a client sees `loaded: false` with an empty `notLoaded`, which reads as "this machine has no
            // plugins installed" — the opposite of the truth, and the reading that sends someone to reinstall. `null`
            // when plugins were allowed to load, so a client can test it rather than guess from an empty string.
            "safeMode": safe_mode,
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
    pub(super) fn logs_value(
        &self,
        lines: usize,
        verbose: bool,
        trace: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        // ★ Asking to see more is what turns more on.
        //
        // The subscriber is built with a fixed level and `tracing` allows one subscriber per process, so a line that was
        // never written cannot be filtered back into existence. The honest answer to `--verbose` is therefore to raise
        // what the process writes from now on, for a bounded window — and to say so, because the first read will
        // legitimately contain no debug lines and a user who was not told would conclude the flag does nothing (which is
        // exactly what it did before this existed).
        //
        // A trace filter raises further than `--verbose` does: asking to follow one identifier is a narrower and more
        // deliberate request than asking for everything.
        let wanted = if trace.is_some() {
            Some(synra_observe::logging::LogLevel::Trace)
        } else if verbose {
            Some(synra_observe::logging::LogLevel::Debug)
        } else {
            None
        };
        let mut raised = false;
        let mut effective = None;
        if let Some(verbosity) = self.verbosity.as_ref() {
            if let Some(level) = wanted {
                verbosity.raise_for_a_while(level);
                raised = true;
            }
            effective = Some(verbosity.effective().as_str());
        }

        // The log lives in the cache directory beside the data directory, which is where `Paths` puts it.
        let log_dir = self.data_dir.join("logs");
        // ★ The writer is asynchronous: without this wait, a line logged a moment ago — often the one explaining the thing
        // the user is asking about — would be missing from the answer, and the answer would look like a quiet kernel.
        if let Some(flush) = &self.log_flush {
            flush.flush();
        }

        // ★ The reading, the level filter and the trace filter all live in `synra-observe::logging` now, because the
        // shell needs the same three decisions for a diagnostic bundle and could not reach them here. What is left in
        // this function is the control protocol's answer shape, which is the only part that is the daemon's business.
        let tail = synra_observe::logging::tail(&log_dir, lines, verbose, trace);

        Ok(serde_json::json!({
            "lines": tail.lines,
            "source": tail.source.map(|path| path.to_string_lossy().into_owned()),
            "total": tail.matched,
            // Echoed so a caller can tell "this trace has no lines" from "the filter was dropped on the way here" —
            // the exact confusion the CLI's old `--trace` produced by discarding the id.
            "trace": trace,
            // What this request did to the logger, so a caller can explain an empty result rather than leaving the user
            // to guess whether the flag is wired at all.
            "raised": raised,
            "level": effective,
            // What the writer dropped or could not write. A log that stopped growing because the disk is full looks
            // exactly like a quiet kernel otherwise — these two numbers are the difference.
            "dropped": self.log_stats.as_ref().map_or(0, |stats| stats.dropped()),
            "writeErrors": self.log_stats.as_ref().map_or(0, |stats| stats.write_errors()),
            // ★ The last failure in its own words. A count says the logger is failing; "no space left on device" says what
            // to do about it.
            "lastWriteError": self.log_stats.as_ref().and_then(|stats| stats.last_write_error()),
        }))
    }
}


