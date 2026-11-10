use synra_protocol::error::ErrorCode;

use super::super::now_ms;

use synra_control::Refusal;

use super::super::Runtime;

impl Runtime {
    /// Turns a plugin on or off, and answers with the list as it now stands.
    ///
    /// """ + S + """ The write, which had no caller.
    ///
    /// `set_plugin_enabled` existed in the store, was tested, and **nothing in production called it** — so `synra plugin
    /// enable` could not have worked even if the CLI had asked. Answering with the whole list rather than the one row is
    /// deliberate: enabling a plugin changes what `plugins` reports, and a caller that had to ask twice would be one
    /// showing a stale list until it did.
    pub(super) fn command_plugin_set_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
    ) -> Result<serde_json::Value, Refusal> {
        let changed = self
            .db
            .lock()
            .set_plugin_enabled(plugin_id, enabled, synra_store::sqlite::now_ms())
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        // """ + S + """ No such plugin is a refusal, and a plugin already in that state is not.
        //
        // `set_plugin_enabled` returns whether a row changed, so a second `enable` on an enabled plugin answers `false` —
        // a success with nothing to do. Reporting that as "no such plugin" would make a caller retry a typo that is not
        // there, and reporting a typo as a success would leave them believing it worked.
        let installed = self
            .db
            .lock()
            .plugin_is_installed(plugin_id)
            .unwrap_or(false);
        if !changed && !installed {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("no plugin is installed as `{plugin_id}`"),
            ));
        }
        // ★ Enabling loads and disabling stops — the same shape the shell has, and the design's lifecycle says enable is
        // *activating*, not "remember this for the next start". The revocation list is the one this daemon was started
        // with, so an enable cannot start a plugin the start-up pass would have refused.
        if let Ok(id) = synra_protocol::ids::PluginId::try_from(plugin_id.to_owned()) {
            if enabled {
                let should_run = {
                    let db = self.db.lock();
                    let rows = db
                        .plugins()
                        .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
                    // The database lock is released before the plugin set is taken: the two are never held in one
                    // order here, so there is no second order for another command to deadlock on.
                    drop(db);
                    rows.into_iter()
                        .find(|row| row.plugin_id == plugin_id)
                        .is_some_and(|row| row.should_run())
                };
                if should_run {
                    // Snapshot the environment; the loader owns short store reads and releases them before guest code.
                    let activation = {
                        let set = self.plugins.lock();
                        synra_core::plugin::activation_config(set.host().as_ref())
                    };
                    let outcome = {
                        let mut set = self.plugins.lock();
                        synra_core::plugin::load_plugin_with_config(
                            &mut set,
                            &self.db,
                            &self.plugins_dir,
                            plugin_id,
                            &self.revocations,
                            &activation,
                        )
                    };
                    match outcome {
                        Ok(loaded) => self.plugin_loads.lock().record_loaded(loaded),
                        Err(reason) => {
                            self.plugin_loads
                                .lock()
                                .record_refused(plugin_id, reason.clone());
                            return Err(Refusal::new(ErrorCode::PluginTrapped, reason));
                        }
                    }
                }
            } else {
                synra_core::plugin::deactivate(&mut self.plugins.lock(), &id, now_ms());
                self.plugin_loads.lock().record_unloaded(&id);
            }
        }
        self.plugins_value()
    }

    /// Records the user's decision about a plugin's capabilities.
    ///
    /// ★ The writer `plugin_grants` had only in tests. The loader has read decisions since it stopped treating a
    /// manifest as its own authorisation, so a plugin could not run without consent — and nothing could record consent
    /// except a test helper. A plugin was therefore installable, visible, enable-able and permanently unloadable.
    ///
    /// ★ **What the decision means is not decided here.** `synra_core::consent` owns the rule — one row per declared
    /// capability, trusted when anything was allowed — because the shell asks the same question and the two hosts had
    /// answered it differently. This method moves that decision into the store and nothing else.
    pub(super) fn command_plugin_consent(
        &self,
        plugin_id: &str,
        granted: &[String],
    ) -> Result<serde_json::Value, Refusal> {
        // The manifest on disk is the document the decision is about. Its digest is what makes a later edit — or an
        // update that adds a capability — visible to the loader, instead of silently inheriting the old consent.
        let text = std::fs::read_to_string(
            self.plugins_dir
                .join(synra_store::sanitise_component(plugin_id))
                .join("manifest.json"),
        )
        .map_err(|_| {
            Refusal::new(
                ErrorCode::PluginNotInstalled,
                format!("no plugin is installed as `{plugin_id}`"),
            )
        })?;
        let manifest = synra_plugin_api::Manifest::from_json(&text)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        let decision = synra_core::consent::decide(&manifest, &text, granted)
            .map_err(|error| Refusal::new(ErrorCode::InvalidArgument, error.to_string()))?;

        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        {
            // Scoped so the guard is gone before `plugins_value` reads the same table: this mutex is not reentrant, and a
            // second lock on this thread would be a hang rather than an error.
            let db = self.db.lock();
            db.record_grants(plugin_id, &decision.pairs(), now, decision.digest())
                .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
            db.set_plugin_trusted(plugin_id, decision.trusted(), now)
                .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        }
        self.plugins_value()
    }

    pub(super) fn command_plugin_remove(
        &self,
        plugin_id: &str,
        remove_data: bool,
    ) -> Result<serde_json::Value, Refusal> {
        // ★ The row first, then the files. The store's removal reports what actually went: measuring before and calling
        // that "freed" would count a locked directory that is still on disk.
        let files = synra_store::PluginFiles::new(self.paths.clone());
        let removed = self
            .db
            .lock()
            .remove_plugin(plugin_id)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        if !removed {
            return Err(Refusal::new(
                ErrorCode::PluginNotInstalled,
                format!("no plugin is installed as `{plugin_id}`"),
            ));
        }
        // ★ Stop it before its files go. A loaded instance still holds the artifact open, and on Windows that is why a
        // removal reports leftovers; more importantly a removed plugin that stayed in the set could still answer a share
        // from bytes the user just deleted.
        if let Ok(id) = synra_protocol::ids::PluginId::try_from(plugin_id.to_owned()) {
            synra_core::plugin::deactivate(&mut self.plugins.lock(), &id, now_ms());
        }
        let removal = files
            .remove(plugin_id, remove_data)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        // ★ Reported, not refused: the row is already gone, and a directory the operating system would not let go (a
        // loaded engine holds its wasm file open on Windows) is a fact the user has to see. The paths are the answer to
        // "so what is still on my disk?" — a count alone would make them go looking.
        let leftover_paths: Vec<String> = removal
            .leftovers
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        Ok(serde_json::json!({
            "pluginId": plugin_id,
            "bytesFreed": removal.bytes_freed,
            "dataKept": !remove_data,
            "leftovers": leftover_paths,
        }))
    }
}
