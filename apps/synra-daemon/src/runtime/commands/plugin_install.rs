use synra_protocol::error::ErrorCode;

use super::super::{now_ms, registry_install};

use synra_control::Refusal;

use super::super::Runtime;

impl Runtime {
    /// Installs a plugin from a directory, through the eleven checks.
    ///
    /// ★ The write that had no caller. `verify::verify` was written, tested against a refusal for each stage, and
    /// called by nobody: a plugin became installed because a directory appeared, so a package whose signature covered
    /// other bytes installed exactly as one that was genuine. This is the production caller that closes that.
    pub(super) fn command_plugin_install(&self, path: &str) -> Result<serde_json::Value, Refusal> {
        // Both locks are held across the install and released before anything is reported. The set's is held because
        // the backend inside it is what compiles the artifact, and compiling is what tells the pipeline what the
        // plugin imports; the database's because the row is written at the end of the same act. Neither is held while
        // the answer is built.
        let plugins = self.plugins.lock();
        let backend = plugins.backend();
        let mut db = self.db.lock();
        // ★ A path that is a file is a `.synra` package; one that is a directory is the unpacked form. Refusing the file
        // made the documented "install a plugin from a path" mean only one of the two shapes the product produces.
        let source = std::path::Path::new(path);
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        let outcome = if source.is_file() {
            crate::runtime::install_from_package(&mut db, backend, &self.plugins_dir, source, now)
        } else {
            // The runtime's clock is `u64` and the database stamps `i64`; saturating rather than `as`, the same
            // direction as every other stamp in this host — a clock past 2262 should let the daemon run.
            crate::runtime::install_from_directory(&mut db, backend, &self.plugins_dir, source, now)
        };
        drop(db);
        drop(plugins);

        match outcome {
            Ok(installed) => Ok(serde_json::json!({
                "pluginId": installed.plugin_id,
                "version": installed.version,
                "path": installed.path.to_string_lossy(),
                "warnings": installed.warnings,
                // ★ `false`, and it is an answer rather than a detail: installing is not approving. The row this wrote
                // is `enabled = false, trusted = false` — the design's `AwaitingConsent` in durable form — and the
                // user's `plugin enable` is the act that changes it.
                "enabled": false,
            })),
            Err(refusal) => Err(Refusal::new(
                refusal.code(),
                format!("{} refused the package: {}", refusal.stage, refusal.reason),
            )),
        }
    }

    /// Installs a plugin the registry names.
    ///
    /// # Why the locks are held the same way as `plugin_install`
    ///
    /// Because the last step **is** that install: the registry path differs in where the directory came from, not in what
    /// it does with it. Holding the same two locks across both means a registry install cannot interleave with a local one
    /// on the same plugin identifier.
    pub(super) fn command_plugin_install_package(
        &self,
        package: &str,
        version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        let plugins = self.plugins.lock();
        let backend = plugins.backend();
        let mut db = self.db.lock();
        let staging = self
            .plugins_dir
            .parent()
            .unwrap_or(&self.plugins_dir)
            .join(".install-staging");
        std::fs::create_dir_all(&staging).map_err(|error| {
            Refusal::new(
                ErrorCode::Internal,
                format!("{}: {error}", staging.display()),
            )
        })?;
        let outcome = registry_install::install_from_registry(
            &mut db,
            backend,
            &self.plugins_dir,
            &staging,
            &registry_install::NetworkFetch::default(),
            package,
            version,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
        );
        drop(db);
        drop(plugins);

        let installed = outcome?;
        Ok(serde_json::json!({
            "pluginId": installed.plugin_id,
            "version": installed.version,
            "path": installed.path.to_string_lossy(),
            "warnings": installed.warnings,
            // Installing is not approving; the same answer the path install gives.
            "enabled": false,
        }))
    }
}
