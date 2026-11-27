//! A lifecycle switch using the kernel's retained, verified replacement bytes.

use synra_core::dispatch::PluginSet;
use synra_core::plugin_updates::automatic_check_is_current;
use synra_core::supervisor::Cancellation;
use synra_plugin_api::update::UpdatePolicy;
use synra_protocol::PluginId;
use synra_store::PluginUpdateCheck;

use super::super::Runtime;

pub(super) fn directory(
    runtime: &Runtime,
    check: &PluginUpdateCheck,
    path: &std::path::Path,
    policy: UpdatePolicy,
    cancel: &Cancellation,
) -> Result<(), String> {
    let version = check.available_version.as_deref().ok_or("the check offers no update")?;
    replace(
        runtime,
        (&check.plugin_id, version),
        path,
        Mode::Automatic {
            check,
            policy,
            cancel,
        },
        check.checked_at_ms,
    )
    .map(|_| ())
}

pub(super) fn manual(
    runtime: &Runtime,
    target: (&str, &str),
    path: &std::path::Path,
    registry: Option<&str>,
    now_ms: i64,
) -> Result<synra_core::install::Installed, String> {
    replace(runtime, target, path, Mode::Manual { registry }, now_ms)
}

#[derive(Clone, Copy)]
enum Mode<'a> {
    Automatic {
        check: &'a PluginUpdateCheck,
        policy: UpdatePolicy,
        cancel: &'a Cancellation,
    },
    Manual {
        registry: Option<&'a str>,
    },
}

enum Verified<'a> {
    Automatic(synra_core::install::PreparedUpdate, &'a PluginUpdateCheck),
    Manual(synra_core::install::PreparedReplacement),
}

impl Verified<'_> {
    fn target(&self) -> (&str, &str) {
        match self {
            Self::Automatic(update, _) => (update.plugin_id(), update.version()),
            Self::Manual(update) => (update.plugin_id(), update.version()),
        }
    }

    fn install(
        self,
        db: &mut synra_store::SynraDb,
        now_ms: i64,
    ) -> Result<synra_core::install::Installed, String> {
        match self {
            Self::Automatic(update, check) => update.install(db, check, now_ms),
            Self::Manual(update) => update.install(db, now_ms),
        }
        .map_err(|error| format!("{}: {}", error.stage, error.reason))
    }
}

impl<'a> Mode<'a> {
    fn ensure(&self, db: &synra_store::SynraDb) -> Result<(), String> {
        match self {
            Self::Automatic {
                check,
                policy,
                cancel,
            } => ensure_automatic_check(db, check, *policy, cancel),
            Self::Manual { registry } => {
                if super::registry_setting(db)?.as_deref() != *registry {
                    return Err("the registry changed during the update".to_owned());
                }
                Ok(())
            }
        }
    }

    fn prepare(
        &self,
        db: &synra_store::SynraDb,
        set: &PluginSet,
        runtime: &Runtime,
        path: &std::path::Path,
        now_ms: i64,
    ) -> Result<Verified<'a>, String> {
        let host = synra_plugin_host::verify::HostFacts::headless();
        match self {
            Self::Automatic { check, policy, .. } => synra_core::install::prepare_automatic_update(
                db,
                set.backend(),
                &runtime.plugins_dir,
                path,
                now_ms,
                host,
                *policy,
            )
            .map(|update| Verified::Automatic(update, check)),
            Self::Manual { .. } => synra_core::install::prepare_replacement(
                db,
                set.backend(),
                &runtime.plugins_dir,
                path,
                now_ms,
                host,
            )
            .map(Verified::Manual),
        }
        .map_err(|error| format!("{}: {}", error.stage, error.reason))
    }
}

fn replace(
    runtime: &Runtime,
    target: (&str, &str),
    path: &std::path::Path,
    mode: Mode<'_>,
    now_ms: i64,
) -> Result<synra_core::install::Installed, String> {
    let (plugin, version) = target;
    let id = PluginId::parse(plugin).map_err(|error| error.to_string())?;
    let mut set = runtime.plugins.lock();
    let prepared = {
        let db = runtime.db();
        mode.ensure(&db)?;
        mode.prepare(&db, &set, runtime, path, now_ms)?
    };
    if prepared.target() != target {
        return Err(
            "the verified package does not match the checked plugin and version".to_owned(),
        );
    }
    if let Some(reason) = runtime.revocations.revokes(plugin, version) {
        return Err(reason.to_string());
    }
    mode.ensure(&runtime.db())?;
    let activation = synra_core::plugin::activation_config(set.host().as_ref());
    // The set lock serializes updates and removals; the store is released while third-party migration code runs.
    let old = set.version(&id).map(str::to_owned);
    if let Some(old) = old {
        let timestamp = u64::try_from(now_ms).unwrap_or(0);
        synra_core::plugin::migrate(&mut set, &id, &old, version, timestamp)?;
        synra_core::plugin::deactivate(&mut set, &id, timestamp);
        runtime.plugin_loads.lock().record_unloaded(&id);
    }
    let outcome = {
        let mut db = runtime.db();
        mode.ensure(&db)
            .and_then(|()| prepared.install(&mut db, now_ms))
    };
    let reloaded = reload(runtime, &mut set, &id, &activation);
    drop(set);
    let installed = outcome?;
    if let Err(error) = reloaded {
        tracing::warn!(plugin, version, %error, "replacement installed but could not activate");
    }
    tracing::info!(plugin, version, "plugin updated");
    Ok(installed)
}

pub(super) fn ensure_automatic_check(
    db: &synra_store::SynraDb,
    check: &PluginUpdateCheck,
    policy: UpdatePolicy,
    cancel: &Cancellation,
) -> Result<(), String> {
    let current = automatic_check_is_current(db, check, policy, cancel)
        .map_err(|error| error.to_string())?;
    if !current {
        return Err("the automatic update was cancelled or its check or policy changed".to_owned());
    }
    Ok(())
}

fn reload(
    runtime: &Runtime,
    set: &mut PluginSet,
    id: &PluginId,
    activation: &str,
) -> Result<(), String> {
    let loaded = {
        let db = runtime.db();
        let enabled = db
            .plugins()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|row| row.plugin_id == id.as_str() && row.should_run());
        if !enabled {
            drop(db);
            runtime.plugin_loads.lock().record_unloaded(id);
            return Ok(());
        }
        drop(db);
        synra_core::plugin::load_plugin_with_config(
            set,
            &runtime.db,
            &runtime.plugins_dir,
            id.as_str(),
            &runtime.revocations,
            activation,
        )
    };
    match loaded {
        Ok(id) => runtime.plugin_loads.lock().record_loaded(id),
        Err(error) => {
            runtime
                .plugin_loads
                .lock()
                .record_refused(id.as_str(), error.clone());
            return Err(error);
        }
    }
    Ok(())
}
