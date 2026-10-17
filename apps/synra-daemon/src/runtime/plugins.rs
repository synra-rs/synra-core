//! Loading the plugins this daemon is supposed to be running.
//!
//! # Why the daemon builds the engine and the kernel does not
//!
//! Because the engine is a host's decision. `synra-core` holds [`synra_core::dispatch::PluginSet`], which is a handle
//! rather than an engine, precisely so that this windowless host and a Tauri shell can each bring one of their own. That
//! separation is only worth anything if something actually uses it, and before this module nothing did: the daemon held
//! no plugin host at all and its status report said so with a hardcoded `"loaded": false`.
//!
//! # Why one plugin's failure does not stop the rest
//!
//! Because a machine with five plugins installed and one broken must still run the other four, and a daemon that refuses
//! to start because a single artifact is missing has turned a plugin's problem into a kernel's outage. So every plugin is
//! loaded independently and each refusal is recorded with its own reason and kept in [`LoadedSummary`].
//!
//! # Why a UI-only plugin is *skipped* rather than refused
//!
//! Because a manifest with no headless half is a working plugin that happens not to run here: its interface is served by
//! the shell, not instantiated. Calling that a refusal would put a plugin author on a bug report for a plugin that works
//! exactly as declared.
//!
//! # What this does not do
//!
//! It does not activate a plugin. Loading compiles and makes a plugin *askable*; activation is a lifecycle transition with
//! its own state machine and its own refusal rules, and a loader that also activated would be a second, weaker version of
//! that state machine. What it reports is therefore "loaded", and nothing in this file claims a plugin is running.

use std::path::Path;

use synra_capability::CapabilitySet;
use synra_plugin_host::{BackendError, InstancePolicy};
use synra_protocol::ids::PluginId;

use synra_core::dispatch::{PluginSet, PluginSpec};
use synra_observe::crash::StartupVerdict;

/// How many instances one plugin may have.
///
/// # Why this is a constant here rather than in the manifest
///
/// Because the manifest's `resourceHints` are, by name, hints — soft, and ignorable. A host that took its limit from a
/// string a plugin author wrote would be taking its resource ceiling from third-party code. Four is the point where a
/// plugin stops being concurrent and starts being a memory leak with a licence.
pub(crate) const INSTANCE_LIMIT: u32 = 4;

/// Why one plugin was not loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Its identifier, as the database spells it.
    pub plugin_id: String,
    /// What stopped it.
    pub reason: String,
}

/// What a load pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedSummary {
    /// What is now askable, in the order it was loaded.
    pub loaded: Vec<PluginId>,
    /// What was not, and why.
    pub refused: Vec<Refused>,
    /// Why nothing was loaded at all, when the daemon chose not to start plugins.
    ///
    /// `Some` only in safe mode. It is a separate field rather than an entry in `refused` because the two are different
    /// statements: `refused` names plugins that failed, and this names a decision the daemon made before looking at any
    /// of them. Putting it in `refused` would attribute the refusal to a plugin that was never examined.
    pub safe_mode: Option<String>,
}

impl LoadedSummary {
    /// How many plugins this daemon can now ask.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    /// Whether a plugin with this identifier is loaded.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.loaded.contains(id)
    }
}

/// Builds the plugin set this daemon runs plugins on.
///
/// # Errors
///
/// [`BackendError`] when the engine cannot start. This is the daemon's refusal to start at all, rather than a plugin
/// being refused: a kernel that has no engine cannot run any plugin, and reporting that as "no plugins loaded" would
/// present a broken daemon as a machine with nothing installed.
///
/// # Why the engine kind is asked for rather than written down
///
/// Because a kind written here would be a decision this file makes on the engine's behalf, and the table that already
/// answers it lives in [`synra_plugin_host::BackendKind::default_for`]. A daemon is a [`synra_plugin_host::HostKind::Headless`]
/// host, so asking is both shorter and harder to get wrong than naming a variant.
pub fn build_set(
    db: &std::sync::Arc<parking_lot::Mutex<synra_store::SynraDb>>,
    metrics: &std::sync::Arc<synra_observe::metrics::RingRecorder>,
) -> Result<PluginSet, BackendError> {
    let kind = synra_plugin_host::BackendKind::default_for(synra_plugin_host::HostKind::Headless);
    let backend = synra_plugin_host::Backend::new(std::sync::Arc::new(
        synra_plugin_host::engine::WasmtimeBackend::new(kind)?,
    ));
    // ★ The engine is asked whether it can enforce what this host will ask of it, **before** any plugin is loaded.
    //
    // `first_gap` is this layer's safety argument — *"the caller refuses rather than running third-party code with a bound it
    // does not have"* — and this is the caller. Asked here rather than per call for the reason the error variant records: a
    // missing limit is a fact about the installation, and this is the only moment somebody can act on it.
    synra_plugin_host::engine::check_enforceable(
        &backend,
        &synra_plugin_host::quota::Quota::default(),
    )?;
    // ★ The host is what makes the capability gate run. Without one there is no session, and `linker::run` refuses
    // every host call — so the gate never ran and nothing was audited.
    let host = std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
        std::sync::Arc::clone(db),
        env!("CARGO_PKG_VERSION"),
    ));

    // ★ And the audit gets its durable half, which it has never had.
    //
    // `plugin_audit` was created by the first migration and its own comment says what it is for: *"A ring in memory, but the
    // durable part is what makes the interface's 'recent activity' survive a restart."* The ring was written — every call is
    // drained into it — and nothing ever wrote the table, so the audit a user sees is the last ten thousand calls of **this
    // run** and a restart empties it.
    //
    // The sink is a closure rather than a store handle on the set, because the kernel is what decides a call is auditable
    // and the host is what has a database. A write that fails is logged and does not fail the call: the call has already
    // happened, and refusing it afterwards would tell a plugin its action did not occur when it did — the same reasoning as
    // `checkpoint_intent`.
    let audit_db = std::sync::Arc::clone(db);
    let sink = std::sync::Arc::new(move |entry: &synra_observe::audit::AuditEntry| {
        let record = synra_store::records::AuditRecord {
            plugin_id: entry.plugin.as_str().to_owned(),
            capability: entry.capability.to_string(),
            outcome: entry.outcome.as_str().to_owned(),
            at_ms: entry.at_ms,
            elapsed_ms: entry.elapsed_ms.map(|elapsed| i64::try_from(elapsed).unwrap_or(i64::MAX)),
        };
        if let Err(error) = audit_db.lock().record_audit(&record) {
            tracing::error!(
                plugin = entry.plugin.as_str(),
                "an audit record could not be written down: {error}. The call it describes has already happened."
            );
        }
    });

    // ★ And the gate's counters get somewhere to go.
    //
    // The recorder is created by the daemon and handed in rather than made here, because the daemon is what can *read* it —
    // a recorder built inside this function and dropped on return would be a metrics subsystem nobody can see, which is
    // exactly what these metrics were before there was a producer at all.
    Ok(PluginSet::new(backend, host)
        .with_audit_sink(sink)
        .with_metrics(std::sync::Arc::clone(metrics)))
}

/// The plugin directories on disk that the database does not know about, recorded as installed and switched off.
///
/// # ★ Why this exists: the subsystem had no way in
///
/// A plugin could not reach the database in production at all. The only writer of a `plugins` row was
/// `SynraDb::insert_plugin`, and every caller of it was a test — so `load_installed` read `db.plugins()` and always got
/// an empty list. Nothing was broken in a way anyone could see; the daemon simply had no plugins, forever, whatever was
/// on disk. The same hole is why `plugin_grants` has no writer and why `set_plugin_trusted` is test-only: they are steps
/// of a lifecycle whose first step was missing.
///
/// This is the first step, in the narrowest form that is honest about consent: **a directory that exists is recorded,
/// and is neither enabled nor trusted.** Dropping a directory on disk is not a decision by anybody, so it must not be
/// one — `should_run` is `enabled && trusted`, and this writes neither. What it does is make the plugin *visible*: it
/// appears in `plugins_list`, a user can see what it asks for, and the enable/consent steps have a row to act on.
///
/// # Why it does not trust, and why that is the whole point
///
/// Because the alternative — trusting whatever is found in the directory — would make the directory a privilege
/// boundary, and this daemon's plugin directory is writable by anything running as the user. The design's consent step
/// exists so that installing and approving are two acts, and collapsing them here would remove the only gate that is
/// currently within reach.
///
/// # Why the manifest is parsed rather than assumed
///
/// A directory that is not a plugin — a stray file, a half-copied install, a build's output — must not become a row.
/// The parse is the whole test, and a directory that fails it is reported so the reason is not silent.
pub fn record_discovered_plugins(
    db: &synra_store::SynraDb,
    plugins_dir: &Path,
    now_ms: i64,
) -> Vec<Discovered> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(plugins_dir) else {
        // A plugins directory that does not exist yet is an installation with nothing installed, which is the ordinary
        // state of a fresh one. Reporting it would make every first run print a warning.
        return found;
    };

    // ★ Two levels, because a plugin identifier contains a slash.
    //
    // `load_one` resolves a plugin as `plugins_dir.join(plugin_id)`, and ids are `@scope/name` — so `@acme/hello` lives
    // at `plugins/@acme/hello/`. A scan that looked only at direct children would see `@acme`, find no manifest in it,
    // and report a perfectly good installation as broken. That is not a hypothetical: it is what the first version of
    // this function did, and the test that caught it is `discovering_a_plugin_twice_records_it_once`.
    //
    // A directory counts as a plugin when it **contains a manifest**, and its identifier is its path relative to the
    // plugins directory. That is the same rule `load_one` uses, so the two cannot disagree about which directory a
    // plugin is.
    let mut candidates: Vec<(String, std::path::PathBuf)> = Vec::new();
    for scope in entries.flatten() {
        let scope_path = scope.path();
        if !scope_path.is_dir() {
            continue;
        }
        let Some(scope_name) = scope_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let mut inner = std::fs::read_dir(&scope_path).ok();
        let mut had_child_directory = false;
        if let Some(entries) = inner.as_mut() {
            for child in entries.flatten() {
                let child_path = child.path();
                if !child_path.is_dir() {
                    continue;
                }
                had_child_directory = true;
                if let Some(child_name) = child_path.file_name().and_then(|name| name.to_str()) {
                    candidates.push((format!("{scope_name}/{child_name}"), child_path));
                }
            }
        }

        // A direct child with a manifest is a plugin too: an id without a scope is legal, and the layout should not
        // have to be either-or.
        if scope_path.join("manifest.json").is_file() {
            candidates.push((scope_name.to_owned(), scope_path.clone()));
        } else if !had_child_directory {
            // A directory with no manifest and nothing under it is not a plugin and is not a scope: it is a stray or
            // half-copied entry, and a user needs to be told which of those two situations they are in.
            candidates.push((scope_name.to_owned(), scope_path));
        }
    }

    for (plugin_id, path) in candidates {
        // Already known: the database is the record, and re-reading the manifest on every start would make the daemon
        // the thing that decides what a plugin declares rather than what the user approved.
        if db.plugin_is_installed(&plugin_id).unwrap_or(false) {
            continue;
        }

        let Ok(text) = std::fs::read_to_string(path.join("manifest.json")) else {
            found.push(Discovered {
                plugin_id,
                problem: Some("no manifest.json".to_owned()),
            });
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<synra_plugin_api::Manifest>(&text) else {
            found.push(Discovered {
                plugin_id,
                problem: Some("the manifest is not readable".to_owned()),
            });
            continue;
        };

        // ★ A signature in the directory is checked here, because this scan is the **second** way into `plugins/`.
        //
        // `plugin install` runs the eleven checks; a directory copied in by hand — which is what an author does while
        // developing, and what this scan exists for — used to be recorded as installed on the strength of a manifest.
        // So a package whose `plugin.wasm` had been replaced beside a genuine `signature.json` became an installed
        // plugin, and the consent prompt would then be about a document nobody had signed.
        if let Some(problem) = signature_problem(&path, &manifest, &text) {
            found.push(Discovered {
                plugin_id,
                problem: Some(problem),
            });
            continue;
        }

        match db.insert_plugin(&plugin_id, false, false, "installed", now_ms, now_ms) {
            Ok(()) => found.push(Discovered { plugin_id, problem: None }),
            Err(error) => found.push(Discovered { plugin_id, problem: Some(error.to_string()) }),
        }
    }

    found
}

/// Whether a package's own signature agrees with the bytes in its directory.
///
/// # Why the scan checks this and does not run the eleven checks
///
/// Because the scan runs at every start and the full pipeline compiles an artifact; a signature check costs one hash per
/// file and no engine. What it catches is the case that matters for a hand-copied directory: **the signature does not
/// describe what is here** — a replaced artifact, an edited manifest, a `signature.json` copied from another release.
///
/// # Why an unsigned package is not refused
///
/// Because that is what an author's own build produces, and this workspace's design allows a local unsigned install in
/// development. The row it gets is untrusted and disabled, so the consent prompt is still the gate; what changes is
/// that a *signed* package can no longer claim to be one while carrying other bytes.
fn signature_problem(
    directory: &Path,
    manifest: &synra_plugin_api::Manifest,
    manifest_json: &str,
) -> Option<String> {
    let text = match std::fs::read_to_string(directory.join("signature.json")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => return Some(format!("signature.json could not be read: {error}")),
    };
    let document = match synra_plugin_api::publisher::SignatureFile::parse(&text) {
        Ok(document) => document,
        Err(error) => return Some(format!("signature.json is not a signature document: {error}")),
    };
    let outcome = match document.verify() {
        Ok(outcome) => outcome,
        Err(error) => return Some(format!("the signature does not verify: {error}")),
    };
    let synra_plugin_api::publisher::VerifyOutcome::Good { fingerprint } = outcome else {
        return Some("the signature does not verify".to_owned());
    };

    let mut digests = synra_plugin_api::publisher::Digests::new();
    for name in super::install::artifact_names(manifest) {
        let bytes = match std::fs::read(directory.join(&name)) {
            Ok(bytes) => bytes,
            Err(error) => return Some(format!("{name}, which the manifest names, could not be read: {error}")),
        };
        digests.insert(name, synra_core::ObjectDigest::of(&bytes).as_sri().to_string());
    }
    // ★ The manifest's digest is the contract's own function, not an SRI hash: `manifest_digest` hashes the bytes on
    // disk in hex, which is what the CLI signs against. Artifacts are SRI — the two encodings differ on purpose, and
    // using the wrong one for either side makes a genuine signature look like it covers a different document.
    let manifest_digest = synra_plugin_api::manifest_digest(manifest_json);
    if let Some(detail) = document.subject.mismatch(&manifest_digest, &digests) {
        // The same wording the pipeline's own refusal uses, so two reports of one condition read alike.
        return Some(format!("the signature covers different bytes: {detail}"));
    }

    // A revoked key, or a key that changed for a publisher this device has seen, is a refusal a user cannot consent past.
    // An unknown publisher is not: that is the first install from somebody, and consent is where the user decides.
    if let synra_plugin_api::publisher::PluginTrust::Untrusted { why } =
        synra_plugin_api::publisher::PublisherTrustStore::new().classify(&document.publisher.id, &fingerprint)
    {
        return Some(format!("the publisher is not trusted: {why}"));
    }
    None
}

/// One plugin directory the daemon looked at, and what came of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The directory's name, which is the plugin's identifier.
    pub plugin_id: String,
    /// Why it was not recorded, when it was not.
    ///
    /// `None` means a row now exists. A reason is reported rather than dropped because a directory that looks like a
    /// plugin and is not one is the difference between "the user has nothing installed" and "the user's installation is
    /// half-copied", and only one of those needs acting on.
    pub problem: Option<String>,
}

/// Loads every plugin the database says should run.
///
/// A row that is not [`synra_store::PluginRow::should_run`] is not loaded and not refused: the user switched it off or
/// never trusted it, and that is a decision already made rather than something that went wrong here.
///
/// # ★ Why the verdict is a parameter
///
/// Because safe mode has to be able to stop this, and until it was passed in, nothing could.
/// `StartupVerdict::allows_plugins` existed, was tested, and was **called only from tests** — no plugin-loading path
/// asked it. So a plugin that crashed on activation three times in a row would crash a fourth and a fifth time, and the
/// settings screen the user needs to disable it stayed unreachable. The verdict's own doc comment says that reaching
/// the settings screen is "the only outcome that has to exist"; the code that reaches it did not exist.
///
/// Taking the verdict rather than a `bool` is deliberate: a refusal can then say *which* location has been crashing,
/// which is the sentence a user needs to act on.
pub fn load_installed(
    set: &mut PluginSet,
    db: &synra_store::SynraDb,
    plugins_dir: &Path,
    verdict: &StartupVerdict,
    revocations: &synra_plugin_api::revocation::RevocationList,
) -> LoadedSummary {
    let mut summary = LoadedSummary::default();

    if !verdict.allows_plugins() {
        // Nothing is loaded and nothing is refused per plugin: this is not a fault in any one plugin's artifact, it is
        // the daemon choosing not to start them at all. Recorded on the summary so the status report can say so instead
        // of showing an empty list, which would read as "nothing is installed".
        summary.safe_mode = Some(verdict.explain());
        return summary;
    }

    let Ok(rows) = db.plugins() else {
        // The table being unreadable is the daemon's problem, and it is reported through its own status line; here it
        // means "nothing could be loaded" rather than "nothing is installed".
        return summary;
    };

    for row in rows {
        if !row.should_run() {
            continue;
        }
        match load_one(set, db, plugins_dir, &row.plugin_id, revocations) {
            Ok(id) => summary.loaded.push(id),
            Err(reason) => summary.refused.push(Refused { plugin_id: row.plugin_id.clone(), reason }),
        }
    }
    summary
}

/// Loads one plugin from its directory.
///
/// # Errors
///
/// A string saying what stopped it, because every reason here is a fact about a file on disk or a manifest a third party
/// wrote, and each one is something the user or the author needs to read rather than an error code to map elsewhere.
fn load_one(
    set: &mut PluginSet,
    db: &synra_store::SynraDb,
    plugins_dir: &Path,
    plugin_id: &str,
    revocations: &synra_plugin_api::revocation::RevocationList,
) -> Result<PluginId, String> {
    let id = PluginId::try_from(plugin_id.to_owned()).map_err(|error| format!("the id is not usable: {error}"))?;
    let directory = plugins_dir.join(plugin_id);
    let manifest_text = std::fs::read_to_string(directory.join("manifest.json"))
        .map_err(|error| format!("the manifest could not be read: {error}"))?;
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("the manifest is not readable: {error}"))?;

    // ★ The revocation list, checked **before** anything else about the plugin is considered.
    //
    // The design's behaviour for an installed revoked version is "disable immediately, and tell the user". Two things follow
    // that are not obvious:
    //
    // 1. **The disable is written to the store, not just skipped here.** Refusing to load it this run would leave it enabled,
    //    so the next start tries again — and a revocation that has to be re-discovered on every boot is one that is
    //    re-decided on every boot.
    // 2. **It comes before the grants.** A plugin that is revoked *and* unconfirmed is still revoked, and reporting the
    //    missing consent would send its author looking for a permission problem.
    if let Some(reason) = revocations.revokes(plugin_id, &manifest.version) {
        // The stamp is the row's `updated_ms`, and this is an update: the same conversion the callers above use, saturating
        // because the store's columns are `i64` and the clock is not.
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis())
                .unwrap_or(0),
        )
        .unwrap_or(i64::MAX);
        let disabled = db.set_plugin_enabled(plugin_id, false, now);
        if let Err(error) = disabled {
            // Reported rather than swallowed: the plugin is not loaded either way, but a user whose store refused the write
            // will see it enabled again next start, and that is a thing they need to be told.
            eprintln!("synra-daemon: {plugin_id} is revoked and could not be disabled in the store: {error}");
        }
        return Err(format!("it is revoked and has been disabled: {reason}"));
    }

    let Some(headless) = manifest.runtime.headless.as_ref() else {
        return Err("the manifest declares no headless half".to_owned());
    };
    let wasm = std::fs::read(directory.join(&headless.artifact))
        .map_err(|error| format!("the artifact could not be read: {error}"))?;

    // ★ The grants are what the **user approved**, not what the manifest asks for.
    //
    // This was `grants_of(&manifest)`, which made the plugin's own declaration its authorisation: the consent table had
    // no writer, so there was nothing else to consult. A plugin received exactly what it asked for and the per-capability
    // consent the whole capability model rests on did not exist at either end.
    //
    // # Why a mismatch is a refusal rather than an intersection
    //
    // Because intersecting quietly would be the wrong shape for the common case. A plugin whose manifest has changed —
    // an update that adds a capability — has decisions recorded against a *different document*, and the honest answer is
    // "we need to ask again", not "we will run it with less than it says it needs". The second one produces a plugin
    // that appears to work and fails at one thing, which is exactly the silent degradation consent exists to prevent.
    //
    // The digest is over the bytes on disk, so a manifest that was edited rather than replaced is caught too.
    let digest = synra_plugin_api::manifest_digest(&manifest_text);
    let decisions = db.plugin_grants(plugin_id).map_err(|error| format!("the decisions could not be read: {error}"))?;
    if decisions.is_empty() {
        // Trusted with nothing recorded is the state a pre-consent build left behind, and it is not an authorisation.
        return Err("it has not been confirmed by the user".to_owned());
    }
    if let Some(stale) = decisions.iter().find(|decision| decision.manifest_digest != digest) {
        let _ = stale;
        return Err(
            "it has changed since the user confirmed it, and needs confirming again".to_owned(),
        );
    }

    let grants = granted_of(&decisions)?;
    let policy = if headless.stateful { InstancePolicy::Stateful } else { InstancePolicy::Stateless };
    set.load(PluginSpec {
        id: id.clone(),
        version: manifest.version.clone(),
        wasm,
        grants,
        policy,
        limit: INSTANCE_LIMIT,
        // The documented default allowance. A manifest does not declare a quota yet, so there is nothing more specific
        // to take it from — and a number invented here would be a limit the plugin's author never agreed to.
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .map_err(|error| error.to_string())?;
    Ok(id)
}

/// The capability set the user granted, from the decisions on record.
///
/// # Why only the granted rows, and why a parse failure is loud
///
/// A denied row is a decision too, and it must not become a grant. And a capability string that does not parse is a row
/// that cannot be honoured: skipping it would run the plugin with less than the user approved, which looks exactly like
/// a plugin that declines everything — and sends its author looking in the wrong file.
///
/// # What used to be here
///
/// A function called `grants_of`, which built the set from the **manifest's own declarations** — and carried a doc
/// comment explaining, correctly, why it must not fail silently. It was right about the failure mode and wrong about the
/// source: a manifest is what a plugin *asks for*, and using it as the grant made the request its own authorisation. It
/// became dead the moment the decisions above became the source, which is the shape a correct-but-misplaced function
/// should have when it is replaced.
fn granted_of(decisions: &[synra_store::PluginGrantRow]) -> Result<CapabilitySet, String> {
    let mut grants = CapabilitySet::new();
    for decision in decisions.iter().filter(|decision| decision.granted) {
        grants
            .insert_str(&decision.capability)
            .map_err(|error| format!("a granted capability is not usable: `{}`: {error}", decision.capability))?;
    }
    Ok(grants)
}
