//! Finding plugins, and building the engine this daemon runs them on.
//!
//! # Where loading itself lives
//!
//! In [`synra_core::plugin`]. It used to live here, and the desktop shell — which has the same five facts to assemble —
//! never had a copy, so a plugin installed from the window was listed, could be enabled, and was never loaded. Loading
//! is the kernel's answer (which rows should run, with what consent, against which manifest), so it moved to the
//! kernel and both hosts call it. What stays here is the daemon's own half: the engine it brings, and the discovery of
//! directories the database has not seen.
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

use synra_plugin_host::BackendError;

use synra_core::dispatch::PluginSet;

pub use synra_core::plugin::{LoadedSummary, Refused, load_installed};

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
            // ★ The action's trace, when the call had one. `can-handle` and lifecycle calls do not, and `None` says that
            // rather than making every audit row look like part of a user action.
            trace_id: entry.trace.map(|trace| trace.to_string()),
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
///
/// # ★ Why one level, and why the manifest decides the identifier
///
/// The installer writes one directory per plugin, named [`synra_store::sanitise_component`]: `@acme/hello` lives in
/// `plugins/acme+hello`. This scan used to read two levels and take the identifier from the directory path, because the
/// loader did the same — and both were wrong about what the installer wrote, so a plugin installed by either host was
/// recorded and then could not be loaded. The identifier now comes from the manifest, and a directory whose name does not
/// match the sanitised id is reported with the name it should have rather than becoming a row that can never load.
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
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(directory_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if !path.join("manifest.json").is_file() {
            // ★ A directory with no manifest is reported only when it has nowhere to hide a plugin.
            //
            // The installer writes one directory per plugin, named [`synra_store::sanitise_component`] — `@acme/hello`
            // lives in `plugins/acme+hello`. A directory that has children and no manifest is therefore not a
            // half-copied plugin but the shape an older layout used (a scope directory), and reporting it would put a
            // warning in front of every user whose plugin directory predates the sanitised name. One that has no
            // children is a stray or a half-copy, and the user needs to know which.
            let has_children = std::fs::read_dir(&path).is_ok_and(|mut inner| inner.any(|child| {
                child.is_ok_and(|child| child.path().is_dir())
            }));
            if !has_children {
                found.push(Discovered {
                    plugin_id: directory_name.to_owned(),
                    problem: Some("no manifest.json".to_owned()),
                });
            }
            continue;
        }

        // ★ The identifier is the **manifest's**, not the directory's, and the directory has to agree with it.
        //
        // The installer names the directory after the sanitised id. A directory copied in by hand under another name
        // would be recorded under an id whose loader looks somewhere else — a row that can never load. Checking the two
        // against each other catches the mistake here, with a sentence that says what to rename it to.
        let Ok(text) = std::fs::read_to_string(path.join("manifest.json")) else {
            found.push(Discovered {
                plugin_id: directory_name.to_owned(),
                problem: Some("no manifest.json".to_owned()),
            });
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<synra_plugin_api::Manifest>(&text) else {
            found.push(Discovered {
                plugin_id: directory_name.to_owned(),
                problem: Some("the manifest is not readable".to_owned()),
            });
            continue;
        };
        let plugin_id = manifest.id.as_str().to_owned();
        let expected = synra_store::sanitise_component(&plugin_id);
        if directory_name != expected {
            found.push(Discovered {
                plugin_id,
                problem: Some(format!(
                    "the directory is named `{directory_name}` but this id lives in `{expected}`"
                )),
            });
            continue;
        }

        // Already known: the database is the record, and re-reading the manifest on every start would make the daemon
        // the thing that decides what a plugin declares rather than what the user approved.
        if db.plugin_is_installed(&plugin_id).unwrap_or(false) {
            continue;
        }

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
    for name in synra_core::install::artifact_names(manifest) {
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



