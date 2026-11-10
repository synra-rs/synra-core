use std::path::Path;

use synra_plugin_api::Manifest;
use synra_plugin_api::publisher::Digests;
use synra_plugin_host::Backend;
use synra_plugin_host::verify::{self, Candidate, DependencyGraph, HostFacts};

use crate::transfer::ObjectDigest;

use super::writing;
use super::*;

/// Installs the plugin in `source` into `plugins_dir`, after verifying it.
///
/// `host` is what the installing machine can do, and it is a parameter rather than a constant because the two hosts
/// differ: the daemon has no window, so a plugin that declares a notification gets a warning here and none on the
/// desktop shell. Nothing else about the pipeline changes with it.
///
/// # Errors
///
/// [`InstallRefusal`] naming the step that refused. Nothing is written to `plugins_dir` and no row is recorded unless
/// every check passed and the copy completed.
///
/// # Why the database is `&mut`
///
/// Because the install writes **two** rows that must undo together: the plugin and the version now in effect. The second
/// write can fail after the first succeeded, and the rollback removes the row as well as the directory — a plugin row
/// naming discarded files is what the loader reports as a broken plugin rather than as a failed install.
pub fn from_directory(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    from_directory_inner(db, backend, plugins_dir, source, now_ms, host, false)
}

/// Installs a newer version over the plugin already at that identifier.
///
/// # What is different from an install
///
/// Every check is the same — the package is verified completely before the old directory is touched — and only the final
/// two steps differ: the existing directory is moved aside, the new one takes its place, and the old one is removed once
/// the version row has landed. A failure at either step restores the old directory, so an update that cannot finish is an
/// update that did not happen rather than a plugin that is now half of each version.
///
/// # Errors
///
/// [`InstallRefusal`] as [`from_directory`], plus `update` when nothing is installed at that identifier.
pub fn update_from_directory(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    from_directory_inner(db, backend, plugins_dir, source, now_ms, host, true)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the pipeline's inputs, plus whether it replaces an installed copy"
)]
fn from_directory_inner(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
    replace: bool,
) -> Result<Installed, InstallRefusal> {
    let prepared = prepare(db, backend, source, now_ms, host, replace)?;
    writing::write(db, plugins_dir, now_ms, prepared, replace)
}

pub(crate) fn prepare(
    db: &synra_store::SynraDb,
    backend: &Backend,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
    replace: bool,
) -> Result<Prepared, InstallRefusal> {
    let source = source
        .canonicalize()
        .map_err(|error| InstallRefusal::new("source", format!("{}: {error}", source.display())))?;
    if !source.is_dir() {
        return Err(InstallRefusal::new(
            "source",
            format!("{} is not a directory", source.display()),
        ));
    }

    // ── The manifest, read as bytes first ───────────────────────────────────────────────────────────────────────────
    //
    // Bytes rather than a parsed value, because the digest of the manifest is what the signature covers: parsing and
    // then re-serialising would hash a different document, and the two would disagree for reasons nobody could see.
    let manifest_json = std::fs::read_to_string(source.join("manifest.json"))
        .map_err(|error| InstallRefusal::new("read", format!("manifest.json: {error}")))?;
    let manifest = Manifest::from_json(&manifest_json)
        .map_err(|error| InstallRefusal::new("manifest", error.to_string()))?;
    let plugin_id = manifest.id.to_string();

    let installed = db.plugin_is_installed(&plugin_id).unwrap_or(false);
    if replace && !installed {
        return Err(InstallRefusal::new(
            "update",
            format!("{plugin_id} is not installed, so there is nothing to update"),
        ));
    }
    if !replace && installed {
        return Err(InstallRefusal::new(
            "install",
            format!("{plugin_id} is already installed; remove it before installing another copy"),
        ));
    }

    // ── Every file the manifest names, read once and hashed ─────────────────────────────────────────────────────────
    //
    // One read, one set of bytes: what is hashed is what is written. Reading twice — once to hash and once to copy —
    // leaves a window in which the file changes, and the install would then write bytes nobody checked while reporting
    // a digest for the ones that were.
    let mut files: Vec<(String, Vec<u8>)> = vec![(
        "manifest.json".to_owned(),
        manifest_json.clone().into_bytes(),
    )];
    let mut digests = Digests::new();
    let mut total = manifest_json.len() as u64;
    for name in artifact_names(&manifest) {
        if !is_artifact_path(&name) {
            return Err(InstallRefusal::new(
                "manifest",
                format!("`{name}` is not a file name inside the package"),
            ));
        }
        let path = source.join(&name);
        let declared_size = std::fs::metadata(&path)
            .map_err(|error| InstallRefusal::new("read", format!("{name}: {error}")))?
            .len();
        if declared_size > MAX_ARTIFACT_BYTES {
            return Err(InstallRefusal::new(
                "archive-limits",
                format!(
                    "{name} is {declared_size} bytes, over the {MAX_ARTIFACT_BYTES} an artifact may be"
                ),
            ));
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| InstallRefusal::new("read", format!("{name}: {error}")))?;
        total = total.saturating_add(bytes.len() as u64);
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(InstallRefusal::new(
                "archive-limits",
                format!("{name} grew to {} bytes while it was read", bytes.len()),
            ));
        }
        if total > MAX_PACKAGE_BYTES {
            return Err(InstallRefusal::new(
                "archive-limits",
                format!("the package is over the {MAX_PACKAGE_BYTES} bytes a package may be"),
            ));
        }
        digests.insert(name.clone(), ObjectDigest::of(&bytes).as_sri().to_string());
        files.push((name, bytes));
    }

    let signature = match std::fs::read_to_string(source.join("signature.json")) {
        Ok(text) => {
            files.push(("signature.json".to_owned(), text.clone().into_bytes()));
            Some(text)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(InstallRefusal::new(
                "read",
                format!("signature.json: {error}"),
            ));
        }
    };

    // ── Where this copy came from, recorded beside it ────────────────────────────────────────────────────────────────
    //
    // ★ `source.json`, because the design's restore flow ends with "reinstall these" and a list of identifiers is not
    // enough: the packages this host installs are directories, and the path is the one fact the user cannot reconstruct
    // from what a backup carries. It is written as part of `files` so every rollback path removes it with the rest — a
    // leftover source note beside a directory the install discarded would be a lie about a plugin that is not there.
    let source_note = serde_json::json!({
        "path": source.display().to_string(),
        "installedAtMs": now_ms,
    });
    let source_note = serde_json::to_vec_pretty(&source_note)
        .map_err(|error| InstallRefusal::new("write", format!("source.json: {error}")))?;
    files.push(("source.json".to_owned(), source_note));

    // Actual component validation runs after digest/signature checks in the shared pipeline.
    let headless = manifest
        .runtime
        .headless
        .as_ref()
        .map(|runtime| runtime.artifact.clone());
    let wasm: &[u8] = match &headless {
        Some(name) => files
            .iter()
            .find(|(file, _)| file == name)
            .map(|(_, bytes)| bytes.as_slice())
            .unwrap_or(&[]),
        None => &[],
    };
    // ★ The manifest's digest is the contract's own function, not a hash this module computes.
    //
    // `manifest_digest` hashes the bytes as they are on disk, in hex — which is what the plugin CLI signs and what the
    // shell records a consent decision against. Computing an SRI digest here (the artifact encoding) made every signed
    // package look like one whose signature covered a different manifest.
    let manifest_digest = synra_plugin_api::manifest_digest(&manifest_json);
    let artifact_digest = match &headless {
        Some(name) => digests.get(name).unwrap_or_default().to_owned(),
        None => ObjectDigest::of(&[]).as_sri().to_string(),
    };

    let candidate = Candidate {
        manifest_json: &manifest_json,
        artifact: wasm,
        declared_digest: None,
        actual_digest: &artifact_digest,
        manifest_digest: &manifest_digest,
        artifacts: &digests,
        signature: signature.as_deref(),
        // A local package is not publisher-signed by policy: an author testing their own build has no publisher. A
        // package that *does* carry a signature is still checked against it — `verify` refuses one that covers other
        // bytes — so this is "a signature is not required", not "a signature is not looked at".
        signature_required: false,
        dependencies: &DependencyGraph::new(),
        host,
    };

    // The publisher store is empty, which is the honest state of a daemon that has never recorded a publisher: every
    // publisher is new, and the pipeline reports that so the interface can ask rather than refusing the first install
    // from anybody. Persisting it is `PublisherTrustStore`'s own gap, not this module's.
    // ★ The decisions this device has made, in the shape the verifier takes. An unknown publisher still installs — the
    // pipeline's own rule — but a trusted one installs as trusted, and a revoked key is refused here rather than at the
    // signature check, because "the user revoked it" is not a cryptographic fact.
    let trust = trust_store(db);
    let report = verify::verify(&candidate, &trust)
        .map_err(|(stage, error)| InstallRefusal::new(stage.as_str(), error.to_string()))?;

    // Inspect the verified snapshot before compilation or installation writes.
    if let Some(ui) = manifest.runtime.ui.as_ref() {
        let bytes = files
            .iter()
            .find(|(name, _)| name == &ui.artifact)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or_else(|| InstallRefusal::new("ui-artifact", "declared UI archive is missing"))?;
        synra_plugin_ui::artifact::inspect_ui_bytes(
            bytes,
            &ui.entry,
            synra_plugin_ui::artifact::ArchiveLimits::artifact(),
        )
        .map_err(|error| InstallRefusal::new("ui-artifact", error.to_string()))?;
    }

    // Only packages that passed the complete verification pipeline reach native compilation.
    // This checks the selected engine without instantiating the guest or invoking callbacks.
    if headless.is_some() {
        let _ = backend
            .compile(wasm, &plugin_id)
            .map_err(|error| InstallRefusal::new("wit-compatibility", error.to_string()))?;
    }

    let warnings: Vec<String> = report
        .warnings()
        .iter()
        .map(|step| format!("{}: {}", step.stage.as_str(), step.detail))
        .collect();

    Ok(Prepared {
        manifest,
        manifest_json,
        files,
        signature,
        headless,
        artifact_digest,
        warnings,
    })
}

#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) manifest: Manifest,
    pub(crate) manifest_json: String,
    pub(crate) files: Vec<(String, Vec<u8>)>,
    pub(crate) signature: Option<String>,
    pub(crate) headless: Option<String>,
    pub(crate) artifact_digest: String,
    pub(crate) warnings: Vec<String>,
}
