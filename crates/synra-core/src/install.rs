//! Installing a plugin from a directory on this machine, through the checks the design document orders.
//!
//! # Why this is in the kernel and not in a host
//!
//! Because there are two hosts and one pipeline. The daemon and the Tauri shell each bring their own engine and their
//! own data directory, and a second implementation of "verify, then write, then record" would be a second place for the
//! order to drift — and the order *is* the security argument. The one thing a host supplies is what it can do
//! ([`HostFacts`]), which is what the platform-applicability check reads.
//!
//! # Why a directory and not a package format
//!
//! Because a directory is what `synra-plugin build` produces and what an author is testing, and the archive format
//! (`.synra`) does not exist yet. The pipeline is the same one a registry install will run — the source of the bytes
//! is the only difference — so this is the small end of a seam rather than a second install path.
//!
//! # The order is the security argument
//!
//! Every step below is only meaningful if the one before it held, so the sequence is not a preference: digest, then
//! signature, then the manifest, then capabilities, then what the artifact imports. That order lives in
//! [`synra_plugin_host::verify`] and this module does not restate it — it supplies the bytes and writes the result.
//!
//! # What this refuses to do
//!
//! It does not build anything. The design document is explicit that a user's machine never runs `pnpm install`: the
//! package ships built, and an author who has not built it gets a refusal that says so rather than an npm supply-chain
//! surface. It also does not follow a symlink or accept an artifact name that leaves the package directory — an install
//! that read `../../etc/passwd` because a manifest said so would be a manifest that decides what a host reads.
//!
//! # What it does not decide
//!
//! Whether the user trusts the publisher, and whether the plugin may run. The rows it writes are **installed, switched
//! off and untrusted** — the design's `AwaitingConsent` in durable form — so installing and approving stay two acts. It
//! also records **which version is in effect** in `plugin_versions`, because that is what a peer's question "what do you
//! have" is answered from.

use std::path::{Path, PathBuf};

use synra_plugin_api::Manifest;
use synra_plugin_api::publisher::{
    Digests, Fingerprint, PublisherTrustStore, SignatureFile, VerifyOutcome,
};
use synra_plugin_host::Backend;
use synra_plugin_host::verify::{self, Candidate, DependencyGraph, HostFacts};

use crate::transfer::ObjectDigest;

/// The largest single artifact a directory install will read.
///
/// The design document's ceiling for a Wasm artifact. It is checked on the file's metadata **and** on the bytes that
/// were read, because the two are not the same number when something is writing to the file while it is read.
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;

/// The largest package, added up.
///
/// Three artifacts of the maximum size would fit; a package that needs more is one whose author should ship fewer
/// files, and a host that had no total would let a hundred small files exhaust the same memory one large one would.
pub(crate) const MAX_PACKAGE_BYTES: u64 = 96 * 1024 * 1024;

/// What an install produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The plugin's identifier, as its manifest spells it.
    pub plugin_id: String,
    /// The version that was installed.
    pub version: String,
    /// Where it now lives.
    pub path: PathBuf,
    /// The checks that passed with a warning, in sentences.
    ///
    /// A warning is a fact to tell the user — "this plugin's notification action will not work on this host" — and a
    /// report that dropped it would present a plugin that half-works as one that works.
    pub warnings: Vec<String>,
    /// Who signed the package, when it carried a genuine signature.
    ///
    /// ★ Carried out of the install because it is the **question** an interface has to ask next: the fingerprint is what a
    /// person compares, and a caller that had to re-read the signature file from the plugin directory would be reading a
    /// copy the install had already checked. It is also the only place the install knows the publisher was *new* — the
    /// prompt is worth showing for `seen`, and noise for a key the user already decided.
    pub signed_by: Option<SignedPublisher>,
}

/// The publisher of a package, as the install saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublisher {
    /// The publisher's own identifier.
    pub publisher_id: String,
    /// The key's fingerprint, as a person reads it.
    pub fingerprint: String,
    /// The key, base64. Not shown to the interface; stored because a fingerprint cannot be turned back into a key.
    pub pubkey: String,
}

/// Why an install did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRefusal {
    /// Which step refused: a [`verify::Stage`] name, or `source`/`manifest`/`read`/`write`/`record`.
    pub stage: &'static str,
    /// What was wrong, in a sentence an author can act on.
    pub reason: String,
}

impl InstallRefusal {
    fn new(stage: &'static str, reason: impl Into<String>) -> Self {
        Self { stage, reason: reason.into() }
    }

    /// The wire code this refusal carries.
    ///
    /// # Why one answer is enough for every check
    ///
    /// Because the distinction that matters to a caller is **whose problem it is**. A package a check refused — a path
    /// that is not there, a manifest that does not parse, a signature over other bytes, a dependency cycle — is the
    /// caller's: the detail names the stage and the author can act on it. The two stages that are not the caller's are
    /// the two after every check passed: writing the directory and recording the row, which are this host failing.
    ///
    /// This lives here rather than in each host because both the daemon and the shell answer the same refusal to a
    /// caller, and two mappings would be two chances to disagree about what an install failure means.
    #[must_use]
    pub fn code(&self) -> synra_protocol::error::ErrorCode {
        match self.stage {
            "write" | "record" => synra_protocol::error::ErrorCode::Internal,
            _ => synra_protocol::error::ErrorCode::InvalidArgument,
        }
    }
}

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

#[allow(clippy::too_many_arguments, reason = "the pipeline's inputs, plus whether it replaces an installed copy")]
fn from_directory_inner(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
    replace: bool,
) -> Result<Installed, InstallRefusal> {
    let source = source
        .canonicalize()
        .map_err(|error| InstallRefusal::new("source", format!("{}: {error}", source.display())))?;
    if !source.is_dir() {
        return Err(InstallRefusal::new("source", format!("{} is not a directory", source.display())));
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
    let version = manifest.version.to_string();

    let installed = db.plugin_is_installed(&plugin_id).unwrap_or(false);
    if replace && !installed {
        return Err(InstallRefusal::new("update", format!("{plugin_id} is not installed, so there is nothing to update")));
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
    let mut files: Vec<(String, Vec<u8>)> = vec![("manifest.json".to_owned(), manifest_json.clone().into_bytes())];
    let mut digests = Digests::new();
    let mut total = manifest_json.len() as u64;
    for name in artifact_names(&manifest) {
        if !is_plain_file_name(&name) {
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
                format!("{name} is {declared_size} bytes, over the {MAX_ARTIFACT_BYTES} an artifact may be"),
            ));
        }
        let bytes = std::fs::read(&path).map_err(|error| InstallRefusal::new("read", format!("{name}: {error}")))?;
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
        Err(error) => return Err(InstallRefusal::new("read", format!("signature.json: {error}"))),
    };

    // ── The imports, which need a compiled artifact ─────────────────────────────────────────────────────────────────
    //
    // Compiling here is not a second load: it is the only way to learn what a component imports, which is the fact two
    // of the eleven checks are about. The compile cache makes the later load reuse it.
    let headless = manifest.runtime.headless.as_ref().map(|runtime| runtime.artifact.clone());
    let wasm: &[u8] = match &headless {
        Some(name) => files
            .iter()
            .find(|(file, _)| file == name)
            .map(|(_, bytes)| bytes.as_slice())
            .unwrap_or(&[]),
        None => &[],
    };
    let imports: Vec<String> = if headless.is_some() {
        let compiled = backend
            .compile(wasm, &plugin_id)
            .map_err(|error| InstallRefusal::new("wit-compatibility", error.to_string()))?;
        // Cloned rather than borrowed because the artifact is dropped here and the candidate outlives it. A thousand
        // short strings is nothing beside the compile this just paid for.
        compiled.imports().to_vec()
    } else {
        // A UI-only plugin has no component to compile, and passing an empty import set is the accurate answer rather
        // than a shortcut: nothing in it imports anything.
        Vec::new()
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
        manifest: None,
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
        imports: &imports,
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

    let warnings: Vec<String> = report
        .warnings()
        .iter()
        .map(|step| format!("{}: {}", step.stage.as_str(), step.detail))
        .collect();

    // ── Writing, atomically ─────────────────────────────────────────────────────────────────────────────────────────
    //
    // A staging directory beside the destination and one rename: a plugin directory that exists is one `load_one`
    // will look at, so half an install must never be visible under the name it will be loaded from.
    let destination = plugins_dir.join(&plugin_id);
    // An update replaces exactly this directory; an install has nothing to replace and refuses rather than overwriting a
    // copy the user did not ask to lose.
    if destination.exists() && !replace {
        return Err(InstallRefusal::new(
            "write",
            format!("{} already exists on disk", destination.display()),
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| InstallRefusal::new("write", format!("{} has no parent directory", destination.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| InstallRefusal::new("write", format!("{}: {error}", parent.display())))?;
    // ★ The staging area is **outside** `plugins/`, and that is not tidiness.
    //
    // `record_discovered_plugins` treats any directory that contains a manifest as an installed plugin, so a half-written
    // staging directory inside the plugins tree would be discovered on the next start as a plugin with a truncated
    // artifact — an install that failed would become a plugin that is broken. Under `<data>/.install-staging/` it is only
    // what it is, and it is on the same volume as the destination, so the rename below stays a rename.
    let staging_root = plugins_dir.parent().unwrap_or(plugins_dir).join(".install-staging");
    std::fs::create_dir_all(&staging_root)
        .map_err(|error| InstallRefusal::new("write", format!("{}: {error}", staging_root.display())))?;
    // ★ The identifier is flattened, not used as a path: an id contains a slash (`@acme/hello`), and a staging name
    // built from it would name a directory two levels down — which is the error this line was first written with.
    let staging = staging_root.join(format!("{}.{now_ms}", plugin_id.replace(['/', '\\'], "_")));
    if staging.exists() {
        // A leftover from a crash. Refused rather than removed: the recursive delete the removal would need is the
        // sandbox's operation, not this module's, and a timestamp collision is a clock that went backwards.
        return Err(InstallRefusal::new(
            "write",
            format!("{} is left over from an earlier install", staging.display()),
        ));
    }
    std::fs::create_dir(&staging)
        .map_err(|error| InstallRefusal::new("write", format!("{}: {error}", staging.display())))?;
    let mut failure: Option<String> = None;
    for (name, bytes) in &files {
        if let Err(error) = std::fs::write(staging.join(name), bytes) {
            failure = Some(format!("{name}: {error}"));
            break;
        }
    }
    if let Some(reason) = failure {
        discard(&staging, &files);
        return Err(InstallRefusal::new("write", reason));
    }
    // ── The UI half, unpacked beside the artifact ───────────────────────────────────────────────────────────────────
    //
    // The bundle's zip is already in `files` (verified like any other artifact), so this step is only "write it out where
    // the `synra-plugin://` handler will look". It runs **before** the rename, so a UI that cannot be unpacked is a failed
    // install rather than an installed plugin whose window is blank.
    if let Some(ui) = manifest.runtime.ui.as_ref() {
        let archive = staging.join(&ui.artifact);
        if let Err(error) = synra_plugin_ui::artifact::unpack(
            &archive,
            &synra_plugin_ui::artifact::bundle_dir(&staging),
            synra_plugin_ui::artifact::ArchiveLimits::artifact(),
        ) {
            // `unpack` removes what it wrote before refusing; `discard` removes the artifact files. Together they leave the
            // staging directory as empty as it started.
            discard(&staging, &files);
            return Err(InstallRefusal::new("unpack", format!("{}: {error}", ui.artifact)));
        }
    }

    let backup = if replace {
        let path = staging_root.join(format!("previous-{}", plugin_id.replace(['/', '\\'], "_")));
        // A backup left by a crash is stale by definition: the version row either landed with the new directory or the
        // update never reached this point. Removing it before the move keeps one backup, not a growing set.
        let _ = synra_store::remove_tree(&staging_root, &path);
        if let Err(error) = std::fs::rename(&destination, &path) {
            discard(&staging, &files);
            return Err(InstallRefusal::new("write", format!("{}: {error}", destination.display())));
        }
        Some(path)
    }
    else {
        None
    };

    if let Err(error) = std::fs::rename(&staging, &destination) {
        discard(&staging, &files);
        if let Some(backup) = &backup {
            let _ = synra_store::remove_tree(plugins_dir, &destination);
            let _ = std::fs::rename(backup, &destination);
        }
        return Err(InstallRefusal::new("write", format!("{}: {error}", destination.display())));
    }

    // ── The row, and the rollback if it does not land ───────────────────────────────────────────────────────────────
    //
    // The two writes — the directory and the row — cannot both be atomic together, so the directory is undone when the
    // row fails. The other order would leave a row naming files that were never written, which `load_installed` would
    // report as a broken plugin rather than as a failed install.
    //
    // An update does not insert: the row (and the user's enabled decision) already exists, and installing a new version is
    // not the moment to forget that the plugin was on — **unless it asks for more**. A new capability is a decision the
    // user made about the old package and not about this one, so the plugin comes back switched off and untrusted, and
    // the consent screen asks again.
    let row_written = if replace {
        let previous_enabled = db
            .plugins()
            .ok()
            .and_then(|rows| rows.into_iter().find(|row| row.plugin_id == plugin_id))
            .is_some_and(|row| row.enabled);
        let previous_capabilities = backup.as_ref().map(|path| capabilities_in(path)).unwrap_or_default();
        let grew = manifest
            .capabilities
            .iter()
            .any(|declaration| !previous_capabilities.contains(&declaration.cap));
        let keep_enabled = previous_enabled && !grew;
        let written = db
            .set_plugin_enabled(&plugin_id, keep_enabled, now_ms)
            .map(|_| ())
            .map_err(|error| error.to_string());
        if written.is_ok() && grew {
            // The approval was about the old permission list; the new one has to be asked for again.
            let _ = db.set_plugin_trusted(&plugin_id, false, now_ms);
        }
        written
    }
    else {
        db.insert_plugin(&plugin_id, false, false, "installed", now_ms, now_ms)
            .map_err(|error| error.to_string())
    };
    if let Err(error) = row_written {
        if let Some(backup) = &backup {
            let _ = synra_store::remove_tree(plugins_dir, &destination);
            let _ = std::fs::rename(backup, &destination);
        }
        else {
            discard(&destination, &files);
        }
        return Err(InstallRefusal::new("record", error));
    }

    // ── Which version is now the one in effect ─────────────────────────────────────────────────────────────────────
    //
    // ★ **This row was missing from the pipeline, and its absence was invisible.** `active_plugin_version` reads
    // `plugin_versions`; every doc that mentioned the table said the installer wrote it; the installer wrote `plugins` and
    // the files and never touched it. So a freshly installed plugin had no active version, and every sync plan — the only
    // reader — answered "this device has no such plugin".
    //
    // ★ **Why an empty digest rather than the empty artifact's digest**: a UI-only plugin has no headless artifact, and
    // `ObjectDigest::of(&[])` is a real digest of zero bytes — recording it would claim the plugin holds an artifact that is
    // not there. Empty is the store's word for "none", the same shape the receiving side writes when it knows the bytes but
    // not the version.
    //
    // ★ **The rollback is the pair.** The plugin row was written a line earlier, so a failure here would leave a plugin that
    // appears installed with no version and no files (they are discarded below) — the state that makes the loader report a
    // broken plugin instead of a failed install.
    let active_digest = if headless.is_some() { artifact_digest.clone() } else { String::new() };
    if let Err(error) = db.record_plugin_version(
        &plugin_id,
        &version,
        headless.as_deref().unwrap_or_default(),
        &active_digest,
        &manifest_json,
        now_ms,
    ) {
        if let Some(backup) = &backup {
            let _ = synra_store::remove_tree(plugins_dir, &destination);
            let _ = std::fs::rename(backup, &destination);
        }
        else {
            let _ = db.remove_plugin(&plugin_id);
            discard(&destination, &files);
        }
        return Err(InstallRefusal::new("record", error.to_string()));
    }

    // ★ Recorded after the install succeeded, not before: a package that failed a check did not make its publisher a
    // part of this device's history, and a row written for it would make the next prompt say "seen before" about a
    // signature this device refused.
    let signed_by = signature.as_deref().and_then(signed_publisher);
    if let Some(publisher) = &signed_by {
        let _ = db.record_publisher(
            &publisher.publisher_id,
            &publisher.fingerprint,
            &publisher.pubkey,
            now_ms,
        );
    }

    // ★ The old directory is removed only now: it was the rollback for both the move and the version row, and deleting it
    // earlier would have made a failed record unrecoverable.
    if let Some(backup) = backup {
        let _ = synra_store::remove_tree(&staging_root, &backup);
    }

    Ok(Installed { plugin_id, version, path: destination, warnings, signed_by })
}

/// The publisher decisions this device has made, in the shape the verifier takes.
///
/// A malformed fingerprint is skipped rather than failing the install: the row is this device's own record, and a
/// package must not be refused because a storage row cannot be read — the signature was checked regardless.
fn trust_store(db: &synra_store::SynraDb) -> PublisherTrustStore {
    let mut store = PublisherTrustStore::new();
    for row in db.publishers().unwrap_or_default() {
        let Ok(fingerprint) = Fingerprint::parse(&row.fingerprint) else {
            continue;
        };
        match row.trust.as_str() {
            synra_store::TRUST_TRUSTED => store.trust(row.publisher_id, fingerprint),
            synra_store::TRUST_REVOKED => store.revoke(fingerprint, "the user revoked this key"),
            _ => {}
        }
    }
    store
}

/// The capabilities the manifest in one directory declares.
///
/// Used only for the update's before/after comparison; a directory whose manifest cannot be read answers an empty list,
/// which makes the comparison conservative in the direction that matters — every capability then counts as new, so the
/// plugin is switched off rather than silently kept on with permissions nobody reviewed.
fn capabilities_in(directory: &Path) -> Vec<String> {
    std::fs::read_to_string(directory.join("manifest.json"))
        .ok()
        .and_then(|text| Manifest::from_json(&text).ok())
        .map(|manifest| manifest.capabilities.into_iter().map(|declaration| declaration.cap).collect())
        .unwrap_or_default()
}

/// The publisher of a signature this build verified, if it is one.
fn signed_publisher(signature: &str) -> Option<SignedPublisher> {    let document = SignatureFile::parse(signature).ok()?;
    let VerifyOutcome::Good { fingerprint } = document.verify().ok()? else {
        return None;
    };
    Some(SignedPublisher {
        publisher_id: document.publisher.id.clone(),
        fingerprint: fingerprint.as_str().to_owned(),
        pubkey: document.pubkey,
    })
}

/// Installs a plugin from a `.synra` archive.
///
/// # What the archive is
///
/// A zip of the directory [`from_directory`] takes: `manifest.json`, the artifacts the manifest names, and
/// `signature.json` when the publisher signed it. The container is zip because the UI half is already one and the same
/// reader covers both — and because the unpacking rules that matter (no `..`, no absolute path, no link, entry and size
/// limits) are about archives rather than about UI bundles, so there is one implementation of them.
///
/// # Why the unpack goes through the UI crate
///
/// Because `synra_plugin_ui::artifact::unpack` is the tested implementation of those rules, with a plan-then-write split
/// and a cleanup of what a refusal already wrote. A second unpacker here would be a second place for a zip-slip check to
/// be forgotten.
///
/// # Errors
///
/// [`InstallRefusal`] with stage `archive` for an archive the rules refuse, and any stage [`from_directory`] reports.
pub fn from_package(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    archive: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    let staging_root = plugins_dir.parent().unwrap_or(plugins_dir).join(".install-staging");
    std::fs::create_dir_all(&staging_root)
        .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", staging_root.display())))?;
    // Outside `plugins/` for the same reason the installer's own staging is: a directory with a manifest under the
    // plugins tree is discovered as an installed plugin, so a half-unpacked archive must not be there.
    let unpacked = staging_root.join(format!("package.{now_ms}.{}", std::process::id()));
    if unpacked.exists() {
        return Err(InstallRefusal::new(
            "archive",
            format!("{} is left over from an earlier install", unpacked.display()),
        ));
    }
    std::fs::create_dir(&unpacked)
        .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", unpacked.display())))?;

    let written = match synra_plugin_ui::artifact::unpack(
        archive,
        &unpacked,
        synra_plugin_ui::artifact::ArchiveLimits::package(),
    ) {
        Ok(written) => written,
        Err(error) => {
            // The unpacker removed the files it wrote; what is left is the directory this function made.
            let _ = std::fs::remove_dir(&unpacked);
            return Err(InstallRefusal::new("archive", error.to_string()));
        }
    };
    let outcome = from_directory(db, backend, plugins_dir, &unpacked, now_ms, host);
    discard_unpacked(&unpacked, &written);
    outcome
}

/// Writes a directory as a `.synra` archive, for the side that sends one.
///
/// # What is left out, and why
///
/// The unpacked UI directory (`ui/`) is not part of the package: the archive carries the `ui.zip` the manifest names, and
/// the unpacked copy is this device's rendering of it. Including both would double every UI plugin and, worse, ship a
/// second copy that the installer would then overwrite from the zip — two sources for one directory.
///
/// # Errors
///
/// [`InstallRefusal`] with stage `archive` when the directory cannot be walked, a limit is exceeded, or the archive
/// cannot be written.
pub fn package_directory(source: &Path, archive: &Path) -> Result<(), InstallRefusal> {
    use std::io::Write as _;

    let file = std::fs::File::create(archive)
        .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", archive.display())))?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut entries: Vec<PathBuf> = Vec::new();
    let mut pending = vec![source.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let read = std::fs::read_dir(&directory)
            .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", directory.display())))?;
        for entry in read {
            let entry = entry
                .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", directory.display())))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", path.display())))?;
            if kind.is_dir() {
                // The unpacked UI is rebuilt from `ui.zip`; everything else is part of the package.
                if path.file_name().is_some_and(|name| name == "ui") && directory == source {
                    continue;
                }
                pending.push(path);
            }
            else if kind.is_file() {
                entries.push(path);
            }
        }
    }
    entries.sort();

    let mut total = 0u64;
    for path in entries {
        let bytes = std::fs::read(&path)
            .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", path.display())))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_PACKAGE_BYTES {
            return Err(InstallRefusal::new(
                "archive-limits",
                format!("the package is over the {MAX_PACKAGE_BYTES} bytes a package may be"),
            ));
        }
        let relative = path
            .strip_prefix(source)
            .map_err(|error| InstallRefusal::new("archive", format!("{}: {error}", path.display())))?;
        let name = relative.to_string_lossy().replace('\\', "/");
        writer
            .start_file(name, options)
            .map_err(|error| InstallRefusal::new("archive", error.to_string()))?;
        writer
            .write_all(&bytes)
            .map_err(|error| InstallRefusal::new("archive", error.to_string()))?;
    }
    writer
        .finish()
        .map_err(|error| InstallRefusal::new("archive", error.to_string()))?;
    Ok(())
}

/// Removes what an unpack wrote, without a recursive delete.
///
/// The same rule as [`discard`]: a recursive delete turns a path mistake into somebody's lost files. The list is known —
/// the unpacker returned it — so each file is removed, then the now-empty directories deepest first. A directory holding
/// something this module did not write is left, and the caller does not care.
fn discard_unpacked(directory: &Path, written: &[PathBuf]) {
    for path in written.iter().rev() {
        let _ = std::fs::remove_file(path);
    }
    let mut parents: Vec<PathBuf> = written
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    parents.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    parents.dedup();
    for parent in parents {
        if parent.starts_with(directory) {
            let _ = std::fs::remove_dir(&parent);
        }
    }
    let _ = std::fs::remove_dir(directory);
}

/// Every file the manifest says the package consists of.
///
/// `pub(crate)` because the startup scan hashes the same set: an artifact list read one way by the install and another
/// way by the scan would be two answers to "what is in this package".
pub fn artifact_names(manifest: &Manifest) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(headless) = &manifest.runtime.headless {
        names.push(headless.artifact.clone());
    }
    if let Some(ui) = &manifest.runtime.ui {
        names.push(ui.artifact.clone());
    }
    names.sort();
    names.dedup();
    names
}

/// Whether a manifest-supplied name is a file name inside the package.
///
/// # Why this is checked rather than trusted
///
/// Because the manifest is third-party data. `../../.ssh/authorized_keys` is a string that joins to a path, and a join
/// that follows it reads and installs a file from outside the package — the same class of escape an archive unpacker
/// has to refuse. Separators, drive-relative names and `.`/`..` are the whole of the rule a flat package needs.
fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', ':'])
}

/// Removes a directory this module made, without a recursive delete.
///
/// # Why not `remove_dir_all`
///
/// Because the workspace's structural guard says only the sandbox may delete a directory tree (11 §D2), and it is
/// right: a recursive delete is the operation that turns a path mistake into somebody's lost files. Everything in a
/// staging directory here is a file this function wrote, so the exact list is known — a `remove_file` for each, then
/// the now-empty `remove_dir`. No recursion, no glob, and nothing that could walk somewhere else.
///
/// The empty `remove_dir` is what reports a directory that contains something this module did not put there: the caller
/// ignores the result, so a leftover is left rather than a stranger's file deleted.
fn discard(directory: &Path, files: &[(String, Vec<u8>)]) {
    for (name, _) in files {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let _ = std::fs::remove_dir(directory);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::Arc;

    /// A scratch directory for one test, removed by the test.
    fn scratch(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("synra-package-{label}-{}-{}", std::process::id(), crate::reading_millis(synra_store::sqlite::now_ms())))
    }

    /// A manifest naming one headless artifact, in the shape the verifier accepts.
    fn manifest() -> String {
        format!(
            r#"{{"id": "@acme/hello", "version": "1.0.0", "title": "Hello",
                "publisher": {{"id": "@acme"}}, "sdk": {{"min": "0.1.0"}},
                "wit": "{}",
                "capabilities": [{{"cap": "log:*"}}],
                "runtime": {{"headless": {{"artifact": "plugin.wasm", "stateful": false}}}}}}"#,
            synra_plugin_host::host_world()
        )
    }

    /// A directory an installer would take: a manifest and one artifact.
    fn write_source(directory: &Path) {
        std::fs::create_dir_all(directory).expect("the source directory");
        std::fs::write(directory.join("manifest.json"), manifest()).expect("a manifest");
        std::fs::write(directory.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");
    }

    fn backend() -> Backend {
        Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new()))
    }

    fn database() -> synra_store::SynraDb {
        let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
        db.migrate().expect("migrates");
        db
    }

    #[test]
    fn a_package_installs_what_the_directory_inside_it_would() {
        let root = scratch("valid");
        let source = root.join("source");
        write_source(&source);
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("hello.synra");
        package_directory(&source, &archive).expect("the package is written");

        let mut db = database();
        let installed =
            from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
                .expect("the package installs");

        assert_eq!(installed.plugin_id, "@acme/hello");
        assert_eq!(installed.version, "1.0.0");
        assert!(installed.path.join("manifest.json").is_file(), "the manifest was not written");
        assert!(installed.path.join("plugin.wasm").is_file(), "the artifact was not written");
        assert!(
            !root.join(".install-staging").read_dir().expect("the staging directory").any(|_| true),
            "the unpacked archive was left behind"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_that_escapes_its_directory_is_refused_before_anything_is_installed() {
        // ★ The archive's own rules, not the installer's: an entry named `../escape.txt` is a package asking to write
        // outside the directory it is unpacked into. `unpack` refuses it and removes what it wrote, and the installer is
        // never reached.
        let root = scratch("escape");
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("evil.synra");
        {
            let file = std::fs::File::create(&archive).expect("a file");
            let mut writer = zip::ZipWriter::new(file);
            for (name, bytes) in [
                ("manifest.json", manifest().into_bytes()),
                ("../escape.txt", b"outside".to_vec()),
            ] {
                writer
                    .start_file(name, zip::write::SimpleFileOptions::default())
                    .expect("an entry");
                writer.write_all(&bytes).expect("the bytes");
            }
            writer.finish().expect("a finished archive");
        }

        let mut db = database();
        let refused = from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
            .expect_err("the entry escapes");

        assert_eq!(refused.stage, "archive", "{}", refused.reason);
        assert!(!root.join("escape.txt").exists(), "the entry was written outside the package");
        assert!(
            !plugins.join("@acme/hello").exists(),
            "a refused package left an installed plugin behind"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_with_no_manifest_is_refused_by_the_installer() {
        let root = scratch("no-manifest");
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("empty.synra");
        {
            let file = std::fs::File::create(&archive).expect("a file");
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file("plugin.wasm", zip::write::SimpleFileOptions::default())
                .expect("an entry");
            writer.write_all(b"\0asm\x01\0\0\0").expect("the bytes");
            writer.finish().expect("a finished archive");
        }

        let mut db = database();
        let refused = from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
            .expect_err("there is no manifest");

        assert_eq!(refused.stage, "read", "{}", refused.reason);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn packaging_an_installed_plugin_leaves_the_unpacked_ui_out() {
        // ★ `ui.zip` is the artifact; `ui/` is this device's rendering of it. Shipping both would send the same files
        // twice and give the installer two sources for one directory.
        let root = scratch("ui");
        let source = root.join("source");
        write_source(&source);
        std::fs::create_dir_all(source.join("ui")).expect("a ui directory");
        std::fs::write(source.join("ui").join("index.html"), b"<html></html>").expect("a ui file");
        std::fs::write(source.join("ui.zip"), b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").expect("a ui zip");
        let archive = root.join("hello.synra");
        package_directory(&source, &archive).expect("the package is written");

        let mut zip = zip::ZipArchive::new(std::fs::File::open(&archive).expect("the archive")).expect("a zip");
        let mut names: Vec<String> = (0..zip.len())
            .map(|index| zip.by_index(index).expect("an entry").name().to_owned())
            .collect();
        names.sort();

        assert!(names.contains(&"ui.zip".to_owned()), "{names:?}");
        assert!(!names.iter().any(|name| name.starts_with("ui/")), "the unpacked UI was packaged: {names:?}");
        assert!(names.contains(&"manifest.json".to_owned()));
        let _ = std::fs::remove_dir_all(&root);
    }
}
