//! Installing a plugin from a directory on this machine, through the checks the design document orders.
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
//! Whether the user trusts the publisher, and whether the plugin may run. The row it writes is **installed, switched
//! off and untrusted** — the design's `AwaitingConsent` in durable form — so installing and approving stay two acts.

use std::path::{Path, PathBuf};

use synra_core::transfer::ObjectDigest;
use synra_plugin_api::Manifest;
use synra_plugin_api::publisher::{Digests, PublisherTrustStore};
use synra_plugin_host::Backend;
use synra_plugin_host::verify::{self, Candidate, DependencyGraph, HostFacts};

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
}

/// Installs the plugin in `source` into `plugins_dir`, after verifying it.
///
/// # Errors
///
/// [`InstallRefusal`] naming the step that refused. Nothing is written to `plugins_dir` and no row is recorded unless
/// every check passed and the copy completed.
pub fn from_directory(
    db: &synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
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

    if db.plugin_is_installed(&plugin_id).unwrap_or(false) {
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

    let manifest_digest = ObjectDigest::of(manifest_json.as_bytes()).as_sri().to_string();
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
        host: HostFacts::headless(),
    };

    // The publisher store is empty, which is the honest state of a daemon that has never recorded a publisher: every
    // publisher is new, and the pipeline reports that so the interface can ask rather than refusing the first install
    // from anybody. Persisting it is `PublisherTrustStore`'s own gap, not this module's.
    let report = verify::verify(&candidate, &PublisherTrustStore::new())
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
    if destination.exists() {
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
    if let Err(error) = std::fs::rename(&staging, &destination) {
        discard(&staging, &files);
        return Err(InstallRefusal::new("write", format!("{}: {error}", destination.display())));
    }

    // ── The row, and the rollback if it does not land ───────────────────────────────────────────────────────────────
    //
    // The two writes — the directory and the row — cannot both be atomic together, so the directory is undone when the
    // row fails. The other order would leave a row naming files that were never written, which `load_installed` would
    // report as a broken plugin rather than as a failed install.
    if let Err(error) = db.insert_plugin(&plugin_id, false, false, "installed", now_ms, now_ms) {
        discard(&destination, &files);
        return Err(InstallRefusal::new("record", error.to_string()));
    }

    Ok(Installed { plugin_id, version, path: destination, warnings })
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

/// Every file the manifest says the package consists of.
fn artifact_names(manifest: &Manifest) -> Vec<String> {
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

#[cfg(test)]
mod tests;
