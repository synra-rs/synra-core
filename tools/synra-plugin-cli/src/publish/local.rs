//! Checks the local archives listed by the index before they are served.

use std::path::{Path, PathBuf};

use crate::package_artifacts::artifact_names;

use super::local_tarball;

/// Checks one version's tarball, returning the line to print or the failure.
pub(super) fn check_version(
    version: &str,
    entry: &synra_registry::Version,
    directory: &Path,
    base: Option<&str>,
) -> Result<String, String> {
    let local = local_tarball(directory, base, &entry.dist.tarball)
        .map_err(|reason| format!("  {version}  {reason}"))?;
    let bytes = std::fs::read(&local).map_err(|error| format!("  {version}  {}: {error}", local.display()))?;

    let extracted = extract_for_check(&bytes)
        .map_err(|reason| format!("  {version}  {}: {reason}", local.display()))?;
    let signature = extracted.dir.join("signature.json");
    let signed = if signature.is_file() {
        let document = std::fs::read_to_string(&signature)
            .map_err(|error| format!("  {version}  signature.json: {error}"))?;
        let trust = synra_plugin_api::publisher::PublisherTrustStore::new();
        let verified = crate::sign::verify(&document, &extracted.dir, &trust)
            .map_err(|error| format!("  {version}  the signature does not cover this tarball: {error}"));
        if let Err(line) = verified {
            cleanup(&extracted);
            return Err(line);
        }
        true
    }
    else {
        false
    };

    // The manifest is read from the source directory, not the archive: it is what the author just packed, and the archive
    // check only has to agree that its files are there.
    let manifest = synra_plugin_api::Manifest::from_json(&entry_text(entry)?)
        .map_err(|error| format!("  {version}  the index's inline manifest: {error}"))?;
    let missing: Vec<String> = artifact_names(&manifest)
        .into_iter()
        .filter(|name| !extracted.dir.join(name).is_file())
        .collect();
    if !missing.is_empty() {
        let names = missing.join(", ");
        cleanup(&extracted);
        return Err(format!("  {version}  the tarball does not contain {names}"));
    }

    let size = bytes.len();
    cleanup(&extracted);
    Ok(format!(
        "  {version}  {}  {size} bytes  {}",
        local.display(),
        if signed { "signed" } else { "unsigned" }
    ))
}

/// The index's inline manifest, as text, or a refusal naming the version.
fn entry_text(entry: &synra_registry::Version) -> Result<String, String> {
    let manifest = entry
        .synra
        .as_ref()
        .ok_or_else(|| "the index carries no inline manifest, so the tarball cannot be checked".to_owned())?;
    serde_json::to_string(manifest).map_err(|error| error.to_string())
}

/// A tarball unpacked under a fresh temporary directory.
struct Extracted {
    /// Where it was unpacked.
    dir: PathBuf,
    /// The files written, so cleanup can remove exactly them.
    files: Vec<PathBuf>,
}

/// Unpacks a tarball into a fresh directory for checking.
fn extract_for_check(bytes: &[u8]) -> Result<Extracted, String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("synra-publish-{}-{stamp}", std::process::id()));
    let files = synra_registry::extract_tgz(
        bytes,
        &dir,
        Some("package"),
        synra_registry::Limits::default(),
    )
    .map_err(|error| error.to_string())?;
    Ok(Extracted { dir, files })
}

/// Removes what [`extract_for_check`] wrote, deepest first, without a recursive delete.
fn cleanup(extracted: &Extracted) {
    for file in &extracted.files {
        let _ = std::fs::remove_file(file);
    }
    let mut directories: Vec<PathBuf> = extracted
        .files
        .iter()
        .filter_map(|file| file.parent().map(Path::to_path_buf))
        .collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    for directory in directories {
        if directory.starts_with(&extracted.dir) {
            let _ = std::fs::remove_dir(&directory);
        }
    }
    let _ = std::fs::remove_dir(&extracted.dir);
}
