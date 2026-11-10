//! Packing a plugin into the archive a registry serves.
//!
//! # The shape, and why it is npm's
//!
//! A registry install reads an npm **packument** and then the tarball its `dist.tarball` names (16 §4.1). npm's tarball
//! is gzip around tar with every file under `package/`, so this module writes exactly that: the manifest, the artifacts
//! the manifest names, and `signature.json` when the package has one, all under `package/`.
//!
//! # What is deliberately excluded
//!
//! Everything else in the directory. A plugin directory after a build also holds sources, tests and build output; packing
//! the tree would ship them to every user, and a tarball is not the place to decide which of an author's files are
//! private. The list is the manifest's, which is also the list the installer reads.
//!
//! # Why the archive is written here rather than by `tar`'s own `pack`
//!
//! Because the metadata is part of the promise: a fixed mode and mtime make two packs of unchanged files byte-identical,
//! so a registry's digest of a version does not change because a build machine's clock did.

use std::path::Path;

use synra_plugin_api::Manifest;

use crate::package_artifacts::artifact_names;
use crate::run::Outcome;

mod archive;
mod index;
mod urls;

pub use archive::write_archive;
use index::merge_index;
use urls::{index_base, registry_base};

/// Packs a plugin directory, or says why it cannot be packed.
///
/// # Errors
///
/// A sentence naming the file that is missing or unreadable. The checks are the ones the installer would make — the
/// archive is not the place to discover that `manifest.json` names an artifact that is not there.
pub fn pack_plugin(args: &crate::args::PackArgs) -> Result<Outcome, String> {
    let dir = &args.dir;

    // ★ The same checks `verify` makes, at the one moment an author is about to publish: a tarball is how a broken package
    // reaches users, and an archive that exists is easier to trust than a report that was skipped.
    let report = crate::verify::verify(&crate::verify::Target::read(dir));
    if !report.is_ok() {
        let mut lines = vec![format!("{} cannot be packed:", dir.display())];
        for finding in report.findings.iter().filter(|finding| finding.verdict.is_failure()) {
            lines.push(format!("  {}: {}", finding.name, finding.detail));
        }
        return Ok(Outcome::Reported { lines, code: 1, failure: true });
    }

    let manifest_text = std::fs::read_to_string(dir.join("manifest.json"))
        .map_err(|error| format!("{}/manifest.json: {error}", dir.display()))?;
    let manifest = Manifest::from_json(&manifest_text)
        .map_err(|error| format!("manifest.json: {error}"))?;

    let artifacts = artifact_names(&manifest);
    for name in &artifacts {
        let path = dir.join(name);
        if !path.is_file() {
            return Err(format!("{name} is named by the manifest but is not in {}", dir.display()));
        }
    }

    let signature_path = dir.join("signature.json");
    // ★ A signature that exists is not a signature that covers this package. The check is the installer's own, with an
    // empty trust store: the question here is cryptographic ("did this key sign these bytes?"), not "does the user trust
    // the key?" — which is a decision the installing device makes later.
    let mut signed_by = None;
    if signature_path.is_file() {
        let document = std::fs::read_to_string(&signature_path)
            .map_err(|error| format!("{}/signature.json: {error}", dir.display()))?;
        let trust = synra_plugin_api::publisher::PublisherTrustStore::new();
        match crate::sign::verify(&document, dir, &trust) {
            Ok(verified) => signed_by = Some((verified.publisher_id, verified.fingerprint.to_string())),
            Err(error) => {
                return Ok(Outcome::Reported {
                    lines: vec![
                        format!("{} cannot be packed:", dir.display()),
                        format!("  signature: {error}"),
                    ],
                    code: 1,
                    failure: true,
                });
            }
        }
    }
    let signature = signature_path.is_file().then_some(signature_path);

    let target = args.out.clone().unwrap_or_else(|| {
        let file = format!("{}-{}.tgz", manifest.id.to_string().replace(['/', '\\'], "-"), manifest.version);
        let dist = dir.join("dist");
        // With a relative index the tarball sits in the index's own directory: `dist/@acme/hello.json` names
        // `@acme-hello-1.2.3.tgz` relatively, and a relative name that resolves to the same directory is the point.
        match &args.index {
            Some(base) if base.is_empty() => {
                let id = manifest.id.to_string();
                let folder = id.rsplit_once('/').map_or_else(|| dist.clone(), |(scope, _)| dist.join(scope));
                folder.join(file)
            }
            _ => dist.join(file),
        }
    });

    // ★ A registry is checked for shape, not contacted. Publishing is an account and a policy; what this tool can know is
    // whether the address it would send an author to is one the installing side could ever read (16 §4.2).
    let publish_to = match args.registry.as_deref().map(registry_base) {
        Some(Ok(registry)) => Some(registry),
        Some(Err(reason)) => {
            return Ok(Outcome::Reported {
                lines: vec![format!("--registry is not usable: {reason}")],
                code: 1,
                failure: true,
            });
        }
        None => None,
    };

    let index_to = match args.index.as_deref() {
        // `--index` with no value: the tarball is named relative to the index, and the client resolves it. An author
        // uploading to a bucket usually does not know its public URL at pack time.
        Some("") => Some(String::new()),
        Some(url) => match index_base(url) {
            Ok(base) => Some(base),
            Err(reason) => {
                return Ok(Outcome::Reported {
                    lines: vec![format!("--index is not usable: {reason}")],
                    code: 1,
                    failure: true,
                });
            }
        },
        None => None,
    };

    let mut lines = vec![
        format!("packing {} {}", manifest.id, manifest.version),
        "  manifest.json".to_owned(),
    ];
    for name in &artifacts {
        lines.push(format!("  {name}"));
    }
    if signature.is_some() {
        lines.push("  signature.json".to_owned());
    }
    lines.push(format!("  -> {}", target.display()));
    if let Some(registry) = publish_to {
        lines.push(format!(
            "publish with: npm publish --registry {registry} {}",
            target.display()
        ));
    }

    // ★ The index is the other half of static publishing: one document per package, beside the tarball, naming the
    // version and the key that signed it (16 §4.4). Writing it here keeps the two in step — a hand-edited index is a
    // second description of the same pack, and the two drift.
    let index = match index_to {
        Some(base) => {
            let file = target
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .ok_or_else(|| format!("{} has no file name", target.display()))?;
            let manifest_value: serde_json::Value = serde_json::from_str(&manifest_text)
                .map_err(|error| format!("manifest.json: {error}"))?;
            let path = if args.out.is_none() {
                // The default layout puts every tarball under `dist/<id>/` and the index at `dist/<id>.json`; a relative
                // name then resolves inside that directory, which is what a bucket serves.
                dir.join("dist").join(format!("{}.json", manifest.id))
            }
            else {
                target
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(format!("{}.json", manifest.id))
            };
            // ★ Publishing a second version must not erase the first: the index is the package's whole history, and an
            // author who re-packs 1.3.0 would otherwise drop every install still asking for 1.2.0.
            let existing = match std::fs::read_to_string(&path) {
                Ok(text) => Some(text),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(format!("{}: {error}", path.display())),
            };
            let publisher = signed_by.as_ref().map(|(id, fingerprint)| (id.as_str(), fingerprint.as_str()));
            let tarball = if base.is_empty() {
                file
            }
            else {
                format!("{base}/{file}")
            };
            let text = merge_index(
                existing.as_deref(),
                &manifest.id.to_string(),
                &manifest.version,
                &tarball,
                &manifest_value,
                publisher,
            )?;
            lines.push(format!("  index    {}", path.display()));
            Some((path, text))
        }
        None => None,
    };

    Ok(Outcome::Archive {
        target,
        manifest: dir.join("manifest.json"),
        artifacts,
        signature,
        index,
        lines,
    })
}

#[cfg(test)]
mod tests;
