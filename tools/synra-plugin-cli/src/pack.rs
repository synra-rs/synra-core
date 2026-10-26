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

use crate::run::Outcome;

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

/// Writes the archive an [`Outcome::Archive`] describes.
///
/// # Errors
///
/// A sentence naming the file that could not be written or read.
pub fn write_archive(
    target: &Path,
    manifest: &Path,
    artifacts: &[String],
    signature: Option<&Path>,
) -> Result<(), String> {
    if let Some(parent) = target.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(format!("{}: {error}", parent.display()));
    }
    let file = std::fs::File::create(target).map_err(|error| format!("{}: {error}", target.display()))?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);

    append(&mut builder, manifest, "manifest.json")?;
    for name in artifacts {
        let source = manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(name);
        append(&mut builder, &source, name)?;
    }
    if let Some(signature) = signature {
        append(&mut builder, signature, "signature.json")?;
    }

    let encoder = builder.into_inner().map_err(|error| error.to_string())?;
    encoder.finish().map_err(|error| error.to_string())?;
    Ok(())
}

/// Appends one file under `package/`, with fixed metadata so two packs of unchanged files match byte for byte.
fn append(builder: &mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>, source: &Path, name: &str) -> Result<(), String> {
    let mut file = std::fs::File::open(source).map_err(|error| format!("{}: {error}", source.display()))?;
    let size = file
        .metadata()
        .map_err(|error| format!("{}: {error}", source.display()))?
        .len();
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, format!("package/{name}"), &mut file)
        .map_err(|error| format!("{}: {error}", source.display()))?;
    Ok(())
}

/// The scheme and authority of a registry URL, or why it is not a shape the installing side could read.
///
/// The client reads the scheme and host and takes the protocol's paths from there (16 §4.2), so a URL with a path, a
/// non-http scheme or plain `http` for a public host is a mistake worth naming here rather than a surprise after publish.
fn registry_base(url: &str) -> Result<String, String> {
    let url = url.trim();
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    }
    else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    }
    else {
        return Err("it must start with https:// or http://".to_owned());
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err("it names no host".to_owned());
    }
    if rest.trim_end_matches('/') != authority {
        return Err("it must name only a scheme and a host, with no path".to_owned());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|character| character.is_ascii_digit()) => host,
        _ => authority,
    };
    let host = host.trim_matches(['[', ']']);
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
    if !secure && !loopback {
        return Err(
            "plain http is only for a local registry; a published package must travel over https".to_owned()
        );
    }
    Ok(format!("{}://{authority}", if secure { "https" } else { "http" }))
}

/// The base a static index's tarball URLs are built from.
///
/// Unlike a registry, a static host's path is where the bucket's files live, so it is kept. The rules that remain are the
/// ones the installing side enforces: a scheme, a host, and `http` only for a local bucket.
fn index_base(url: &str) -> Result<String, String> {
    let url = url.trim().trim_end_matches('/');
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    }
    else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    }
    else {
        return Err("it must start with https:// or http://".to_owned());
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err("it names no host".to_owned());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|character| character.is_ascii_digit()) => host,
        _ => authority,
    };
    let host = host.trim_matches(['[', ']']);
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
    if !secure && !loopback {
        return Err(
            "plain http is only for a local bucket; a published package must travel over https".to_owned()
        );
    }
    Ok(format!("{}://{rest}", if secure { "https" } else { "http" }))
}

/// Adds one version to a static index, keeping the versions it already lists.
///
/// # Errors
///
/// A sentence when the existing document is not JSON or is not the index shape. Overwriting a file this tool cannot read
/// would lose every version it did not write.
fn merge_index(
    existing: Option<&str>,
    name: &str,
    version: &str,
    tarball: &str,
    manifest: &serde_json::Value,
    publisher: Option<(&str, &str)>,
) -> Result<String, String> {
    let mut document = match existing {
        Some(text) => serde_json::from_str::<serde_json::Value>(text)
            .map_err(|error| format!("the index is not JSON: {error}"))?,
        None => serde_json::json!({ "name": name, "versions": [], "publishers": {} }),
    };
    let Some(object) = document.as_object_mut() else {
        return Err("the index is not a JSON object".to_owned());
    };
    object.insert("name".to_owned(), serde_json::json!(name));
    object.insert("latest".to_owned(), serde_json::json!(version));

    let mut publishers = object
        .remove("publishers")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    if let Some((id, fingerprint)) = publisher {
        publishers.insert(id.to_owned(), serde_json::json!(fingerprint));
    }
    object.insert("publishers".to_owned(), serde_json::Value::Object(publishers));

    let mut versions = object
        .remove("versions")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let entry = serde_json::json!({
        "version": version,
        "tarball": tarball,
        "manifest": manifest,
    });
    match versions
        .iter()
        .position(|listed| listed.get("version").and_then(serde_json::Value::as_str) == Some(version))
    {
        // Re-packing a version replaces its entry rather than listing it twice: the parser refuses duplicates, and a
        // second tarball for one version is not a history.
        Some(index) => {
            if let Some(slot) = versions.get_mut(index) {
                *slot = entry;
            }
        }
        None => versions.push(entry),
    }
    object.insert("versions".to_owned(), serde_json::Value::Array(versions));

    serde_json::to_string_pretty(&document).map_err(|error| format!("the index could not be written: {error}"))
}

/// The file names the manifest says a package contains.
///
/// Mirrors the installer's own list: the headless artifact and the UI bundle, each a plain file name. A name that is a
/// path is refused at install time, so packing it would produce an archive the installer rejects.
fn artifact_names(manifest: &Manifest) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(runtime) = &manifest.runtime.headless {
        names.push(runtime.artifact.clone());
    }
    if let Some(runtime) = &manifest.runtime.ui {
        names.push(runtime.artifact.clone());
    }
    names
}

#[cfg(test)]
mod tests {
    use super::{artifact_names, pack_plugin, write_archive};

    fn manifest(version: &str, capabilities: &[&str]) -> String {
        let declared: Vec<serde_json::Value> =
            capabilities.iter().map(|cap| serde_json::json!({ "cap": cap })).collect();
        serde_json::json!({
            "id": "@acme/hello",
            "version": version,
            "title": "Hello",
            "publisher": { "id": "acme" },
            "sdk": { "min": "1.0.0" },
            "wit": synra_plugin_host::host_world(),
            "capabilities": declared,
            "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
        })
        .to_string()
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("synra-pack-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a directory");
        path
    }

    #[test]
    fn a_packed_plugin_is_the_archive_the_installer_reads() {
        // ★ The property that matters is not "a file appeared": it is that `extract_tgz` — the code the registry install
        // runs — finds the three files at the depths it expects.
        let root = scratch("ok");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");
        sign(&root);

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("out.tgz")),
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let crate::run::Outcome::Archive { target, manifest, artifacts, signature, .. } = &outcome else {
            panic!("expected an archive outcome");
        };
        write_archive(target, manifest, artifacts, signature.as_deref()).expect("it writes");

        let destination = scratch("unpacked");
        let files = synra_registry::extract_tgz(
            &std::fs::read(target).expect("the archive"),
            &destination,
            Some("package"),
            synra_registry::Limits::default(),
        )
        .expect("the archive is what the installer reads");
        assert_eq!(files.len(), 3);
        assert!(destination.join("manifest.json").is_file());
        assert!(destination.join("plugin.wasm").is_file());
        assert!(destination.join("signature.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&destination);
    }

    #[test]
    fn packing_twice_produces_the_same_bytes() {
        // ★ A registry's digest is of the bytes it received. A pack that embedded the clock would make the same version
        // different on every machine, and every republish a new digest for unchanged content.
        let root = scratch("stable");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");

        let pack = |name: &str| {
            let target = root.join(name);
            let outcome = pack_plugin(&crate::args::PackArgs {
                dir: root.clone(),
                out: Some(target.clone()),
                index: None,
            registry: None,
            dry_run: false,
            })
            .expect("it packs");
            let crate::run::Outcome::Archive { manifest, artifacts, signature, .. } = &outcome else {
                panic!("expected an archive outcome");
            };
            write_archive(&target, manifest, artifacts, signature.as_deref()).expect("it writes");
            std::fs::read(target).expect("the archive")
        };
        assert_eq!(pack("one.tgz"), pack("two.tgz"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_artifact_is_named_rather_than_packed_around() {
        let root = scratch("missing");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"])).expect("a manifest");

        let crate::run::Outcome::Reported { lines, failure, .. } = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("a report") else {
            panic!("expected a report");
        };

        assert!(failure);
        assert!(lines.iter().any(|line| line.contains("plugin.wasm")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_archive_is_named_after_the_id_and_version() {
        let root = scratch("name");
        std::fs::write(root.join("manifest.json"), manifest("2.0.0", &[])).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let crate::run::Outcome::Archive { target, .. } = outcome else {
            panic!("expected an archive outcome");
        };
        assert_eq!(target.file_name().and_then(|name| name.to_str()), Some("@acme-hello-2.0.0.tgz"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_that_fails_verification_is_not_packed() {
        // ★ Pack runs the checks `verify` runs. An empty artifact is refused by both, and the failure is a report rather
        // than a second implementation of the rule.
        let root = scratch("broken");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"])).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), b"").expect("an empty artifact");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("the decision is a report, not an error");

        let crate::run::Outcome::Reported { lines, code, failure } = outcome else {
            panic!("expected a report");
        };
        assert_eq!(code, 1);
        assert!(failure);
        assert!(lines.iter().any(|line| line.contains("wasm")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_signature_that_covers_the_package_is_kept() {
        let root = scratch("signed");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");
        sign(&root);

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("out.tgz")),
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("a signed package packs");
        let crate::run::Outcome::Archive { signature, .. } = &outcome else {
            panic!("expected an archive outcome");
        };
        assert!(signature.is_some(), "the signature travels with the archive");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tampered_artifact_after_signing_is_refused() {
        // ★ The whole point of checking at the publish boundary: the author signed one build, then rebuilt — the archive
        // must not carry a signature that says "trust this" about bytes it does not cover.
        let root = scratch("tampered");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");
        sign(&root);
        std::fs::write(
            root.join("plugin.wasm"),
            [crate::test_component::component(), vec![0, 2, 1, b'x']].concat(),
        )
        .expect("a changed artifact");

        let crate::run::Outcome::Reported { lines, failure, .. } =
            pack_plugin(&crate::args::PackArgs {
                dir: root.clone(),
                out: None,
                index: None,
                registry: None,
                dry_run: false,
            })
            .expect("a report")
        else {
            panic!("expected a report");
        };

        assert!(failure);
        assert!(lines.iter().any(|line| line.contains("signature")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_changed_manifest_after_signing_is_refused() {
        let root = scratch("re-manifest");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");
        sign(&root);
        // Same files, one more permission: the manifest digest the signature covers no longer names this manifest.
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*", "device:send:*"]))
            .expect("a changed manifest");

        let crate::run::Outcome::Reported { failure, .. } = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("a report") else {
            panic!("expected a report");
        };

        assert!(failure);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Signs the package the way the `sign` command does, so the tests exercise the same document format.
    fn sign(root: &std::path::Path) {
        let key = crate::sign::SigningKeyFile::generate().expect("a key");
        let content = crate::sign::SignedContent::read(root).expect("what a signature covers");
        let document = key.sign(&content, "2026-01-01T00:00:00Z");
        std::fs::write(root.join("signature.json"), document).expect("a signature");
    }

    #[test]
    fn a_registry_flag_is_checked_and_shown_as_the_command_to_run() {
        // ★ Nothing is uploaded. The flag answers "is this a registry the installing side could read?" and turns the
        // answer into the command an author would run, so the address is stated once instead of retyped.
        let root = scratch("registry");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("out.tgz")),
            index: None,
            registry: Some("https://r.example".to_owned()),
            dry_run: false,
        })
        .expect("it packs");
        let crate::run::Outcome::Archive { lines, .. } = outcome else {
            panic!("expected an archive outcome");
        };

        assert!(
            lines.iter().any(|line| line.contains("npm publish --registry https://r.example")),
            "{lines:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_registry_that_could_not_be_read_is_refused() {
        let root = scratch("bad-registry");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");

        for (url, acceptable) in [
            ("https://r.example", true),
            ("https://r.example/", true),
            ("http://127.0.0.1:4873", true),
            ("http://r.example", false),
            ("ftp://r.example", false),
            ("https://r.example/path", false),
            ("https://", false),
        ] {
            let outcome = pack_plugin(&crate::args::PackArgs {
                dir: root.clone(),
                out: None,
                index: None,
            registry: Some(url.to_owned()),
                dry_run: true,
            })
            .expect("a decision");
            let accepted = matches!(&outcome, crate::run::Outcome::Archive { .. });
            assert_eq!(accepted, acceptable, "for {url}: {outcome:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_static_index_is_written_beside_the_archive() {
        // ★ The author's half of static publishing: one document per package, at the path a `static:` registry reads, with
        // the tarball URL and the key that signed it. A hand-edited index is a second description of the same pack.
        let root = scratch("index");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");
        sign(&root);

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("out.tgz")),
            index: Some("https://static.example.com/plugins".to_owned()),
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let executed = crate::execute::execute(&outcome, false);
        assert_eq!(executed.code, 0);

        let index_path = root.join("@acme").join("hello.json");
        assert!(index_path.is_file(), "the index is written at the id's path");
        let index = synra_registry::parse_static_index(
            &std::fs::read_to_string(&index_path).expect("the index"),
        )
        .expect("the index parses");
        let latest = index.document.latest().expect("a latest");
        assert_eq!(latest.version, "1.2.3");
        assert_eq!(
            latest.dist.tarball,
            "https://static.example.com/plugins/out.tgz"
        );
        assert!(
            index.publishers.contains_key("acme"),
            "the index names the key that signed it"
        );
        assert_eq!(latest.synra.as_ref().expect("the manifest").title, "Hello");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unsigned_package_writes_an_index_with_no_publisher() {
        let root = scratch("index-unsigned");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("out.tgz")),
            index: Some("https://static.example.com/plugins".to_owned()),
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let _ = crate::execute::execute(&outcome, false);

        let index = synra_registry::parse_static_index(
            &std::fs::read_to_string(root.join("@acme").join("hello.json")).expect("the index"),
        )
        .expect("the index parses");
        assert!(index.publishers.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_version_is_added_to_the_index() {
        // ★ The index is the package's history. Re-packing 1.3.0 must not drop 1.2.0: an install that asks for the older
        // version still has to find it.
        let root = scratch("index-history");
        let pack = |version: &str, out: &str| {
            std::fs::write(root.join("manifest.json"), manifest(version, &["log:*"]))
                .expect("a manifest");
            std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
                .expect("an artifact");
            sign(&root);
            let outcome = pack_plugin(&crate::args::PackArgs {
                dir: root.clone(),
                out: Some(root.join(out)),
                index: Some("https://static.example.com/plugins".to_owned()),
                registry: None,
                dry_run: false,
            })
            .expect("it packs");
            let executed = crate::execute::execute(&outcome, false);
            assert_eq!(executed.code, 0);
        };
        pack("1.2.3", "one.tgz");
        pack("1.3.0", "two.tgz");

        let index = synra_registry::parse_static_index(
            &std::fs::read_to_string(root.join("@acme").join("hello.json")).expect("the index"),
        )
        .expect("the index parses");
        assert_eq!(index.document.versions.len(), 2);
        assert_eq!(index.document.latest().expect("a latest").version, "1.3.0");
        assert_eq!(
            index.document.at("1.2.3").expect("the old version").dist.tarball,
            "https://static.example.com/plugins/one.tgz"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn merging_replaces_a_version_rather_than_listing_it_twice() {
        let manifest_value: serde_json::Value =
            serde_json::from_str(&manifest("1.0.0", &["log:*"])).expect("a manifest document");
        let first = super::merge_index(
            None,
            "@acme/hello",
            "1.0.0",
            "https://static.example.com/one.tgz",
            &manifest_value,
            None,
        )
        .expect("an index");
        let second = super::merge_index(
            Some(&first),
            "@acme/hello",
            "1.0.0",
            "https://static.example.com/two.tgz",
            &manifest_value,
            None,
        )
        .expect("an index");

        let index = synra_registry::parse_static_index(&second).expect("it parses");
        assert_eq!(index.document.versions.len(), 1);
        assert_eq!(
            index.document.at("1.0.0").expect("the version").dist.tarball,
            "https://static.example.com/two.tgz"
        );
    }

    #[test]
    fn an_index_this_tool_cannot_read_is_not_overwritten() {
        let refused = super::merge_index(
            Some("not json"),
            "@acme/hello",
            "1.0.0",
            "https://static.example.com/one.tgz",
            &serde_json::json!({}),
            None,
        )
        .expect_err("it is not an index");
        assert!(refused.contains("not JSON"), "{refused}");
    }

    #[test]
    fn an_index_without_a_base_names_the_tarball_relatively() {
        // ★ The author does not know the bucket's public URL at pack time; the client resolves the name against the
        // index's own URL, so publishing is "upload these two files".
        let root = scratch("index-relative");
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("one.tgz")),
            index: Some(String::new()),
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let _ = crate::execute::execute(&outcome, false);

        let index = synra_registry::parse_static_index(
            &std::fs::read_to_string(root.join("@acme").join("hello.json")).expect("the index"),
        )
        .expect("the index parses");
        assert_eq!(
            index.document.latest().expect("a latest").dist.tarball,
            "one.tgz"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_artifact_list_is_the_manifests() {
        let manifest = synra_plugin_api::Manifest::from_json(&manifest("1.0.0", &[])).expect("a manifest");
        assert_eq!(artifact_names(&manifest), ["plugin.wasm"]);
    }
}
