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
    let signature = signature_path.is_file().then_some(signature_path);

    let target = args.out.clone().unwrap_or_else(|| {
        let file = format!("{}-{}.tgz", manifest.id.to_string().replace(['/', '\\'], "-"), manifest.version);
        dir.join("dist").join(file)
    });

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

    Ok(Outcome::Archive {
        target,
        manifest: dir.join("manifest.json"),
        artifacts,
        signature,
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
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"])).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");
        std::fs::write(root.join("signature.json"), "{}").expect("a signature");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join("out.tgz")),
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
        std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"])).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");

        let pack = |name: &str| {
            let target = root.join(name);
            let outcome = pack_plugin(&crate::args::PackArgs {
                dir: root.clone(),
                out: Some(target.clone()),
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

        let refused = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            dry_run: false,
        })
        .expect_err("the artifact is missing");

        assert!(refused.contains("plugin.wasm"), "{refused}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_archive_is_named_after_the_id_and_version() {
        let root = scratch("name");
        std::fs::write(root.join("manifest.json"), manifest("2.0.0", &[])).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");

        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
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
    fn the_artifact_list_is_the_manifests() {
        let manifest = synra_plugin_api::Manifest::from_json(&manifest("1.0.0", &[])).expect("a manifest");
        assert_eq!(artifact_names(&manifest), ["plugin.wasm"]);
    }
}
