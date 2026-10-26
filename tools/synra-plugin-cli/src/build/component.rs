//! Cargo artifact discovery and atomic component output; no WASI adapter is granted.

use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use super::Step;
use crate::verify::MAX_WASM_BYTES;

/// Encodes the SDK's core module and checks that the required plugin interfaces are exported.
///
/// # Errors
/// Returns the component encoder's diagnosis or names a missing contract interface.
pub fn encode(module: &[u8]) -> Result<Vec<u8>, String> {
    if u64::try_from(module.len()).unwrap_or(u64::MAX) > MAX_WASM_BYTES {
        return Err("the guest core module exceeds the component size limit".to_owned());
    }
    let bytes = wit_component::ComponentEncoder::default()
        .module(module)
        .map_err(|error| format!("the guest module is invalid: {error:#}"))?
        .validate(true)
        .encode()
        .map_err(|error| format!("component encoding failed: {error:#}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_WASM_BYTES {
        return Err("the encoded component exceeds the component size limit".to_owned());
    }
    crate::verify::component::inspect(&bytes)?;
    Ok(bytes)
}

/// Runs one Cargo step and publishes only the successfully encoded component.
///
/// # Errors
/// Fails on a compiler error, ambiguous artifact, invalid module, unsafe destination or output IO error.
pub fn build(root: &Path, step: &Step, destination: &Path) -> Result<(), String> {
    if destination.as_os_str().is_empty()
        || destination.is_absolute()
        || destination
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(
            "the component destination must be a relative file path without traversal".to_owned(),
        );
    }
    let output = Command::new(&step.program)
        .args(&step.args)
        .current_dir(root.join(&step.in_dir))
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("{} could not run: {error}", step.program))?;
    if !output.status.success() {
        return Err(format!("{} exited with {}", step.program, output.status));
    }
    let source = artifact(&output.stdout, &root.join("Cargo.toml"))?;
    let file =
        std::fs::File::open(&source).map_err(|error| format!("{}: {error}", source.display()))?;
    let mut module = Vec::new();
    file.take(MAX_WASM_BYTES + 1)
        .read_to_end(&mut module)
        .map_err(|error| format!("{}: {error}", source.display()))?;
    let component = encode(&module)?;
    let destination = root.join(destination);
    if std::fs::canonicalize(&destination).ok() == Some(source) {
        return Err("the component destination must differ from Cargo's core module".to_owned());
    }
    let parent = destination
        .parent()
        .ok_or("the component destination has no parent")?;
    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    staged
        .write_all(&component)
        .map_err(|error| error.to_string())?;
    staged
        .persist(&destination)
        .map_err(|error| format!("{}: {}", destination.display(), error.error))?;
    Ok(())
}

fn artifact(messages: &[u8], manifest: &Path) -> Result<PathBuf, String> {
    let manifest = std::fs::canonicalize(manifest).map_err(|error| error.to_string())?;
    let mut found = None;
    for message in serde_json::Deserializer::from_slice(messages).into_iter::<serde_json::Value>() {
        let message = message
            .map_err(|error| format!("Cargo did not return valid artifact metadata: {error}"))?;
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(path) = message
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if std::fs::canonicalize(path).ok().as_ref() != Some(&manifest) {
            continue;
        }
        let cdylib = message
            .get("target")
            .and_then(|target| target.get("crate_types"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|types| types.iter().any(|kind| kind == "cdylib"));
        if !cdylib {
            continue;
        }
        if let Some(files) = message
            .get("filenames")
            .and_then(serde_json::Value::as_array)
        {
            for path in files
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(PathBuf::from)
            {
                if path
                    .extension()
                    .is_some_and(|extension| extension == "wasm")
                {
                    let path = std::fs::canonicalize(path).map_err(|error| error.to_string())?;
                    if found.replace(path).is_some() {
                        return Err("Cargo produced multiple guest modules".to_owned());
                    }
                }
            }
        }
    }
    found.ok_or_else(|| {
        "Cargo produced no cdylib Wasm artifact for this plugin; set crate-type to cdylib"
            .to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_bytes_and_modules_without_plugin_exports_cannot_be_published() {
        assert!(encode(b"not wasm").is_err());
        let error = encode(b"\0asm\x01\0\0\0").unwrap_err();
        assert!(error.contains("component"), "{error}");
    }

    #[test]
    fn a_successful_cargo_exit_without_an_artifact_is_not_a_build() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        std::fs::write(&manifest, "").unwrap();
        assert!(artifact(br#"{"reason":"build-finished","success":true}"#, &manifest).is_err());
        assert!(artifact(b"not JSON", &manifest).is_err());
    }

    #[test]
    fn dependency_artifacts_cannot_be_mistaken_for_the_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let other = dir.path().join("Other.toml");
        let module = dir.path().join("dependency.wasm");
        for path in [&manifest, &other, &module] {
            std::fs::write(path, "").unwrap();
        }
        let message = serde_json::json!({
            "reason": "compiler-artifact", "manifest_path": other,
            "target": { "crate_types": ["cdylib"] }, "filenames": [module],
        });
        assert!(artifact(&serde_json::to_vec(&message).unwrap(), &manifest).is_err());
    }

    #[test]
    fn multiple_guest_modules_are_refused_instead_of_picking_one() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let first = dir.path().join("first.wasm");
        let second = dir.path().join("second.wasm");
        for path in [&manifest, &first, &second] {
            std::fs::write(path, "").unwrap();
        }
        let message = serde_json::json!({
            "reason": "compiler-artifact", "manifest_path": manifest,
            "target": { "crate_types": ["cdylib"] }, "filenames": [first, second],
        });
        let error = artifact(&serde_json::to_vec(&message).unwrap(), &manifest).unwrap_err();
        assert!(error.contains("multiple"), "{error}");
    }

    #[test]
    fn an_output_outside_the_project_is_refused_before_cargo_runs() {
        let step = Step {
            program: "must-not-run".to_owned(),
            args: Vec::new(),
            in_dir: PathBuf::new(),
            why: String::new(),
            component: None,
        };
        let error = build(Path::new("."), &step, Path::new("../outside.wasm")).unwrap_err();
        assert!(error.contains("relative file path"), "{error}");
    }
}
