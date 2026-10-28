//! Build a complete package in isolation, then replace the previous owned output.

use std::io::Read as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::BuildPlan;

const MARKER: &str = ".synra-build.json";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    project: String,
    plugin: String,
}

pub(crate) fn run(plan: &BuildPlan) -> Result<Vec<String>, String> {
    let root = std::fs::canonicalize(&plan.root).map_err(|error| error.to_string())?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".synra-build.lock"))
        .map_err(|error| error.to_string())?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| "another plugin build is already running".to_owned())?;
    let manifest = synra_plugin_api::Manifest::from_json(&plan.manifest_json)
        .map_err(|error| error.to_string())?;
    let owner = Owner {
        project: root.to_string_lossy().into_owned(),
        plugin: manifest.id.to_string(),
    };
    let output = root.join("dist");
    let backup = root.join(".synra-build-previous");
    recover(&root, &output, &backup, &owner)?;
    clear_staging(&root, &owner)?;
    if exists(&output)? {
        owned(&output, &owner)?;
    }
    let stage = tempfile::Builder::new()
        .prefix(".synra-build-")
        .tempdir_in(&root)
        .map_err(|error| error.to_string())?;
    std::fs::write(
        stage.path().join(MARKER),
        serde_json::to_vec(&owner).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    for step in &plan.steps {
        if let Some(destination) = &step.component {
            super::component::build(&root, stage.path(), step, destination)?;
        } else {
            let working = std::fs::canonicalize(root.join(&step.in_dir))
                .map_err(|error| error.to_string())?;
            if !working.starts_with(&root) {
                return Err("UI command directory escapes the project".to_owned());
            }
            let status = std::process::Command::new(&step.program)
                .args(&step.args)
                .current_dir(working)
                .status()
                .map_err(|error| format!("{} could not run: {error}", step.command_line()))?;
            if !status.success() {
                return Err(format!("{} exited with {status}", step.command_line()));
            }
        }
    }
    if let Some(ui) = manifest.runtime.ui.as_ref() {
        let source = plan.ui_source.as_ref().ok_or("UI source was not planned")?;
        let source = root.join(source);
        let resolved = std::fs::canonicalize(&source).map_err(|error| error.to_string())?;
        if !resolved.starts_with(&root) || resolved.starts_with(&output) || resolved == root {
            return Err("UI source escapes the project or overlaps package output".to_owned());
        }
        super::ui::pack(&source, &stage.path().join(&ui.artifact), &ui.entry)?;
    }
    if crate::verify::read_manifest(&root)? != plan.manifest_json {
        return Err("manifest changed during build; run build again".to_owned());
    }
    std::fs::write(stage.path().join("manifest.json"), &plan.manifest_json)
        .map_err(|error| error.to_string())?;
    let report = crate::verify::verify(&crate::verify::Target::read(stage.path()));
    if !report.is_ok() {
        return Err(report.lines().join("\n"));
    }
    std::fs::write(
        stage.path().join(MARKER),
        serde_json::to_vec(&owner).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    // Windows cannot atomically replace a nonempty directory. Keep the old generation
    // available for rollback until the complete new directory has been renamed.
    let previous = exists(&output)?;
    if previous {
        owned(&output, &owner)?;
    }
    if previous {
        std::fs::rename(&output, &backup).map_err(|error| error.to_string())?;
    }
    if let Err(error) = std::fs::rename(stage.path(), &output) {
        if previous {
            std::fs::rename(&backup, &output).map_err(|restore| {
                format!(
                    "publication failed: {error}; previous package remains at {}: {restore}",
                    backup.display()
                )
            })?;
        }
        return Err(error.to_string());
    }
    if previous {
        synra_store::remove_tree(&root, &backup)
            .map_err(|error| format!("package built; previous output cleanup failed: {error}"))?;
    }
    let mut lines = plan.outcome_lines();
    lines.push(format!("package {}", output.display()));
    Ok(lines)
}

fn owned(path: &Path, expected: &Owner) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("build output must be a real directory".to_owned());
    }
    if std::fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .next()
        .is_none()
    {
        return Ok(());
    }
    let marker = path.join(MARKER);
    if !std::fs::symlink_metadata(&marker)
        .map_err(|_| "refusing to replace an output directory not owned by this build".to_owned())?
        .is_file()
    {
        return Err("build ownership marker must be a regular file".to_owned());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(marker)
        .map_err(|error| error.to_string())?
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 16_384 {
        return Err("build ownership marker is oversized".to_owned());
    }
    let actual: Owner = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if actual != *expected {
        return Err("build output belongs to a different project or plugin".to_owned());
    }
    Ok(())
}

fn recover(root: &Path, output: &Path, backup: &Path, owner: &Owner) -> Result<(), String> {
    if !exists(backup)? {
        return Ok(());
    }
    owned(backup, owner)?;
    if exists(output)? {
        owned(output, owner)?;
        synra_store::remove_tree(root, backup).map_err(|error| error.to_string())?;
    } else {
        std::fs::rename(backup, output).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn exists(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn clear_staging(root: &Path, owner: &Owner) -> Result<(), String> {
    for entry in std::fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".synra-build-") || name == ".synra-build-previous" {
            continue;
        }
        let path = entry.path();
        // Lock is held: no cooperating live build owns another staging directory.
        // Unknown/nonmatching markers and symlinks remain untouched.
        if owned(&path, owner).is_ok() {
            synra_store::remove_tree(root, &path).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
