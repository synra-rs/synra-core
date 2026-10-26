//! Bounded reads of the artifacts named by the manifest.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use synra_plugin_api::Manifest;

use super::component::{ComponentInfo, inspect};
use super::limits::{
    MAX_MANIFEST_BYTES, MAX_UI_BYTES, MAX_UI_ENTRIES, MAX_UI_FILES, MAX_WASM_BYTES,
};

/// Facts read from a plugin directory, preserving read and validation failures.
#[derive(Debug, Clone)]
pub struct Target {
    /// The bounded manifest text or its read failure.
    pub manifest_json: Result<String, String>,
    /// Validated actual component metadata or a named read/validation failure.
    pub wasm: Result<ComponentInfo, String>,
    /// UI file and byte totals, or a named traversal/entry failure.
    pub ui_bundle: Result<(usize, u64), String>,
}

impl Target {
    /// Reads the manifest and its declared artifacts without executing guest code.
    #[must_use]
    pub fn read(directory: &Path) -> Self {
        let manifest_json = read_file(directory, "manifest.json", MAX_MANIFEST_BYTES)
            .and_then(|bytes| String::from_utf8(bytes).map_err(|error| error.to_string()));
        let manifest = manifest_json
            .as_ref()
            .ok()
            .and_then(|text| Manifest::from_json(text).ok());
        let wasm = manifest
            .as_ref()
            .and_then(|manifest| manifest.runtime.headless.as_ref())
            .ok_or_else(|| "no headless component is declared in a readable manifest".to_owned())
            .and_then(|headless| read_file(directory, &headless.artifact, MAX_WASM_BYTES))
            .and_then(|bytes| inspect(&bytes));
        let ui_bundle = manifest
            .as_ref()
            .and_then(|manifest| manifest.runtime.ui.as_ref())
            .ok_or_else(|| "no UI bundle is declared in a readable manifest".to_owned())
            .and_then(|ui| {
                let bundle = contained(directory, &ui.artifact)?;
                let entry = contained(&bundle, &ui.entry)?;
                if !entry.is_file() {
                    return Err(format!("{} is not a UI entry file", entry.display()));
                }
                read_bundle(&bundle)
            });
        Self {
            manifest_json,
            wasm,
            ui_bundle,
        }
    }
}

fn contained(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!(
            "{relative:?} must be a relative artifact path without traversal"
        ));
    }
    let root =
        std::fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let resolved =
        std::fs::canonicalize(root.join(path)).map_err(|error| format!("{relative}: {error}"))?;
    if !resolved.starts_with(&root) || resolved == root {
        return Err(format!("{relative:?} resolves outside its artifact root"));
    }
    Ok(resolved)
}

fn read_file(root: &Path, relative: &str, limit: u64) -> Result<Vec<u8>, String> {
    let path = contained(root, relative)?;
    let kind = std::fs::metadata(&path).map_err(|error| format!("{relative}: {error}"))?;
    if !kind.is_file() {
        return Err(format!("{relative} is not a regular file"));
    }
    let file = std::fs::File::open(&path).map_err(|error| format!("{relative}: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{relative}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("{relative} is not a regular file"));
    }
    if metadata.len() > limit {
        return Err(format!(
            "{relative} is {} bytes, over the {limit}-byte limit",
            metadata.len()
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{relative}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("{relative} grew beyond the {limit}-byte limit"));
    }
    Ok(bytes)
}

fn read_bundle(directory: &Path) -> Result<(usize, u64), String> {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut entries = 0usize;
    let mut stack = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)
            .map_err(|error| format!("{}: {error}", current.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            entries = entries.saturating_add(1);
            if entries > MAX_UI_ENTRIES {
                return Err(format!("UI traversal exceeds {MAX_UI_ENTRIES} entries"));
            }
            let resolved =
                std::fs::canonicalize(entry.path()).map_err(|error| error.to_string())?;
            if !resolved.starts_with(directory) || resolved == directory {
                return Err(format!(
                    "{} resolves outside the UI bundle or forms a root cycle",
                    entry.path().display()
                ));
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                files = files.saturating_add(1);
                bytes = bytes
                    .saturating_add(entry.metadata().map_err(|error| error.to_string())?.len());
                if files > MAX_UI_FILES || bytes > MAX_UI_BYTES {
                    return Err(format!(
                        "UI bundle exceeds limits: {files} files and {bytes} bytes"
                    ));
                }
            } else {
                return Err(format!(
                    "{} is not a regular UI file or directory",
                    entry.path().display()
                ));
            }
        }
    }
    Ok((files, bytes))
}
