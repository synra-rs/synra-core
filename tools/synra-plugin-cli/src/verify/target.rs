//! Where the artifact to check comes from.

use std::path::Path;

/// What is on disk, as far as `verify` can tell.
///
/// A struct rather than a set of arguments, because the artifact's *kind* decides which checks apply: a UI bundle has
/// a file count and a Wasm artifact has imports, and running both sets against both would report findings about a file
/// that cannot exist.
#[derive(Debug, Clone)]
pub struct Target {
    /// The manifest, as text.
    pub manifest_json: Option<String>,
    /// The Wasm artifact, when there is one.
    pub wasm_bytes: Option<u64>,
    /// The imports the Wasm artifact names.
    pub wasm_imports: Vec<String>,
    /// The UI bundle, as `(file count, total bytes)`.
    pub ui_bundle: Option<(usize, u64)>,
}

impl Target {
    /// What `verify` found on disk, reading the paths a built plugin has.
    ///
    /// # Errors
    ///
    /// Never — a missing file is a finding rather than an error, because "there is no manifest here" is exactly the
    /// answer the author needs.
    #[must_use]
    pub fn read(directory: &Path) -> Self {
        let manifest_json = std::fs::read_to_string(directory.join("manifest.json")).ok();

        let wasm = directory.join("plugin.wasm");
        let wasm_bytes = std::fs::metadata(&wasm).ok().map(|meta| meta.len());
        // The imports are *not* read from the binary here: parsing a Wasm module needs a parser, and this crate's job
        // is the report. A caller that has one fills the field in; a caller that does not gets a warning that the
        // check could not run, which is honest rather than a pass it did not earn.
        let wasm_imports = Vec::new();

        let ui = read_bundle(&directory.join("ui"));

        Self { manifest_json, wasm_bytes, wasm_imports, ui_bundle: ui }
    }
}

/// Counts a UI bundle's files and bytes.
///
/// `None` when the directory does not exist, which is not a failure on its own: a headless plugin has no bundle.
fn read_bundle(directory: &Path) -> Option<(usize, u64)> {
    if !directory.is_dir() {
        return None;
    }
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(entry.path());
            }
            else if kind.is_file() {
                files = files.saturating_add(1);
                if let Ok(meta) = entry.metadata() {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }
    Some((files, bytes))
}
