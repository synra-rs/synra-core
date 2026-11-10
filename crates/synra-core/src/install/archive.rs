use std::path::{Path, PathBuf};

use synra_plugin_api::Manifest;

use super::*;

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

    let file = std::fs::File::create(archive).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", archive.display()))
    })?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut entries: Vec<PathBuf> = Vec::new();
    let mut pending = vec![source.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let read = std::fs::read_dir(&directory).map_err(|error| {
            InstallRefusal::new("archive", format!("{}: {error}", directory.display()))
        })?;
        for entry in read {
            let entry = entry.map_err(|error| {
                InstallRefusal::new("archive", format!("{}: {error}", directory.display()))
            })?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| {
                InstallRefusal::new("archive", format!("{}: {error}", path.display()))
            })?;
            if kind.is_dir() {
                // The unpacked UI is rebuilt from `ui.zip`; everything else is part of the package.
                if path.file_name().is_some_and(|name| name == "ui") && directory == source {
                    continue;
                }
                pending.push(path);
            } else if kind.is_file() {
                entries.push(path);
            }
        }
    }
    entries.sort();

    let mut total = 0u64;
    for path in entries {
        let bytes = std::fs::read(&path).map_err(|error| {
            InstallRefusal::new("archive", format!("{}: {error}", path.display()))
        })?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_PACKAGE_BYTES {
            return Err(InstallRefusal::new(
                "archive-limits",
                format!("the package is over the {MAX_PACKAGE_BYTES} bytes a package may be"),
            ));
        }
        let relative = path.strip_prefix(source).map_err(|error| {
            InstallRefusal::new("archive", format!("{}: {error}", path.display()))
        })?;
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
pub(crate) fn discard_unpacked(directory: &Path, written: &[PathBuf]) {
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

/// A portable relative artifact path that cannot shadow package metadata or the derived UI tree.
pub(crate) fn is_artifact_path(name: &str) -> bool {
    synra_plugin_ui::artifact::check_package_artifact_path(name).is_ok()
}

/// Remove owned install output: sandbox the derived UI removal, then remove only known files and empty parents.
pub(crate) fn discard(directory: &Path, files: &[(String, Vec<u8>)]) {
    // This is a directory created by this installer. Only the sandbox removes the
    // derived UI tree; artifact parent directories are removed only when empty.
    let _ = synra_store::remove_tree(directory, &synra_plugin_ui::artifact::bundle_dir(directory));
    for (name, _) in files {
        let path = directory.join(name);
        let _ = std::fs::remove_file(&path);
        let mut parent = path.parent();
        while let Some(path) =
            parent.filter(|path| *path != directory && path.starts_with(directory))
        {
            let _ = std::fs::remove_dir(path);
            parent = path.parent();
        }
    }
    let _ = std::fs::remove_dir(directory);
}
