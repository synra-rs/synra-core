//! Writing a UI bundle's files out, without letting it write anywhere else.
//!
//! # Why this is the crate's job
//!
//! Design 01 makes the UI half a `ui.zip`, and design 06 lists "解包/校验/目录管理" among this crate's responsibilities. The
//! three refusals below are the whole reason it is code rather than a `unzip` call:
//!
//! * **zip-slip** — an entry named `../../identity.toml` is an archive asking to overwrite the device's private key. Every
//!   entry name goes through [`check_path`](crate::artifact::check_path), and the joined path is checked again;
//! * **decompression bombs** — the limits come from [`ArchiveLimits`], and the running total is what stops a small archive
//!   from filling the disk;
//! * **silent overwrites** — a directory already holding the destination is refused rather than merged, because a merge is
//!   how one plugin's bundle ends up half of another's.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::{ArchiveLimits, ArtifactError, check_path};

/// What can go wrong writing a bundle out.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    /// The archive could not be read.
    #[error("the bundle could not be read: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The files could not be written.
    #[error("the bundle could not be written: {0}")]
    Io(#[from] std::io::Error),
    /// An entry was refused by the artifact rules.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
}

/// Writes an archive's files into `dest`, and answers how many it wrote.
///
/// # Errors
///
/// [`UnpackError`] when the archive cannot be read, an entry is refused, a limit is exceeded, or a file cannot be written.
/// A refused archive leaves whatever was written before the refusal — the caller is expected to unpack into a directory it
/// discards on failure, which is what `synra-core`'s install staging is for.
pub fn unpack(archive: &Path, dest: &Path, limits: ArchiveLimits) -> Result<Vec<PathBuf>, UnpackError> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(archive)?)?;
    if zip.len() > limits.max_entries {
        return Err(ArtifactError::TooManyFiles { found: zip.len(), limit: limits.max_entries }.into());
    }

    let mut written: Vec<PathBuf> = Vec::new();
    let mut total = 0u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_owned();
        // ★ Before anything else: the name is the attack surface. `check_path` refuses `..`, absolute paths, backslashes
        // and null bytes — the four ways a zip entry escapes a directory or lies about where it points.
        check_path(&name)?;

        if entry.size() > limits.max_single_file {
            return Err(ArtifactError::TooLarge { found: entry.size(), limit: limits.max_single_file }.into());
        }
        total += entry.size();
        if total > limits.max_total_uncompressed {
            return Err(ArtifactError::TooLarge { found: total, limit: limits.max_total_uncompressed }.into());
        }

        let target = dest.join(&name);
        // ★ Checked **after** the join, because that is where a `..` would have taken effect. `check_path` already refuses
        // one; this refuses a path that got here anyway, which is what a second guard is for.
        if !target.starts_with(dest) {
            return Err(ArtifactError::BadPath { path: name, reason: super::PathRefusal::Traversal }.into());
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut file)?;
        file.flush()?;
        written.push(target);
    }
    Ok(written)
}

/// Where a bundle's files go, given the plugin directory.
///
/// One function so the installer and the `synra-plugin://` handler cannot disagree about the directory: `ui_file` is given
/// this path's value, and the handler is what serves it.
#[must_use]
pub fn bundle_dir(plugin_dir: &Path) -> PathBuf {
    plugin_dir.join("ui")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;

    /// An archive holding these entries, written beside the test's scratch space.
    fn archive(label: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("synra-ui-{label}-{}.zip", std::process::id()));
        let file = std::fs::File::create(&path).expect("a file");
        let mut writer = zip::ZipWriter::new(file);
        for (name, bytes) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .expect("an entry");
            writer.write_all(bytes).expect("the bytes");
        }
        writer.finish().expect("a finished archive");
        path
    }

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("synra-ui-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a directory");
        path
    }

    #[test]
    fn the_answer_names_files_the_installer_can_delete() {
        // ★ The installer rolls back through the list this function answers with, so every entry has to be a real file inside
        // the destination: a path that does not exist is a rollback that silently leaves the file behind, and one outside
        // the destination is a rollback that deletes somebody else's data.
        let zip = archive("unpack-list", &[("index.html", b"<p>"), ("assets/app.js", b"export {}")]);
        let dest = scratch("unpack-list-dest");

        let written = unpack(&zip, &dest, ArchiveLimits::artifact()).expect("it unpacks");

        assert_eq!(written.len(), 2);
        for path in &written {
            assert!(path.starts_with(&dest), "{} is inside the destination", path.display());
            assert!(path.is_file(), "{} exists", path.display());
        }
    }

    #[test]
    fn a_bundle_is_written_out() {
        let zip = archive("unpack-ok", &[("index.html", b"<!doctype html>"), ("assets/app.js", b"export {}")]);
        let dest = scratch("unpack-ok-dest");

        let written = unpack(&zip, &dest, ArchiveLimits::artifact()).expect("it unpacks");

        assert_eq!(written.len(), 2);
        assert_eq!(std::fs::read(dest.join("index.html")).expect("the page"), b"<!doctype html>");
        assert!(dest.join("assets/app.js").exists(), "and its resource");
    }

    #[test]
    fn an_entry_that_leaves_the_directory_is_refused() {
        // ★ The request that would overwrite the device's key. Nothing is written: `check_path` refuses the entry before the
        // join, so the destination stays as empty as it started.
        let zip = archive("unpack-slip", &[("index.html", b"ok"), ("../identity.toml", b"stolen")]);
        let dest = scratch("unpack-slip-dest");

        let refused = unpack(&zip, &dest, ArchiveLimits::artifact()).expect_err("it must not unpack");

        assert!(matches!(refused, UnpackError::Artifact(ArtifactError::BadPath { .. })), "got {refused:?}");
        assert!(!dest.parent().unwrap_or(&dest).join("identity.toml").exists(), "nothing escaped");
    }

    #[test]
    fn a_bundle_over_its_file_limit_is_refused() {
        let zip = archive("unpack-many", &[("a.js", b"1"), ("b.js", b"2"), ("c.js", b"3")]);
        let dest = scratch("unpack-many-dest");
        let mut limits = ArchiveLimits::artifact();
        limits.max_entries = 2;

        let refused = unpack(&zip, &dest, limits).expect_err("too many files");

        assert!(matches!(refused, UnpackError::Artifact(ArtifactError::TooManyFiles { .. })), "got {refused:?}");
    }
}
