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

use super::{ArchiveLimits, ArtifactError, EntryKind};

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
/// **A refused archive leaves nothing behind**: the files written before the refusal are removed again, so a caller does not
/// have to guess which half of a bundle reached the disk. The caller still owns the destination directory — this removes the
/// files it wrote, not directories that were already there.
pub fn unpack(
    archive: &Path,
    dest: &Path,
    limits: ArchiveLimits,
) -> Result<Vec<PathBuf>, UnpackError> {
    let mut archive =
        super::archive::Archive::open(archive, limits, limits.max_total_uncompressed)?;
    let root_exists = match std::fs::symlink_metadata(dest) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || std::fs::read_dir(dest)?.next().is_some()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "unpack destination must be absent or an empty real directory",
                )
                .into());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut written = Vec::new();
    let mut directories = Vec::new();
    let result = (|| {
        if !root_exists {
            create_directories(dest, &mut directories)?;
        }
        write_all(&mut archive, dest, &mut written, &mut directories)
    })();
    if let Err(error) = result {
        for path in written.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
        for path in directories.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
        return Err(error);
    }
    Ok(written)
}

fn create_directories(path: &Path, made: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_directories(parent, made)?;
    }
    std::fs::create_dir(path)?;
    made.push(path.to_path_buf());
    Ok(())
}

fn write_all(
    archive: &mut super::archive::Archive<std::io::Cursor<Vec<u8>>>,
    dest: &Path,
    written: &mut Vec<PathBuf>,
    directories: &mut Vec<PathBuf>,
) -> Result<(), UnpackError> {
    for index in 0..archive.expansion.len() {
        let entry = archive
            .expansion
            .entries
            .get(index)
            .ok_or_else(|| std::io::Error::other("ZIP plan entry is missing"))?;
        let target = dest.join(&entry.path);
        if entry.kind == EntryKind::Directory {
            create_directories(&target, directories)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            create_directories(parent, directories)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        written.push(target);
        archive.copy(index, &mut file)?;
        file.flush()?;
    }
    Ok(())
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
        let path =
            std::env::temp_dir().join(format!("synra-ui-{label}-{}.zip", std::process::id()));
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
        let zip = archive(
            "unpack-list",
            &[("index.html", b"<p>"), ("assets/app.js", b"export {}")],
        );
        let dest = scratch("unpack-list-dest");

        let written = unpack(&zip, &dest, ArchiveLimits::artifact()).expect("it unpacks");

        assert_eq!(written.len(), 2);
        for path in &written {
            assert!(
                path.starts_with(&dest),
                "{} is inside the destination",
                path.display()
            );
            assert!(path.is_file(), "{} exists", path.display());
        }
    }

    #[test]
    fn a_bundle_is_written_out() {
        let zip = archive(
            "unpack-ok",
            &[
                ("index.html", b"<!doctype html>"),
                ("assets/app.js", b"export {}"),
            ],
        );
        let dest = scratch("unpack-ok-dest");

        let written = unpack(&zip, &dest, ArchiveLimits::artifact()).expect("it unpacks");

        assert_eq!(written.len(), 2);
        assert_eq!(
            std::fs::read(dest.join("index.html")).expect("the page"),
            b"<!doctype html>"
        );
        assert!(dest.join("assets/app.js").exists(), "and its resource");
    }

    #[test]
    fn an_entry_that_leaves_the_directory_is_refused() {
        // ★ The request that would overwrite the device's key. Nothing is written: `check_path` refuses the entry before the
        // join, so the destination stays as empty as it started.
        let zip = archive(
            "unpack-slip",
            &[("index.html", b"ok"), ("../identity.toml", b"stolen")],
        );
        let dest = scratch("unpack-slip-dest");

        let refused =
            unpack(&zip, &dest, ArchiveLimits::artifact()).expect_err("it must not unpack");

        assert!(
            matches!(
                refused,
                UnpackError::Artifact(ArtifactError::BadPath { .. })
            ),
            "got {refused:?}"
        );
        assert!(
            !dest
                .parent()
                .unwrap_or(&dest)
                .join("identity.toml")
                .exists(),
            "nothing escaped"
        );
    }

    #[test]
    fn a_refused_archive_leaves_nothing_behind() {
        // ★ The property the installer needs: a bundle that is refused halfway must not leave half of itself in staging. The
        // first entry is written before the second is refused, so this only passes if `unpack` undoes its own work.
        let zip = archive(
            "unpack-undo",
            &[
                ("index.html", b"written first"),
                ("../identity.toml", b"refused second"),
            ],
        );
        let dest = scratch("unpack-undo-dest");

        unpack(&zip, &dest, ArchiveLimits::artifact()).expect_err("it is refused");

        assert!(
            !dest.join("index.html").exists(),
            "the file written before the refusal is gone"
        );
    }

    #[test]
    fn a_bundle_over_its_file_limit_is_refused() {
        let zip = archive(
            "unpack-many",
            &[("a.js", b"1"), ("b.js", b"2"), ("c.js", b"3")],
        );
        let dest = scratch("unpack-many-dest");
        let mut limits = ArchiveLimits::artifact();
        limits.max_entries = 2;

        let refused = unpack(&zip, &dest, limits).expect_err("too many files");

        assert!(
            matches!(
                refused,
                UnpackError::Artifact(ArtifactError::TooManyFiles { .. })
            ),
            "got {refused:?}"
        );
    }
}
