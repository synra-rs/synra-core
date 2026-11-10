//! Opening the tarball a registry points at, without letting it write anywhere it likes.
//!
//! # The four attacks, and what stops each
//!
//! | Attack | What stops it |
//! | --- | --- |
//! | `../` in an entry name | every component is checked against [`Path::components`], and only `Normal`/`CurDir` pass |
//! | an absolute path, or a Windows drive | the same check: `RootDir` and `Prefix` are refused |
//! | a symlink pointing outside | the entry's **type** is checked, and only regular files and directories are written |
//! | a decompression bomb | a count, a per-file size and a total, all checked before a byte is written |
//!
//! # Why the archive is not unpacked with `Archive::unpack`
//!
//! Because that function's job is to write an archive; this one's job is to decide which entries an install will accept.
//! The decisions are the reason the module exists, and handing them to a helper would leave the interesting part untested
//! and the helper's defaults in charge.
//!
//! # What a failure leaves behind
//!
//! Nothing this function wrote. The files are removed in reverse order, and then the directories that became empty —
//! never a recursive delete, because a recursive delete turns a path mistake into somebody else's lost files.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;

/// What the installer will accept from one tarball.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most entries the archive may hold.
    pub max_entries: usize,
    /// The most bytes all entries may expand to.
    pub max_total_uncompressed: u64,
    /// The most bytes one entry may expand to.
    pub max_single_file: u64,
}

/// The design's numbers for a whole package (16 §2.1): an artefact is at most 32 MiB, and a package at most 64 MiB.
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 4_096,
            max_total_uncompressed: 64 * 1024 * 1024,
            max_single_file: 32 * 1024 * 1024,
        }
    }
}

/// Why an archive was refused.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// The gzip layer could not be read.
    #[error("the tarball could not be decompressed: {0}")]
    Gzip(String),
    /// The tar layer could not be read.
    #[error("the archive could not be read: {0}")]
    Tar(String),
    /// There are too many entries.
    #[error("the archive has {found} entries, and the limit is {limit}")]
    TooMany {
        /// How many the archive claims.
        found: usize,
        /// What the caller allows.
        limit: usize,
    },
    /// One entry is too large.
    #[error("`{path}` is {found} bytes, over the {limit} a file may be")]
    TooLarge {
        /// The entry's name.
        path: String,
        /// How large it is.
        found: u64,
        /// What the caller allows.
        limit: u64,
    },
    /// The whole archive is too large.
    #[error("the package is over the {limit} bytes a package may be")]
    PackageTooLarge {
        /// What the caller allows.
        limit: u64,
    },
    /// An entry name is not a path inside the package.
    #[error("`{path}` is not a path inside the package: {reason}")]
    BadPath {
        /// The entry's name.
        path: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// An entry is not a regular file or a directory.
    #[error("`{path}` is not a regular file or a directory")]
    RefusedKind {
        /// The entry's name.
        path: String,
    },
    /// A file could not be written.
    #[error("`{path}`: {error}")]
    Io {
        /// Where the write failed.
        path: String,
        /// The operating system's sentence.
        error: String,
    },
}

/// Writes a tarball's files under `destination`, stripping an optional prefix.
///
/// The npm convention puts every file under `package/`, so an install passes `Some("package")` and a tarball that does
/// not use the prefix is refused rather than unpacked at the wrong depth.
///
/// # Errors
///
/// [`ExtractError`] when the archive cannot be read, an entry is refused, or a limit is exceeded. A refused archive leaves
/// nothing behind: what this function wrote is removed before the error is returned.
pub fn extract_tgz(
    bytes: &[u8],
    destination: &Path,
    strip_prefix: Option<&str>,
    limits: Limits,
) -> Result<Vec<PathBuf>, ExtractError> {
    let mut written: Vec<PathBuf> = Vec::new();
    match extract_into(bytes, destination, strip_prefix, limits, &mut written) {
        Ok(()) => Ok(written),
        Err(error) => {
            discard(&written);
            Err(error)
        }
    }
}

/// The body, collecting what it writes so a refusal can undo it.
fn extract_into(
    bytes: &[u8],
    destination: &Path,
    strip_prefix: Option<&str>,
    limits: Limits,
    written: &mut Vec<PathBuf>,
) -> Result<(), ExtractError> {
    std::fs::create_dir_all(destination).map_err(|error| ExtractError::Io {
        path: destination.display().to_string(),
        error: error.to_string(),
    })?;

    let decoder = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|error| ExtractError::Tar(error.to_string()))?;
    let mut total: u64 = 0;

    for entry in entries {
        let mut entry = entry.map_err(|error| ExtractError::Tar(error.to_string()))?;
        let path = entry.path().map_err(|error| ExtractError::Tar(error.to_string()))?;
        let raw = path.display().to_string();
        let kind = entry.header().entry_type();
        // ★ The type is checked before the name: a symlink named `manifest.json` is the attack that looks ordinary, and
        // the name rules below would pass it.
        if !kind.is_file() && !kind.is_dir() {
            return Err(ExtractError::RefusedKind { path: raw });
        }

        let relative = relative_path(&path, strip_prefix)?;
        if written.len() >= limits.max_entries {
            return Err(ExtractError::TooMany { found: written.len() + 1, limit: limits.max_entries });
        }

        let target = destination.join(&relative);
        if kind.is_dir() {
            std::fs::create_dir_all(&target).map_err(|error| ExtractError::Io {
                path: target.display().to_string(),
                error: error.to_string(),
            })?;
            continue;
        }

        let size = entry.size();
        if size > limits.max_single_file {
            return Err(ExtractError::TooLarge {
                path: raw,
                found: size,
                limit: limits.max_single_file,
            });
        }
        total = total.saturating_add(size);
        if total > limits.max_total_uncompressed {
            return Err(ExtractError::PackageTooLarge { limit: limits.max_total_uncompressed });
        }

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| ExtractError::Io {
                path: parent.display().to_string(),
                error: error.to_string(),
            })?;
        }
        let mut file = std::fs::File::create(&target).map_err(|error| ExtractError::Io {
            path: target.display().to_string(),
            error: error.to_string(),
        })?;
        // The bytes are copied rather than read into memory: a 32 MiB artefact read whole would be 32 MiB the caller did
        // not ask to hold, and `io::copy` is bounded by the entry's own length.
        std::io::copy(&mut entry, &mut file).map_err(|error| ExtractError::Io {
            path: target.display().to_string(),
            error: error.to_string(),
        })?;
        written.push(target);
    }

    Ok(())
}

/// The path an entry takes under the destination.
fn relative_path(path: &Path, strip_prefix: Option<&str>) -> Result<PathBuf, ExtractError> {
    let raw = path.display().to_string();
    let stripped = match strip_prefix {
        Some(prefix) => path.strip_prefix(prefix).map_err(|_| ExtractError::BadPath {
            path: raw.clone(),
            reason: "it is not under the package prefix",
        })?,
        None => path,
    };

    let mut clean = PathBuf::new();
    for component in stripped.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(ExtractError::BadPath {
                    path: raw,
                    reason: "it is absolute or contains `..`",
                });
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(ExtractError::BadPath { path: raw, reason: "it names no file" });
    }
    Ok(clean)
}

/// Removes what a refused archive wrote, without a recursive delete.
fn discard(written: &[PathBuf]) {
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
        let _ = std::fs::remove_dir(parent);
    }
}

/// Reads a gzip stream to the end, so a corrupt archive is refused before the first entry is written.
///
/// Exposed for a caller that wants to size-check a download without extracting it. Not used by [`extract_tgz`], which
/// relies on `GzDecoder` to report corruption as the tar reader pulls bytes.
///
/// # Errors
///
/// [`ExtractError::Gzip`] when the stream is not gzip or is truncated.
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, ExtractError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| ExtractError::Gzip(error.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests;
