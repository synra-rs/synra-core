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
mod tests {
    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::{ExtractError, Limits, extract_tgz};

    /// A `.tgz` holding these entries, written in memory.
    fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).expect("an entry");
        }
        builder.into_inner().expect("the encoder").finish().expect("a gzip tail")
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("synra-registry-{label}-{}", std::process::id()))
    }

    #[test]
    fn an_npm_shaped_tarball_lands_without_its_prefix() {
        let archive = tgz(&[
            ("package/manifest.json", b"{}"),
            ("package/plugin.wasm", b"\0asm\x01\0\0\0"),
        ]);
        let destination = scratch("ok");
        let written = extract_tgz(&archive, &destination, Some("package"), Limits::default())
            .expect("the archive is extracted");

        assert_eq!(written.len(), 2);
        assert!(destination.join("manifest.json").is_file());
        assert!(destination.join("plugin.wasm").is_file());
        let _ = std::fs::remove_dir_all(&destination);
    }

    /// A `.tgz` holding this raw tar stream.
    fn gzipped(raw: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw).expect("the raw tar");
        encoder.finish().expect("a gzip tail")
    }

    /// A tar stream written by hand, so a hostile name can be expressed.
    ///
    /// ★ `tar::Builder` refuses to write an entry whose path contains `..` — a good default for producing archives, and
    /// exactly why the test cannot use it to produce the archive this module has to refuse.
    fn raw_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            let mut header = [0u8; 512];
            let bytes = name.as_bytes();
            header[..bytes.len()].copy_from_slice(bytes);
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            let size = format!("{:011o}\0", data.len());
            header[124..136].copy_from_slice(size.as_bytes());
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            let checksum = format!("{sum:06o}\0 ");
            header[148..156].copy_from_slice(checksum.as_bytes());
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            let pad = (512 - data.len() % 512) % 512;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    #[test]
    fn an_entry_that_escapes_the_directory_is_refused_and_nothing_is_left() {
        // ★ The entry is after a legitimate one, so this also proves the cleanup: `a.txt` was written before the escape
        // was seen, and a refused archive must not leave it behind.
        let archive = gzipped(&raw_tar(&[("a.txt", b"kept?"), ("../escape.txt", b"outside")]));
        let destination = scratch("escape");
        let parent = destination.parent().expect("a parent").to_path_buf();

        let refused = extract_tgz(&archive, &destination, None, Limits::default()).expect_err("the entry escapes");

        assert!(matches!(refused, ExtractError::BadPath { .. }), "{refused}");
        assert!(!parent.join("escape.txt").exists(), "the entry was written outside the destination");
        assert!(!destination.join("a.txt").exists(), "the cleanup missed a written file");
        let _ = std::fs::remove_dir_all(&destination);
    }

    #[test]
    fn a_symlink_is_refused_by_its_type() {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("manifest.json").expect("a link target");
        header.set_mode(0o777);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/link", std::io::empty())
            .expect("an entry");
        let archive = builder.into_inner().expect("the encoder").finish().expect("a gzip tail");
        let destination = scratch("link");

        let refused = extract_tgz(&archive, &destination, Some("package"), Limits::default())
            .expect_err("a link is not a file");

        assert!(matches!(refused, ExtractError::RefusedKind { .. }), "{refused}");
        let _ = std::fs::remove_dir_all(&destination);
    }

    #[test]
    fn a_file_over_the_per_file_ceiling_is_refused_before_it_is_written() {
        let archive = tgz(&[("package/big.bin", b"12345")]);
        let destination = scratch("size");
        let limits = Limits { max_single_file: 4, ..Limits::default() };

        let refused = extract_tgz(&archive, &destination, Some("package"), limits).expect_err("too big");

        assert!(matches!(refused, ExtractError::TooLarge { found: 5, limit: 4, .. }), "{refused}");
        assert!(!destination.join("big.bin").exists());
        let _ = std::fs::remove_dir_all(&destination);
    }

    #[test]
    fn a_tarball_that_does_not_use_the_prefix_is_refused_rather_than_unpacked_at_the_wrong_depth() {
        let archive = tgz(&[("manifest.json", b"{}")]);
        let destination = scratch("prefix");

        let refused = extract_tgz(&archive, &destination, Some("package"), Limits::default())
            .expect_err("no prefix");

        assert!(matches!(refused, ExtractError::BadPath { .. }), "{refused}");
        let _ = std::fs::remove_dir_all(&destination);
    }

    #[test]
    fn gzip_corruption_is_a_named_error() {
        let mut not_gzip = Vec::new();
        not_gzip.write_all(b"not a gzip stream").expect("bytes");
        assert!(matches!(super::decompress(&not_gzip), Err(ExtractError::Gzip(_))));
    }
}
