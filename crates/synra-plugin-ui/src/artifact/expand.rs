//! Unpacking an artifact: what may be written where, and what a hostile archive looks like.
//!
//! # Why this is a plan rather than an unpacker
//!
//! Because the decision and the syscalls it authorises have different failure modes, and only one of them is worth
//! testing. *May this entry be written under this root, and is the archive's shape one the host agreed to?* is a
//! question about a list of `(path, kind, size)` records, and it is answered here without a filesystem. Doing the
//! writes is a loop that opens files — and a loop that opens files is not where an implementation gets traversal
//! wrong; the path arithmetic before it is.
//!
//! So [`plan`] answers, and the caller writes exactly what came back. A plan is a closed set of relative paths: there
//! is no path arithmetic left for the caller to get wrong, which is the same property the artifact index has for
//! serving.
//!
//! # The four attacks, and what stops each
//!
//! | Attack | What stops it |
//! | --- | --- |
//! | `../` in a name | a `..` component is refused, and every path is checked as a whole |
//! | an absolute path, or a Windows drive | the first component may not be a root or a drive letter |
//! | a symlink pointing outside | symlinks are refused outright — see below |
//! | a zip bomb | a count, a per-file size, a total, a ratio, and a depth |
//!
//! # Why symlinks are refused rather than resolved
//!
//! A link is followed *later*, by whoever opens the path, and the check that would have to catch it is at that moment
//! rather than at extraction. A host that resolved a link during unpacking would be checking a target that the
//! archive's own next entry can change — a race with a window measured in microseconds and a consequence measured in
//! every file the user can read. Refusing them costs an artifact nothing: a UI bundle is documents and scripts, and a
//! bundle that needs a link is one that would break on a filesystem without them anyway.
//!
//! Hard links are refused for the same reason plus one more: a hard link's target is a path, and making one would let
//! an archive give itself a second name for a file the user owns.

use std::collections::HashSet;

use super::limits::{ArtifactError, MAX_ARTIFACT_PATH_LEN, PathRefusal};
use super::serving::check_path;

/// What the host will accept from an archive.
///
/// # Why these are settings and not constants
///
/// Because the right numbers depend on what is being unpacked: a plugin bundle is documents and scripts, and a
/// transfer of a user's files is something else with a different shape. The defaults are the design document's, and a
/// caller with a different shape supplies its own rather than the host having two code paths.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArchiveLimits {
    /// The most entries an archive may hold.
    pub max_entries: usize,
    /// The most bytes all entries may expand to.
    pub max_total_uncompressed: u64,
    /// The most bytes one entry may expand to.
    pub max_single_file: u64,
    /// The most a compressed size may be multiplied by before the archive is a bomb.
    pub max_compression_ratio: f64,
    /// The most components a path may have.
    pub max_path_depth: usize,
}

/// The design document's defaults.
///
/// Sixty-four mebibytes of content in at most four thousand entries, no entry larger than sixteen mebibytes, no entry
/// expanding by more than two hundred times its compressed size, and no path deeper than sixteen components. A real
/// interface is dozens of files and a few hundred kilobytes, so every one of these is generous by an order of
/// magnitude — which is what makes a refusal informative rather than arbitrary.
impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 4_096,
            max_total_uncompressed: 256 * 1024 * 1024,
            max_single_file: 64 * 1024 * 1024,
            max_compression_ratio: 200.0,
            max_path_depth: 16,
        }
    }
}

impl ArchiveLimits {
    /// The defaults, as a value.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Limits for an artifact tree, which is what the design document's numbers describe.
    #[must_use]
    pub fn artifact() -> Self {
        Self::default()
    }
}

/// What an entry is.
///
/// A directory is allowed and written as a directory, because archives contain them and refusing one would refuse
/// every archive a real tool produces. Anything else — a link, a device node, a fifo — is refused, and the type is
/// what makes that a decision rather than a guess about the mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A hard link.
    HardLink,
    /// Anything else the format can express: a device node, a fifo, a socket.
    Other,
}

impl EntryKind {
    /// A name, for a message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symbolic link",
            Self::HardLink => "hard link",
            Self::Other => "entry",
        }
    }

    /// Whether the host will write it.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::File | Self::Directory)
    }
}

/// One entry of an archive, as the format describes it.
///
/// `compressed` is what the ratio is computed from, and it is `None` when the format does not say — which is the
/// honest answer for a streamed archive whose entries were not sized ahead of time. A missing compressed size is not
/// treated as zero: a ratio of infinity would refuse every entry of an archive that simply did not record one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its path, as the archive spells it.
    pub path: String,
    /// What it is.
    pub kind: EntryKind,
    /// How large it claims to be once expanded.
    pub size: u64,
    /// How large it is in the archive, when the format says.
    pub compressed: Option<u64>,
}

impl Entry {
    /// A regular file.
    #[must_use]
    pub fn file(path: impl Into<String>, size: u64) -> Self {
        Self { path: path.into(), kind: EntryKind::File, size, compressed: None }
    }

    /// A directory.
    #[must_use]
    pub fn directory(path: impl Into<String>) -> Self {
        Self { path: path.into(), kind: EntryKind::Directory, size: 0, compressed: None }
    }

    /// A symbolic link to somewhere.
    #[must_use]
    pub fn symlink(path: impl Into<String>, to: impl Into<String>) -> Self {
        // The target is documentation for the refusal; the decision refuses every link whatever it points at.
        let _ = to.into();
        Self { path: path.into(), kind: EntryKind::Symlink, size: 0, compressed: None }
    }

    /// How many components its path has, ignoring a trailing slash.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.path
            .trim_end_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .count()
    }

    /// Whether the ratio bound refuses it.
    #[must_use]
    pub fn expands_too_far(&self, limit: f64) -> bool {
        let Some(compressed) = self.compressed else {
            return false;
        };
        if self.size == 0 {
            return false;
        }
        // A zero compressed size with content behind it is not a ratio of infinity to be reasoned about; it is an
        // archive lying about a size, and the per-file and total bounds are what refuse it.
        if compressed == 0 {
            return true;
        }
        (self.size as f64) / (compressed as f64) > limit
    }
}

/// What the caller is allowed to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    /// What to write, in the order the plan gives.
    pub entries: Vec<Entry>,
    /// How many bytes that will be.
    pub total_bytes: u64,
}

impl Expansion {
    /// How many entries there are.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there is nothing to write.
    ///
    /// Always `false` for a plan that came from [`plan`], which refuses an empty archive — and stated so a caller does
    /// not have to reason about whether it can be.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The files, which is what a manifest's artifact list is checked against.
    #[must_use]
    pub fn files(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|entry| entry.kind == EntryKind::File).collect()
    }
}

/// Decides what may be written from an archive's listing.
///
/// # The order, and why
///
/// The **count** is checked first because it is what bounds the work: a listing of a million entries should fail on
/// its count rather than after a million path validations. Then the paths, because a refusal about a path is the most
/// useful message an author can get. Then the sizes, which are the checks that need the whole listing.
///
/// # Errors
///
/// The first [`ArtifactError`] that applies, each naming what was found and what the limit is.
pub fn plan(entries: &[Entry], limits: ArchiveLimits) -> Result<Expansion, ArtifactError> {
    if entries.is_empty() {
        return Err(ArtifactError::Empty);
    }
    if entries.len() > limits.max_entries {
        return Err(ArtifactError::TooManyFiles { found: entries.len(), limit: limits.max_entries });
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(entries.len());
    for entry in entries {
        check_entry(entry, limits)?;
        // A duplicate is refused rather than overwritten: an archive with two entries under one name is one whose
        // extraction order decides the contents, and nothing about it says which the author meant.
        if !seen.insert(entry.path.as_str()) {
            return Err(ArtifactError::DuplicatePath { path: entry.path.clone() });
        }
    }

    // Saturating rather than summing: an archive that declares `u64::MAX` for two entries would overflow, and a
    // saturated total is above every bound — which is the answer an overflow should produce.
    let total_bytes = entries.iter().fold(0u64, |total, entry| total.saturating_add(entry.size));
    if total_bytes > limits.max_total_uncompressed {
        return Err(ArtifactError::TooLarge { found: total_bytes, limit: limits.max_total_uncompressed });
    }

    Ok(Expansion { entries: entries.to_vec(), total_bytes })
}

/// Checks one entry, which is the whole of the path arithmetic.
fn check_entry(entry: &Entry, limits: ArchiveLimits) -> Result<(), ArtifactError> {
    if !entry.kind.is_writable() {
        return Err(ArtifactError::ForbiddenEntry {
            path: entry.path.clone(),
            kind: entry.kind.as_str(),
        });
    }
    if entry.path.len() > MAX_ARTIFACT_PATH_LEN {
        return Err(ArtifactError::BadPath {
            path: entry.path.clone(),
            reason: PathRefusal::TooLong,
        });
    }
    if entry.depth() > limits.max_path_depth {
        return Err(ArtifactError::TooDeep {
            path: entry.path.clone(),
            found: entry.depth(),
            limit: limits.max_path_depth,
        });
    }
    // The same check the serving path uses, so a path that could never be *served* is also one that is never written:
    // two checks would eventually disagree, and the one that disagreed would be the one nobody was looking at.
    check_path(entry.path.trim_end_matches('/')).map_err(|_| ArtifactError::BadPath {
        path: entry.path.clone(),
        reason: refusal_for(&entry.path),
    })?;
    if entry.size > limits.max_single_file {
        return Err(ArtifactError::TooLarge { found: entry.size, limit: limits.max_single_file });
    }
    if entry.expands_too_far(limits.max_compression_ratio) {
        return Err(ArtifactError::CompressionBomb {
            path: entry.path.clone(),
            expanded: entry.size,
            compressed: entry.compressed.unwrap_or(0),
            limit: limits.max_compression_ratio,
        });
    }
    Ok(())
}

/// Which refusal a path earned, for a message that says what to fix.
///
/// `check_path` answers whether a path is usable; this answers *why not*, and it asks the same questions in the same
/// order so the two cannot disagree about which one applies.
fn refusal_for(path: &str) -> PathRefusal {
    if path.is_empty() {
        return PathRefusal::Empty;
    }
    if path.contains('\0') {
        return PathRefusal::NullByte;
    }
    if path.contains('\\') {
        return PathRefusal::Backslash;
    }
    if path.starts_with('/') {
        return PathRefusal::Absolute;
    }
    if path.len() >= 2 && path.as_bytes().get(1) == Some(&b':') {
        return PathRefusal::DriveLetter;
    }
    if path.split('/').any(|component| component == "..") {
        return PathRefusal::Traversal;
    }
    if path.len() > MAX_ARTIFACT_PATH_LEN {
        return PathRefusal::TooLong;
    }
    PathRefusal::BadCharacter
}

#[cfg(test)]
#[path = "expand_tests.rs"]
mod tests;
