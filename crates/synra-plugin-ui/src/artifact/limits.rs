//! The size ceilings, the error vocabulary, and one file's record.

use serde::{Deserialize, Serialize};
/// The most files a UI artifact may hold.
///
/// Two thousand. A bundle of a real interface is dozens; the bound exists because the *listing* is what an expansion
/// attack exhausts, and a listing of a million entries is memory the kernel never agreed to hold.
pub const MAX_ARTIFACT_FILES: usize = 2_000;

/// The most bytes a UI artifact may hold in total.
///
/// Sixty-four mebibytes. Well beyond a hand-written interface and well inside what a user expects an application to
/// download. A bundle that is larger is one whose size the user was not told about.
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// The most bytes one file may be.
///
/// The same as the total, because the two bounds are about different attacks: a bundle of one enormous file is
/// caught by the total, and a bundle of many files is caught by the count. A per-file bound would be a third number
/// to keep in step with the other two.
pub const MAX_ARTIFACT_FILE_BYTES: u64 = MAX_ARTIFACT_BYTES;

/// Why an artifact is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactError {
    /// The bundle holds more files than the bound.
    #[error("the artifact holds {found} files, and the limit is {limit}")]
    TooManyFiles {
        /// How many it holds.
        found: usize,
        /// The bound.
        limit: usize,
    },

    /// The bundle is larger than the bound.
    #[error("the artifact is {found} bytes, and the limit is {limit}")]
    TooLarge {
        /// How large it is.
        found: u64,
        /// The bound.
        limit: u64,
    },

    /// Two entries name the same path.
    ///
    /// Refused rather than resolved: an archive with two entries under one name is one whose extraction order
    /// decides the contents, and nothing about it says which the author meant.
    #[error("the artifact lists {path:?} twice")]
    DuplicatePath {
        /// The repeated path.
        path: String,
    },

    /// A path is not a relative, plain path.
    #[error("{path:?} is not a usable path inside an artifact: {reason}")]
    BadPath {
        /// The path that was offered.
        path: String,
        /// Why it is not usable.
        reason: PathRefusal,
    },

    /// The entry document is not in the bundle.
    #[error("the entry document {entry:?} is not in the artifact")]
    MissingEntry {
        /// The entry that was declared.
        entry: String,
    },

    /// Nothing was listed.
    ///
    /// An artifact with no files has no interface, and a page that loads nothing is a blank window rather than an
    /// error a user can act on.
    #[error("the artifact holds no files")]
    Empty,
}

/// Why a path is not usable inside an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PathRefusal {
    /// It is empty.
    Empty,
    /// It starts at the root of the filesystem.
    Absolute,
    /// It contains a `..` component.
    Traversal,
    /// It contains a component that is a backslash, which is a separator on one platform and a filename character on
    /// the others.
    Backslash,
    /// It contains a null byte.
    NullByte,
    /// It contains a drive letter, as Windows spells one.
    DriveLetter,
    /// It is not valid UTF-8 after the fact, or holds a character a path may not.
    BadCharacter,
    /// It is longer than the bound.
    TooLong,
}

impl core::fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.explain())
    }
}

impl PathRefusal {
    /// A sentence for the author.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Empty => "the path is empty",
            Self::Absolute => "the path starts at the root, and an artifact's paths are relative",
            Self::Traversal => "the path contains `..`, which would leave the artifact",
            Self::Backslash => {
                "the path contains a backslash, which is a separator on one platform and part of a name on others"
            }
            Self::NullByte => "the path contains a null byte",
            Self::DriveLetter => "the path starts with a drive letter, which only means something on Windows",
            Self::BadCharacter => "the path contains a character a path may not",
            Self::TooLong => "the path is too long",
        }
    }
}

/// The longest a path inside an artifact may be.
///
/// Five hundred and twelve bytes, which is the shortest limit any filesystem the application runs on imposes. Longer
/// than that is a path that extracts on one machine and fails on another, and the failure appears as a plugin whose
/// interface is blank on one platform.
pub const MAX_ARTIFACT_PATH_LEN: usize = 512;

/// One file in an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactFile {
    /// Its path, relative to the artifact's root, with `/` as the separator.
    pub path: String,
    /// Its size in bytes.
    pub size: u64,
    /// The content type an interface should be told, if it can be inferred from the extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

impl ArtifactFile {
    /// Whether it is the entry document or a resource the entry needs.
    ///
    /// Derived from the extension rather than stored, because storing it would be a second place the answer lives —
    /// and the question the interface actually asks is "must this be loaded before the page can run", which the
    /// content type already answers.
    #[must_use]
    pub fn is_script(&self) -> bool {
        self.content_type
            .as_deref()
            .is_some_and(|kind| kind.contains("javascript") || kind.contains("ecmascript"))
    }

    /// Whether it is a stylesheet.
    #[must_use]
    pub fn is_style(&self) -> bool {
        self.content_type.as_deref().is_some_and(|kind| kind.contains("css"))
    }
}
