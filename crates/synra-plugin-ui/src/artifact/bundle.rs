//! The artifact and its index, and the lookups and validation they support.

use std::collections::HashMap;


use super::limits::{ArtifactError, ArtifactFile, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_FILES};
use super::limits::MAX_ARTIFACT_FILE_BYTES;
use super::serving::{check_path, content_type_for};

/// A UI artifact: its files and its entry document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiArtifact {
    /// Every file, keyed by its path.
    files: HashMap<String, ArtifactFile>,
    /// The document the WebView loads.
    entry: String,
    /// The page shown first, from the plugin's manifest.
    default_page: Option<String>,
    /// The total size, kept rather than summed on demand.
    total_bytes: u64,
}

/// The path a plugin's index is built from, before any validation.
///
/// A tuple rather than a struct at the API boundary, because the loader has a directory listing and this is what it
/// has to say about each entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiArtifactIndex {
    /// The entry document's path.
    pub entry: String,
    /// The page shown first, if the manifest named one.
    pub default_page: Option<String>,
    /// Every file, as `(path, size)`.
    pub files: Vec<(String, u64)>,
}

impl UiArtifact {
    /// Builds an artifact from a listing, checking every bound.
    ///
    /// # Errors
    ///
    /// The first [`ArtifactError`] that applies. All of the checks run before any of the map is built, so a refusal
    /// leaves nothing half-constructed.
    ///
    /// # Bounds first
    ///
    /// The count and the total are checked before the paths, because they are the checks that bound the work: a
    /// listing of a million entries should fail on its count rather than after a million path validations.
    pub fn build(index: UiArtifactIndex) -> Result<Self, ArtifactError> {
        if index.files.is_empty() {
            return Err(ArtifactError::Empty);
        }
        if index.files.len() > MAX_ARTIFACT_FILES {
            return Err(ArtifactError::TooManyFiles {
                found: index.files.len(),
                limit: MAX_ARTIFACT_FILES,
            });
        }

        // Saturating rather than `sum()`: a listing that declares a `u64::MAX` size would overflow and panic, and
        // this function is the one that is supposed to turn a hostile listing into an error. A saturated total is
        // above every bound, so the check below refuses it — which is the answer an overflow should produce.
        let total_bytes = index
            .files
            .iter()
            .fold(0u64, |total, (_, size)| total.saturating_add(*size));
        if total_bytes > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::TooLarge { found: total_bytes, limit: MAX_ARTIFACT_BYTES });
        }

        let mut files = HashMap::with_capacity(index.files.len());
        for (path, size) in &index.files {
            check_path(path)?;
            if size > &MAX_ARTIFACT_FILE_BYTES {
                return Err(ArtifactError::TooLarge { found: *size, limit: MAX_ARTIFACT_FILE_BYTES });
            }
            let file = ArtifactFile {
                path: path.clone(),
                size: *size,
                content_type: content_type_for(path).map(str::to_owned),
            };
            // A duplicate is refused rather than overwritten: an archive with two entries under one name is one whose
            // extraction order decides the contents, and nothing about it says which the author meant.
            if files.insert(path.clone(), file).is_some() {
                return Err(ArtifactError::DuplicatePath { path: path.clone() });
            }
        }

        check_path(&index.entry)?;
        if !files.contains_key(&index.entry) {
            return Err(ArtifactError::MissingEntry { entry: index.entry });
        }

        Ok(Self {
            files,
            entry: index.entry,
            default_page: index.default_page,
            total_bytes,
        })
    }

    /// The document the WebView loads.
    #[must_use]
    pub fn entry(&self) -> &str {
        &self.entry
    }

    /// The page shown first, if the manifest named one.
    #[must_use]
    pub fn default_page(&self) -> Option<&str> {
        self.default_page.as_deref()
    }

    /// How many files it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether it holds nothing.
    ///
    /// Always `false`, because [`Self::build`] refuses an empty listing — and stated so a caller does not have to
    /// reason about whether it can be.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The total size.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Every file, sorted by path so a listing is stable.
    #[must_use]
    pub fn files(&self) -> Vec<&ArtifactFile> {
        let mut files: Vec<&ArtifactFile> = self.files.values().collect();
        files.sort_by(|first, second| first.path.cmp(&second.path));
        files
    }

    /// One file, by path.
    ///
    /// # The path is looked up rather than resolved
    ///
    /// A request that does not name a file the index holds is refused, which is what makes traversal impossible by
    /// construction: there is no path arithmetic to get wrong, because a path either is a key or is not.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&ArtifactFile> {
        self.files.get(path)
    }

    /// Whether a request for a path may be served.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::BadPath`] when the path is not one an artifact may contain, and
    /// [`ArtifactError::MissingEntry`] when it names nothing the index holds.
    ///
    /// # The two failures are different
    ///
    /// A malformed path is the plugin's own code asking for something it should not, and it is worth an error a
    /// developer sees. A well-formed path that names nothing is a 404 in the ordinary sense — a stale reference after
    /// a rebuild — and the caller's response is to show the interface's own not-found behaviour.
    pub fn resolve(&self, path: &str) -> Result<&ArtifactFile, ArtifactError> {
        check_path(path)?;
        self.files
            .get(path)
            .ok_or_else(|| ArtifactError::MissingEntry { entry: path.to_owned() })
    }

    /// How many scripts the entry needs, for a diagnostic report.
    #[must_use]
    pub fn script_count(&self) -> usize {
        self.files.values().filter(|file| file.is_script()).count()
    }
}
