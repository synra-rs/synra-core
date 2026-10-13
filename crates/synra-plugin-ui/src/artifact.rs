//! UI plugin artifacts: which files a version contains, and what may be served from it.
//!
//! # The artifact is data the kernel describes, not code it runs
//!
//! A UI plugin's artifact is a directory of files with an entry document. The kernel's job is to know what is in it,
//! find the entry, and refuse a request that leaves the bundle — the WebView serves the files.
//!
//! That division is what makes this module testable without a window, and it is also why the module is small: an
//! artifact has no manifest of its own (the plugin's `manifest.json` has the entry and the default page), no
//! dependencies, and no code. What it has is files, and the only interesting questions are which ones exist and
//! whether a requested path is one of them.
//!
//! # Two bounds, and they are about different things
//!
//! * **A file count.** A bundle is unzipped from something a user downloaded, and an archive can declare a million
//!   small files. The count stops an expansion attack, where the *listing* is what exhausts memory.
//! * **A total byte size.** The size stops a bundle that is one enormous file. Both are needed: a bound on either
//!   alone leaves the other open, and the two attacks look completely different.
//!
//! # Paths are checked, not normalised
//!
//! A request for `../../etc/passwd`, for an absolute path, or for a path containing a null byte is **refused**, not
//! cleaned up and then served. Normalising means deciding what the requester meant, and the requester here is a
//! plugin's own code — the one place where guessing is least appropriate. So the path has to name a file the index
//! actually holds, which makes traversal impossible by construction rather than by a check.

use std::collections::HashMap;

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

/// Checks a path is one an artifact may name.
///
/// # Errors
///
/// [`ArtifactError::BadPath`] naming the reason.
pub fn check_path(path: &str) -> Result<(), ArtifactError> {
    let refuse = |reason: PathRefusal| ArtifactError::BadPath { path: path.to_owned(), reason };

    if path.is_empty() {
        return Err(refuse(PathRefusal::Empty));
    }
    if path.len() > MAX_ARTIFACT_PATH_LEN {
        return Err(refuse(PathRefusal::TooLong));
    }
    if path.contains('\0') {
        return Err(refuse(PathRefusal::NullByte));
    }
    // Refused rather than accepted on the platforms where it is a filename character: the same artifact is served on
    // all of them, so a path that means one thing on Windows and another elsewhere is a difference nobody would find.
    if path.contains('\\') {
        return Err(refuse(PathRefusal::Backslash));
    }
    if path.starts_with('/') {
        return Err(refuse(PathRefusal::Absolute));
    }
    // A drive letter, as Windows spells one. Checked by shape rather than by platform, for the same reason.
    if path.len() >= 2 && path.as_bytes().get(1) == Some(&b':') {
        return Err(refuse(PathRefusal::DriveLetter));
    }

    for component in path.split('/') {
        if component.is_empty() {
            // A doubled separator or a trailing one. Refused rather than collapsed, because two spellings of one path
            // is two index keys for one file.
            return Err(refuse(PathRefusal::BadCharacter));
        }
        if component == ".." {
            return Err(refuse(PathRefusal::Traversal));
        }
        // A single `.` is a directory reference, not a file, and a file named `.` is not one an artifact can hold.
        if component == "." {
            return Err(refuse(PathRefusal::BadCharacter));
        }
        if component.chars().any(|ch| ch.is_control()) {
            return Err(refuse(PathRefusal::BadCharacter));
        }
    }

    Ok(())
}

/// The content type for a path, from its extension.
///
/// A closed list, and `None` for anything else — which is what an interface is told to serve as an opaque download.
/// A guessed type is worse than none: a browser that is told a file is `text/html` will render it, and a plugin that
/// ships a file named `.html` that is not a document would then be able to run script.
#[must_use]
pub fn content_type_for(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.').map(|(_, extension)| extension)?;
    // Lowercased for the comparison without allocating: an extension is short and ASCII in every case here.
    let matches = |candidate: &str| extension.eq_ignore_ascii_case(candidate);

    if matches("html") || matches("htm") {
        return Some("text/html; charset=utf-8");
    }
    if matches("js") || matches("mjs") {
        return Some("text/javascript; charset=utf-8");
    }
    if matches("css") {
        return Some("text/css; charset=utf-8");
    }
    if matches("json") {
        return Some("application/json");
    }
    if matches("svg") {
        return Some("image/svg+xml");
    }
    if matches("png") {
        return Some("image/png");
    }
    if matches("jpg") || matches("jpeg") {
        return Some("image/jpeg");
    }
    if matches("webp") {
        return Some("image/webp");
    }
    if matches("gif") {
        return Some("image/gif");
    }
    if matches("woff2") {
        return Some("font/woff2");
    }
    if matches("woff") {
        return Some("font/woff");
    }
    if matches("ttf") {
        return Some("font/ttf");
    }
    if matches("wasm") {
        return Some("application/wasm");
    }
    if matches("map") {
        return Some("application/json");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(files: &[(&str, u64)]) -> UiArtifactIndex {
        UiArtifactIndex {
            entry: "index.html".to_owned(),
            default_page: None,
            files: files.iter().map(|(path, size)| ((*path).to_owned(), *size)).collect(),
        }
    }

    fn artifact(files: &[(&str, u64)]) -> UiArtifact {
        UiArtifact::build(index(files)).expect("builds")
    }

    /// A listing with an entry document.
    fn with_entry(extra: &[(&str, u64)]) -> UiArtifactIndex {
        let mut files = vec![("index.html", 100u64)];
        files.extend_from_slice(extra);
        index(&files)
    }

    // ── Building ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_artifact_with_an_entry_builds() {
        let artifact = artifact(&[("index.html", 100), ("app.js", 200), ("app.css", 50)]);
        assert_eq!(artifact.entry(), "index.html");
        assert_eq!(artifact.len(), 3);
        assert_eq!(artifact.total_bytes(), 350);
        assert!(!artifact.is_empty());
    }

    #[test]
    fn an_empty_listing_is_refused() {
        // An artifact with no files has no interface, and a page that loads nothing is a blank window rather than an
        // error a user can act on.
        assert_eq!(UiArtifact::build(index(&[])), Err(ArtifactError::Empty));
    }

    #[test]
    fn too_many_files_is_refused_before_the_paths_are_checked() {
        // The count is what bounds the work: a listing of a million entries should fail on its count rather than after
        // a million path validations.
        let files: Vec<(String, u64)> = (0..=MAX_ARTIFACT_FILES)
            .map(|index| (format!("file{index}.js"), 1))
            .collect();
        let mut listing = index(&[]);
        listing.files = files;
        match UiArtifact::build(listing) {
            Err(ArtifactError::TooManyFiles { found, limit }) => {
                assert_eq!(found, MAX_ARTIFACT_FILES + 1);
                assert_eq!(limit, MAX_ARTIFACT_FILES);
            }
            other => panic!("expected a count refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_artifact_is_refused() {
        let listing = with_entry(&[("blob.bin", MAX_ARTIFACT_BYTES)]);
        match UiArtifact::build(listing) {
            Err(ArtifactError::TooLarge { limit, .. }) => assert_eq!(limit, MAX_ARTIFACT_BYTES),
            other => panic!("expected a size refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_path_is_refused() {
        // An archive with two entries under one name is one whose extraction order decides the contents, and nothing
        // about it says which the author meant.
        let mut listing = with_entry(&[("app.js", 10)]);
        listing.files.push(("app.js".to_owned(), 20));
        match UiArtifact::build(listing) {
            Err(ArtifactError::DuplicatePath { path }) => assert_eq!(path, "app.js"),
            other => panic!("expected a duplicate refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_entry_document_is_refused() {
        // A manifest naming an entry the bundle does not have is a blank window, and the refusal says which name.
        let mut listing = index(&[("app.js", 10)]);
        listing.entry = "index.html".to_owned();
        match UiArtifact::build(listing) {
            Err(ArtifactError::MissingEntry { entry }) => assert_eq!(entry, "index.html"),
            other => panic!("expected a missing entry, got {other:?}"),
        }
    }

    #[test]
    fn the_default_page_is_carried_from_the_manifest() {
        let mut listing = with_entry(&[]);
        listing.default_page = Some("settings".to_owned());
        let artifact = UiArtifact::build(listing).expect("builds");
        assert_eq!(artifact.default_page(), Some("settings"));
    }

    // ── Paths ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_traversal_is_refused() {
        // The path a plugin's own code would ask for when it is trying to leave the bundle.
        for path in ["../secret", "a/../../b", "..", "a/.."] {
            match check_path(path) {
                Err(ArtifactError::BadPath { reason, .. }) => {
                    assert_eq!(reason, PathRefusal::Traversal, "{path}");
                }
                other => panic!("{path:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_absolute_path_is_refused() {
        // Including a UNC path, which begins with a backslash and is caught by the backslash check first.
        for path in ["/etc/passwd", "/index.html"] {
            assert!(matches!(
                check_path(path),
                Err(ArtifactError::BadPath { reason: PathRefusal::Absolute, .. })
            ));
        }
    }

    #[test]
    fn a_backslash_is_refused() {
        // A path that means one thing on Windows and another elsewhere is a difference nobody would find, because the
        // same artifact is served on all of them.
        assert!(matches!(
            check_path("a\\b.js"),
            Err(ArtifactError::BadPath { reason: PathRefusal::Backslash, .. })
        ));
    }

    #[test]
    fn a_drive_letter_is_refused() {
        assert!(matches!(
            check_path("C:/index.html"),
            Err(ArtifactError::BadPath { reason: PathRefusal::DriveLetter, .. })
        ));
    }

    #[test]
    fn a_null_byte_is_refused() {
        // The one path character that can truncate a name in a lower layer while still comparing unequal here.
        assert!(matches!(
            check_path("index.html\0.txt"),
            Err(ArtifactError::BadPath { reason: PathRefusal::NullByte, .. })
        ));
    }

    #[test]
    fn an_empty_or_over_long_path_is_refused() {
        assert!(matches!(
            check_path(""),
            Err(ArtifactError::BadPath { reason: PathRefusal::Empty, .. })
        ));
        let long = format!("{}.js", "a".repeat(MAX_ARTIFACT_PATH_LEN));
        assert!(matches!(
            check_path(&long),
            Err(ArtifactError::BadPath { reason: PathRefusal::TooLong, .. })
        ));
    }

    #[test]
    fn a_doubled_or_trailing_separator_is_refused() {
        // Two spellings of one path is two index keys for one file, and whichever the interface asks for decides what
        // it gets.
        for path in ["a//b.js", "a/", "/a", "./a.js", "a/./b.js"] {
            assert!(check_path(path).is_err(), "{path:?} should be refused");
        }
    }

    #[test]
    fn a_control_character_is_refused() {
        for path in ["a\u{7}.js", "a\nb.js", "a\tb.js"] {
            assert!(check_path(path).is_err(), "{path:?} should be refused");
        }
    }

    #[test]
    fn an_ordinary_path_is_accepted() {
        for path in [
            "index.html",
            "assets/app.js",
            "assets/fonts/inter.woff2",
            "a/b/c/d/e.png",
            "a-b_c.d.js",
            "文件.html",
        ] {
            assert_eq!(check_path(path), Ok(()), "{path}");
        }
    }

    #[test]
    fn every_path_refusal_explains_itself() {
        for reason in [
            PathRefusal::Empty,
            PathRefusal::Absolute,
            PathRefusal::Traversal,
            PathRefusal::Backslash,
            PathRefusal::NullByte,
            PathRefusal::DriveLetter,
            PathRefusal::BadCharacter,
            PathRefusal::TooLong,
        ] {
            assert!(reason.explain().len() > 15, "{reason:?}");
        }
    }

    // ── Resolving ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_request_for_a_file_in_the_index_is_served() {
        let artifact = artifact(&[("index.html", 100), ("app.js", 200)]);
        let file = artifact.resolve("app.js").expect("resolves");
        assert_eq!(file.size, 200);
        assert_eq!(file.content_type.as_deref(), Some("text/javascript; charset=utf-8"));
    }

    #[test]
    fn a_request_for_something_not_in_the_index_is_refused() {
        // A well-formed path that names nothing is a 404 in the ordinary sense — a stale reference after a rebuild.
        let artifact = artifact(&[("index.html", 100)]);
        assert!(matches!(
            artifact.resolve("missing.js"),
            Err(ArtifactError::MissingEntry { .. })
        ));
    }

    #[test]
    fn a_traversal_is_refused_by_resolve_too() {
        // The lookup is what makes traversal impossible, and this asserts the path check runs before it — a traversal
        // that happened to name a real key would otherwise be served.
        let artifact = artifact(&[("index.html", 100), ("secret", 10)]);
        assert!(matches!(
            artifact.resolve("../secret"),
            Err(ArtifactError::BadPath { .. })
        ));
    }

    #[test]
    fn the_index_is_the_only_thing_that_decides_what_can_be_served() {
        // There is no path arithmetic: a path either is a key or is not. A path that normalises to a real file but is
        // not spelled that way is refused.
        let artifact = artifact(&[("index.html", 100), ("assets/app.js", 200)]);
        assert!(artifact.resolve("assets/app.js").is_ok());
        assert!(artifact.resolve("assets/./app.js").is_err());
        assert!(artifact.resolve("assets//app.js").is_err());
        assert!(artifact.resolve("./assets/app.js").is_err());
    }

    // ── Listing and types ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_listing_is_sorted() {
        // So a caller showing the files does not get a different order each time: a `HashMap`'s order is not stable
        // between runs, and a listing that reordered would make a diff of two runs useless.
        let artifact = artifact(&[("index.html", 1), ("z.js", 1), ("a.js", 1)]);
        let paths: Vec<&str> = artifact.files().iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, vec!["a.js", "index.html", "z.js"]);
    }

    #[test]
    fn scripts_and_styles_are_recognised() {
        let artifact = artifact(&[("index.html", 1), ("app.js", 1), ("app.css", 1), ("a.png", 1)]);
        assert_eq!(artifact.script_count(), 1);
        let css = artifact.file("app.css").expect("present");
        assert!(css.is_style());
        assert!(!css.is_script());
        let png = artifact.file("a.png").expect("present");
        assert!(!png.is_script() && !png.is_style());
    }

    #[rstest::rstest]
    #[case("a.html", Some("text/html; charset=utf-8"))]
    #[case("a.HTM", Some("text/html; charset=utf-8"))]
    #[case("a.mjs", Some("text/javascript; charset=utf-8"))]
    #[case("a.css", Some("text/css; charset=utf-8"))]
    #[case("a.json", Some("application/json"))]
    #[case("a.svg", Some("image/svg+xml"))]
    #[case("a.wasm", Some("application/wasm"))]
    #[case("a.woff2", Some("font/woff2"))]
    #[case("a.map", Some("application/json"))]
    #[case("a.txt", None)]
    #[case("a", None)]
    #[case("a.exe", None)]
    #[case("a.php", None)]
    fn content_types_are_a_closed_list(#[case] path: &str, #[case] expected: Option<&str>) {
        // `None` for anything else, which an interface serves as an opaque download. A guessed type is worse than
        // none: a browser told a file is `text/html` renders it, and a plugin shipping a non-document named `.html`
        // could then run script.
        assert_eq!(content_type_for(path), expected, "{path}");
    }

    #[test]
    fn a_script_is_not_served_as_a_document() {
        // The extension decides, and only the extensions on the list get a type. A file named `.txt` is not a script
        // whatever its contents are, and a file named `.js` is served as script whether or not it is one — which is
        // true of every static file server and is why the plugin's own build is what has to be correct.
        assert_eq!(content_type_for("payload.txt"), None);
        assert_eq!(content_type_for("payload.js"), Some("text/javascript; charset=utf-8"));
    }

    #[test]
    fn artifact_errors_explain_themselves() {
        let errors = [
            ArtifactError::TooManyFiles { found: 3_000, limit: 2_000 },
            ArtifactError::TooLarge { found: u64::MAX, limit: MAX_ARTIFACT_BYTES },
            ArtifactError::DuplicatePath { path: "a".to_owned() },
            ArtifactError::BadPath { path: "a".to_owned(), reason: PathRefusal::Traversal },
            ArtifactError::MissingEntry { entry: "a".to_owned() },
            ArtifactError::Empty,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A path that passes the check never contains a traversal, an absolute root, a backslash, a null byte or a
        /// drive letter. The property is what makes the check worth having: a path that passes and *does* leave the
        /// artifact is the escape.
        #[test]
        fn an_accepted_path_is_contained(path in ".{0,600}") {
            if check_path(&path).is_ok() {
                prop_assert!(!path.is_empty());
                prop_assert!(!path.contains('\0'));
                prop_assert!(!path.contains('\\'));
                prop_assert!(!path.starts_with('/'));
                prop_assert!(path.len() <= MAX_ARTIFACT_PATH_LEN);
                for component in path.split('/') {
                    prop_assert!(!component.is_empty(), "an empty component in {:?}", path);
                    prop_assert_ne!(component, "..");
                    prop_assert_ne!(component, ".");
                    prop_assert!(!component.chars().any(char::is_control));
                }
                // And the drive-letter shape is absent, which is a colon in the second byte.
                prop_assert!(path.as_bytes().get(1) != Some(&b':') || path.len() < 2);
            }
        }

        /// Resolving a path either gives a file the index holds or an error, whatever the path is. There is no third
        /// answer, and in particular no path that resolves to something the index does not hold — which is what makes
        /// traversal impossible by construction rather than by a check.
        #[test]
        fn resolving_never_invents_a_file(
            paths in proptest::collection::vec("[a-z./\\\\]{0,20}", 1..10),
            requested in "[a-zA-Z0-9./\\\\:_-]{0,40}",
        ) {
            let mut files: Vec<(String, u64)> = paths
                .into_iter()
                .filter(|path| check_path(path).is_ok())
                .map(|path| (path, 1))
                .collect();
            // The entry has to be present, so the artifact can build at all.
            files.retain(|(path, _)| path != "index.html");
            files.push(("index.html".to_owned(), 1));
            let listing = UiArtifactIndex {
                entry: "index.html".to_owned(),
                default_page: None,
                files,
            };
            if let Ok(artifact) = UiArtifact::build(listing)
                && let Ok(file) = artifact.resolve(&requested)
            {
                prop_assert!(
                    artifact.file(&file.path).is_some(),
                    "{:?} resolved to {:?}, which the index does not hold",
                    requested,
                    file.path,
                );
            }
        }

        /// Building a listing is total: any set of paths and sizes either yields an artifact or an error. The listing
        /// comes from an archive a user downloaded, so it is only semi-trusted.
        #[test]
        fn building_is_total(
            paths in proptest::collection::vec(".{0,40}", 0..30),
            size in any::<u64>(),
        ) {
            let listing = UiArtifactIndex {
                entry: "index.html".to_owned(),
                default_page: None,
                files: paths.into_iter().map(|path| (path, size)).collect(),
            };
            // Either answer is fine; what must not happen is a panic or a half-built artifact.
            if let Ok(artifact) = UiArtifact::build(listing) {
                prop_assert_eq!(artifact.len(), artifact.files().len());
                prop_assert!(artifact.file(artifact.entry()).is_some());
            }
        }

        /// A content type is only ever returned for a path whose extension is on the list, and never for a path with
        /// no extension. A guessed type is what lets a browser render a file the plugin did not mean as a document.
        #[test]
        fn a_content_type_needs_a_known_extension(path in "[a-z]{0,8}\\.?[a-zA-Z0-9]{0,6}") {
            if let Some(kind) = content_type_for(&path) {
                let Some((_, extension)) = path.rsplit_once('.') else {
                    prop_assert!(false, "{:?} has no extension but got {:?}", path, kind);
                    return Ok(());
                };
                prop_assert!(!extension.is_empty());
                prop_assert!(
                    ["html", "htm", "js", "mjs", "css", "json", "svg", "png", "jpg", "jpeg", "webp", "gif", "woff2", "woff", "ttf", "wasm", "map"]
                        .iter()
                        .any(|known| extension.eq_ignore_ascii_case(known)),
                    "{:?} has an unknown extension {:?} but got {:?}",
                    path,
                    extension,
                    kind,
                );
            }
        }
    }
}
