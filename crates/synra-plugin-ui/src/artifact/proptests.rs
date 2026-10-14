//! The UI artifact's property tests.

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
