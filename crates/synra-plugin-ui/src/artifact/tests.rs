//! The UI artifact's tests.

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
