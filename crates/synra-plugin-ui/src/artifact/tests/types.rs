use super::*;

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
