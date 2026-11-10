use super::*;

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
