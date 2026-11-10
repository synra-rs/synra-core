use std::path::Path;
use crate::paths::PathError;
use super::super::FILES;
use super::Fixture;

#[test]
fn an_absolute_path_is_refused() {
    // `Path::join` replaces rather than appends, so this would not be an error without the check: it would
    // be a read of `/etc/passwd`.
    let fixture = Fixture::new();
    // A path on the current platform that is rooted: `/etc/passwd` is absolute on Unix and merely
    // drive-relative on Windows, so the fixture is built rather than written out.
    let rooted = if cfg!(windows) {
        "C:\\Windows\\System32"
    } else {
        "/etc/passwd"
    };
    for path in [rooted, "\\\\server\\share"] {
        assert!(
            matches!(
                fixture.sandbox.resolve(FILES, path),
                Err(PathError::Absolute(_))
            ),
            "{path:?} should be refused"
        );
    }
}

#[test]
fn a_traversal_is_refused() {
    let fixture = Fixture::new();
    // `..` from `files/` reaches the sandbox root, and one more reaches the parent directory.
    for path in [
        "../cache",
        "../x",
        "../../x",
        "a/../../x",
        "a/../../../etc/passwd",
    ] {
        match fixture.sandbox.resolve(FILES, path) {
            Err(PathError::Escapes { .. }) | Err(PathError::Unresolvable { .. }) => {}
            other => panic!("{path:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn a_traversal_that_stays_inside_is_allowed() {
    // `files/a/../b.txt` is `files/b.txt`, which is inside. Refusing it would be an over-correction that
    // breaks plugins doing ordinary path arithmetic.
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.sandbox.root().join(FILES).join("a")).expect("creates");
    let resolved = fixture
        .sandbox
        .resolve(FILES, "a/../b.txt")
        .expect("resolves");

    let files = std::fs::canonicalize(fixture.sandbox.root().join(FILES)).expect("canonical");
    assert!(resolved.starts_with(&files), "{}", resolved.display());
    assert!(resolved.ends_with("b.txt"));
}

#[cfg(unix)]
#[test]
fn a_symlink_pointing_out_is_refused() {
    // The case that makes "count the `..`s" insufficient: a plugin can create a symlink inside its own
    // sandbox, and counting components cannot see where it points.
    let fixture = Fixture::new();
    let outside = fixture.parent.join("outside");
    std::fs::create_dir_all(&outside).expect("creates");
    std::fs::write(outside.join("secret.txt"), b"secret").expect("writes");

    let link = fixture.sandbox.root().join(FILES).join("escape");
    std::os::unix::fs::symlink(&outside, &link).expect("links");

    match fixture.sandbox.resolve(FILES, "escape/secret.txt") {
        Err(PathError::Escapes { .. }) => {}
        other => panic!("a symlink out of the sandbox should be refused, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_pointing_inside_is_allowed() {
    // A plugin laying out its own storage with links is ordinary use, and refusing it would be an
    // over-correction.
    let fixture = Fixture::new();
    let target = fixture.sandbox.root().join(FILES).join("real");
    std::fs::create_dir_all(&target).expect("creates");

    let link = fixture.sandbox.root().join(FILES).join("link");
    std::os::unix::fs::symlink(&target, &link).expect("links");

    assert!(fixture.sandbox.resolve(FILES, "link/x.txt").is_ok());
}

#[test]
fn a_missing_parent_is_unresolvable_rather_than_accepted() {
    // The file's parent has to be canonicalised, so it has to exist. Accepting a missing parent would mean
    // returning a path that was never checked against the sandbox.
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.sandbox.resolve(FILES, "no/such/directory/x.txt"),
        Err(PathError::Unresolvable { .. })
    ));
}

#[test]
fn a_resolved_path_is_always_inside_the_sandbox() {
    // The invariant a caller relies on, asserted over every shape a path can take.
    let fixture = Fixture::new();
    let candidates = [
        "a.txt",
        "a/b/c.txt",
        "a/../b.txt",
        "./a.txt",
        "a/./b.txt",
        "a//b.txt",
    ];
    for candidate in candidates {
        if let Ok(resolved) = fixture.sandbox.resolve(FILES, candidate) {
            assert!(
                fixture.sandbox.contains(&resolved),
                "{candidate:?} resolved outside the sandbox to {}",
                resolved.display()
            );
        }
    }
}

#[test]
fn containing_a_path_compares_against_the_root() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .sandbox
            .contains(&fixture.sandbox.root().join("files/x"))
    );
    assert!(fixture.sandbox.contains(fixture.sandbox.root()));
    // A sibling plugin's sandbox is not this one's, even sharing a prefix.
    assert!(
        !fixture
            .sandbox
            .contains(&fixture.parent.join("synra-plugin+notes/files/x"))
    );
    assert!(!fixture.sandbox.contains(Path::new("/etc")));
}
