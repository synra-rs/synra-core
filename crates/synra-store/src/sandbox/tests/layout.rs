use crate::paths::PathError;
use super::super::{FILES, SUBDIRECTORIES};
use super::Fixture;

#[test]
fn ensuring_creates_both_subdirectories() {
    let fixture = Fixture::new();
    assert!(fixture.sandbox.root().is_dir());
    for name in SUBDIRECTORIES {
        assert!(
            fixture
                .sandbox
                .subdirectory(name)
                .expect("resolves")
                .is_dir(),
            "{name} was not created"
        );
    }
}

#[test]
fn the_root_is_canonicalised_so_a_linked_parent_still_works() {
    // A user who moved their data directory and linked it back would otherwise have every resolution fail,
    // because the configured path and the real one differ.
    let fixture = Fixture::new();
    assert!(fixture.sandbox.root().is_absolute());
    assert_eq!(
        fixture.sandbox.root(),
        std::fs::canonicalize(fixture.parent.join("synra-plugin+chat")).expect("canonical")
    );
}

#[test]
fn only_the_two_subdirectories_may_be_named() {
    let fixture = Fixture::new();
    assert!(fixture.sandbox.subdirectory("files").is_ok());
    assert!(fixture.sandbox.subdirectory("cache").is_ok());

    // Not a mistyped path: a directory that was never promised to the plugin.
    for name in ["", "..", "/", "keys", "files/../cache", "secrets"] {
        match fixture.sandbox.subdirectory(name) {
            Err(PathError::BadComponent { .. }) => {}
            other => panic!("{name:?} should not resolve, got {other:?}"),
        }
    }
}

#[test]
fn a_plain_relative_path_resolves_inside_its_subdirectory() {
    let fixture = Fixture::new();
    // The parent has to exist, because that is the part which is canonicalised and therefore the part that
    // carries the escape risk. A caller writing a file creates its directory first.
    std::fs::create_dir_all(fixture.sandbox.root().join(FILES).join("notes")).expect("creates");

    let resolved = fixture
        .sandbox
        .resolve(FILES, "notes/today.txt")
        .expect("resolves");

    let files = std::fs::canonicalize(fixture.sandbox.root().join(FILES)).expect("canonical");
    assert!(resolved.starts_with(&files), "{}", resolved.display());
    assert!(resolved.ends_with("today.txt"));
}

#[test]
fn a_path_at_the_top_of_a_subdirectory_resolves() {
    let fixture = Fixture::new();
    assert!(fixture.sandbox.resolve(FILES, "a.txt").is_ok());
    // An empty relative path names the directory, not a file, so it is refused rather than treated as "the
    // subdirectory itself" — which would make a write into it ambiguous.
    assert!(fixture.sandbox.resolve(FILES, "").is_err());
    assert!(fixture.sandbox.resolve(FILES, ".").is_err());
}
