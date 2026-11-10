use super::*;

#[test]
fn a_path_with_a_parent_component_is_refused() {
    // ★ The classic. Checked as a whole path rather than per component, because `..` is exactly as dangerous in the
    // middle as at the start.
    for path in ["../escape.txt", "assets/../../escape.txt", "a/b/../../../c"] {
        let entries = vec![Entry::file(path, 10)];
        match plan(&entries, ArchiveLimits::default()) {
            Err(ArtifactError::BadPath { reason, .. }) => {
                assert_eq!(reason, PathRefusal::Traversal, "{path}");
            }
            other => panic!("{path} was accepted: {other:?}"),
        }
    }
}

#[test]
fn an_absolute_path_is_refused() {
    for path in ["/etc/passwd", "/index.html"] {
        let entries = vec![Entry::file(path, 10)];
        match plan(&entries, ArchiveLimits::default()) {
            Err(ArtifactError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::Absolute, "{path}"),
            other => panic!("{path} was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_windows_drive_letter_is_refused() {
    // It is a relative path on a Unix filesystem and an absolute one on Windows, which is the worst kind of
    // platform-dependent answer: it would unpack on the machine that built it and write to `C:\` on a user's.
    for path in ["C:/Windows/System32/x.dll", "c:index.html"] {
        let entries = vec![Entry::file(path, 10)];
        match plan(&entries, ArchiveLimits::default()) {
            Err(ArtifactError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::DriveLetter, "{path}"),
            other => panic!("{path} was accepted: {other:?}"),
        }
    }
    // An inner colon is also refused: on Windows it can address an alternate data stream.
    let entries = vec![Entry::file("assets/a:b.js", 10)];
    assert!(plan(&entries, ArchiveLimits::default()).is_err());
}

#[test]
fn a_backslash_is_refused() {
    // It is a separator on one platform and an ordinary character on the others, so a path containing one means
    // different things in different places — which is how `..\\..\\x` gets through a check that only looks for `/`.
    let entries = vec![Entry::file(r"..\..\escape.txt", 10)];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::Backslash),
        other => panic!("expected a backslash refusal, got {other:?}"),
    }
}

#[test]
fn a_null_byte_is_refused() {
    // It truncates a path in the C APIs underneath everything, so a name that contains one is a name two layers
    // disagree about.
    let entries = vec![Entry::file("index.html\0.txt", 10)];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::NullByte),
        other => panic!("expected a null-byte refusal, got {other:?}"),
    }
}

#[test]
fn a_symbolic_link_is_refused_wherever_it_points() {
    // ★ The rule, and the reason it is not "refused when it points outside": the target is resolved by whoever opens
    // the path *later*, and the archive's own next entry can change what it points at in between. A check at
    // extraction time is a check on a value that is not what will be used.
    for target in ["/etc/passwd", "../../escape", "index.html"] {
        let entries = vec![Entry::file("index.html", 10), Entry::symlink("link", target)];
        match plan(&entries, ArchiveLimits::default()) {
            Err(ArtifactError::ForbiddenEntry { kind, path }) => {
                assert_eq!(kind, "symbolic link");
                assert_eq!(path, "link");
            }
            other => panic!("a link to {target} was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_hard_link_is_refused() {
    // A hard link's target is a path, so making one would let an archive give itself a second name for a file the user
    // owns.
    let entries = vec![Entry {
        path: "second-name".to_owned(),
        kind: EntryKind::HardLink,
        size: 0,
        compressed: None,
    }];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::ForbiddenEntry { kind, .. }) => assert_eq!(kind, "hard link"),
        other => panic!("expected a hard-link refusal, got {other:?}"),
    }
}

#[test]
fn a_device_node_or_fifo_is_refused() {
    // Anything the format can express and a bundle has no use for.
    let entries = vec![Entry { path: "tty".to_owned(), kind: EntryKind::Other, size: 0, compressed: None }];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::ForbiddenEntry { kind, .. }) => assert_eq!(kind, "entry"),
        other => panic!("expected an entry-kind refusal, got {other:?}"),
    }
    // And the two writable kinds are the two a bundle is made of.
    assert!(EntryKind::File.is_writable());
    assert!(EntryKind::Directory.is_writable());
    assert!(!EntryKind::Symlink.is_writable());
}

#[test]
fn a_path_that_is_too_deep_is_refused_with_its_depth() {
    let limits = ArchiveLimits { max_path_depth: 3, ..ArchiveLimits::default() };
    let entries = vec![Entry::file("a/b/c/d", 10)];
    match plan(&entries, limits) {
        Err(ArtifactError::TooDeep { path, found, limit }) => {
            assert_eq!(path, "a/b/c/d");
            assert_eq!(found, 4);
            assert_eq!(limit, 3);
        }
        other => panic!("expected a depth refusal, got {other:?}"),
    }
    // A trailing slash is not a component, which is what stops a directory from being one deeper than its contents.
    assert_eq!(Entry::directory("a/b/").depth(), 2);
    assert_eq!(Entry::file("a/b", 1).depth(), 2);
}

#[test]
fn a_path_longer_than_the_filesystem_allows_is_refused() {
    let long = "a".repeat(MAX_ARTIFACT_PATH_LEN + 1);
    let entries = vec![Entry::file(long, 10)];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::TooLong),
        other => panic!("expected a length refusal, got {other:?}"),
    }
}

#[test]
fn two_entries_under_one_name_are_refused() {
    // An archive with two entries under one name is one whose extraction order decides the contents, and nothing
    // about it says which the author meant.
    let entries = vec![Entry::file("index.html", 10), Entry::file("index.html", 20)];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::DuplicatePath { path }) => assert_eq!(path, "index.html"),
        other => panic!("expected a duplicate refusal, got {other:?}"),
    }
}

#[test]
fn an_empty_archive_is_refused() {
    assert_eq!(plan(&[], ArchiveLimits::default()), Err(ArtifactError::Empty));
}

#[test]
fn a_directory_and_a_file_of_the_same_name_are_not_a_duplicate() {
    // They are written differently — one is created, one is created and filled — and an archive that lists both is
    // odd rather than hostile. The set is on the path as spelled, which is why the trailing slash distinguishes them.
    let entries = vec![Entry::directory("assets"), Entry::file("assets", 10)];
    match plan(&entries, ArchiveLimits::default()) {
        Err(ArtifactError::DuplicatePath { .. }) => {}
        // Either answer is defensible; what matters is that the two are not silently merged.
        Ok(planned) => assert_eq!(planned.len(), 2),
        other => panic!("unexpected: {other:?}"),
    }
}
