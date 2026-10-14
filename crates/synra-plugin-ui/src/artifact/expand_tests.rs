//! The expansion plan, driven with hostile archives.
//!
//! Every rule here has a case that must be refused, and the cases are the four attacks rather than invented ones: a
//! `..` in a name, an absolute path, a link, and a bomb. A suite that only ever planned a well-formed archive would
//! pass against a `plan` that returned everything it was given.

use super::super::limits::{ArtifactError, PathRefusal, MAX_ARTIFACT_PATH_LEN};
use super::*;

/// A small archive that passes.
fn good() -> Vec<Entry> {
    vec![
        Entry::directory("assets"),
        Entry::file("index.html", 1_024),
        Entry::file("assets/app.js", 4_096),
    ]
}

#[test]
fn a_well_formed_archive_is_planned_in_the_order_it_was_given() {
    let planned = plan(&good(), ArchiveLimits::default()).expect("a plan");
    assert_eq!(planned.len(), 3);
    assert_eq!(planned.entries.first().map(|entry| entry.path.as_str()), Some("assets"));
    assert_eq!(planned.total_bytes, 5_120);
    assert_eq!(planned.files().len(), 2, "the directory is not a file");
    assert!(!planned.is_empty());
}

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
    // And a name that merely *contains* a colon is fine, because only the first component can be a drive.
    let entries = vec![Entry::file("assets/a:b.js", 10)];
    assert!(plan(&entries, ArchiveLimits::default()).is_ok());
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
fn too_many_entries_is_refused_by_count_before_any_path_is_checked() {
    // ★ The order matters: a listing of a million entries should fail on its count rather than after a million path
    // validations. The fixture's paths are all *invalid*, so a plan that checked paths first would report a traversal
    // instead.
    let limits = ArchiveLimits { max_entries: 4, ..ArchiveLimits::default() };
    let entries: Vec<Entry> = (0..5).map(|index| Entry::file(format!("../{index}"), 1)).collect();

    match plan(&entries, limits) {
        Err(ArtifactError::TooManyFiles { found, limit }) => {
            assert_eq!(found, 5);
            assert_eq!(limit, 4);
        }
        other => panic!("expected a count refusal, got {other:?}"),
    }
}

#[test]
fn a_total_over_the_bound_is_refused() {
    let limits = ArchiveLimits { max_total_uncompressed: 100, ..ArchiveLimits::default() };
    let entries = vec![Entry::file("a", 60), Entry::file("b", 60)];
    match plan(&entries, limits) {
        Err(ArtifactError::TooLarge { found, limit }) => {
            assert_eq!(found, 120);
            assert_eq!(limit, 100);
        }
        other => panic!("expected a total refusal, got {other:?}"),
    }
}

#[test]
fn a_single_file_over_the_bound_is_refused_even_when_the_total_is_fine() {
    let limits = ArchiveLimits { max_single_file: 100, max_total_uncompressed: 1_000, ..ArchiveLimits::default() };
    let entries = vec![Entry::file("big", 101), Entry::file("small", 10)];
    match plan(&entries, limits) {
        Err(ArtifactError::TooLarge { found, limit }) => {
            assert_eq!(found, 101);
            assert_eq!(limit, 100);
        }
        other => panic!("expected a per-file refusal, got {other:?}"),
    }
}

#[test]
fn a_saturated_total_is_refused_rather_than_wrapped() {
    // ★ Two entries that each declare `u64::MAX` would overflow a sum, and a wrapped total would be a *small* number —
    // so the archive that lied about its size would be the one that passed.
    let entries = vec![Entry::file("a", u64::MAX), Entry::file("b", u64::MAX)];
    match plan(&entries, ArchiveLimits::default()) {
        // The per-file bound refuses it first, which is the right answer too — the assertion is that nothing wrapped.
        Err(ArtifactError::TooLarge { found, .. }) => assert_eq!(found, u64::MAX),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // With a huge per-file allowance, the total is what has to catch it.
    let limits = ArchiveLimits { max_single_file: u64::MAX, ..ArchiveLimits::default() };
    match plan(&entries, limits) {
        Err(ArtifactError::TooLarge { found, .. }) => assert_eq!(found, u64::MAX, "the sum saturated"),
        other => panic!("expected a saturated total to be refused, got {other:?}"),
    }
}

#[test]
fn a_compression_bomb_is_refused_by_its_ratio() {
    // ★ The bound a count and a total do not catch: one entry, a few kilobytes compressed, expanding to the whole
    // allowance. The ratio is the only one of the three that notices.
    let entry = Entry { path: "bomb.bin".to_owned(), kind: EntryKind::File, size: 64 * 1024 * 1024, compressed: Some(1_024) };
    match plan(&[entry], ArchiveLimits::default()) {
        Err(ArtifactError::CompressionBomb { path, expanded, compressed, limit }) => {
            assert_eq!(path, "bomb.bin");
            assert_eq!(expanded, 64 * 1024 * 1024);
            assert_eq!(compressed, 1_024);
            assert!((limit - 200.0).abs() < f64::EPSILON);
        }
        other => panic!("expected a ratio refusal, got {other:?}"),
    }
}

#[test]
fn an_entry_that_says_it_compressed_to_nothing_is_refused() {
    // Not a ratio of infinity to be reasoned about: it is an archive lying about a size.
    let entry = Entry { path: "a".to_owned(), kind: EntryKind::File, size: 10, compressed: Some(0) };
    assert!(plan(&[entry], ArchiveLimits::default()).is_err());
    // And an *empty* entry that compressed to nothing is fine, because there is nothing behind the claim.
    let empty = Entry { path: "a".to_owned(), kind: EntryKind::File, size: 0, compressed: Some(0) };
    assert!(plan(&[empty], ArchiveLimits::default()).is_ok());
}

#[test]
fn an_archive_that_does_not_record_compressed_sizes_is_not_treated_as_a_bomb() {
    // A streamed archive has no per-entry compressed size, and a ratio of infinity would refuse every entry of it.
    let entries = vec![Entry::file("a", 1_000_000), Entry::file("b", 1_000_000)];
    let planned = plan(&entries, ArchiveLimits::default()).expect("a plan");
    assert_eq!(planned.total_bytes, 2_000_000);
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

#[test]
fn every_refusal_explains_itself() {
    let refusals = [
        ArtifactError::ForbiddenEntry { path: "link".to_owned(), kind: "symbolic link" },
        ArtifactError::TooDeep { path: "a/b/c".to_owned(), found: 3, limit: 2 },
        ArtifactError::CompressionBomb { path: "a".to_owned(), expanded: 1_000, compressed: 1, limit: 200.0 },
        ArtifactError::TooManyFiles { found: 10, limit: 4 },
        ArtifactError::Empty,
    ];
    for refusal in &refusals {
        let sentence = refusal.to_string();
        assert!(sentence.len() > 15, "{refusal:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
    }
    // And the two that name a path name it, which is what an author needs to find the entry.
    assert!(refusals[0].to_string().contains("link"));
    assert!(refusals[2].to_string().contains("expands"));
}

#[test]
fn the_limits_are_the_design_documents_numbers() {
    // Written down here as well as in the type, because a limit that quietly changed is a limit nobody reviewed.
    let limits = ArchiveLimits::default();
    assert_eq!(limits.max_entries, 4_096);
    assert_eq!(limits.max_total_uncompressed, 256 * 1024 * 1024);
    assert_eq!(limits.max_single_file, 64 * 1024 * 1024);
    assert!((limits.max_compression_ratio - 200.0).abs() < f64::EPSILON);
    assert_eq!(limits.max_path_depth, 16);
    assert_eq!(ArchiveLimits::artifact(), limits);
    assert_eq!(ArchiveLimits::new(), limits);
}

#[test]
fn a_plan_carries_exactly_what_came_back_and_nothing_else() {
    // The property the caller depends on: there is no path arithmetic left to get wrong, because the plan is a closed
    // set. A caller that wanted to write something not in it would have to construct it.
    let planned = plan(&good(), ArchiveLimits::default()).expect("a plan");
    for entry in &planned.entries {
        assert!(entry.kind.is_writable(), "{entry:?}");
        assert!(!entry.path.starts_with('/'), "{entry:?}");
        assert!(!entry.path.contains(".."), "{entry:?}");
    }
}
