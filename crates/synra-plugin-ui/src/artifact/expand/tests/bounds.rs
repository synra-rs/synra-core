use super::*;

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
fn the_limits_are_the_design_documents_numbers() {
    // Written down here as well as in the type, because a limit that quietly changed is a limit nobody reviewed.
    let limits = ArchiveLimits::default();
    assert_eq!(limits.max_entries, 4_096);
    assert_eq!(limits.max_total_uncompressed, 256 * 1024 * 1024);
    assert_eq!(limits.max_single_file, 64 * 1024 * 1024);
    assert!((limits.max_compression_ratio - 200.0).abs() < f64::EPSILON);
    assert_eq!(limits.max_path_depth, 16);
    assert_eq!(
        ArchiveLimits::artifact().max_total_uncompressed,
        crate::artifact::MAX_ARTIFACT_BYTES
    );
    assert_eq!(
        ArchiveLimits::artifact().max_single_file,
        crate::artifact::MAX_ARTIFACT_FILE_BYTES
    );
    assert_eq!(ArchiveLimits::new(), limits);
}
