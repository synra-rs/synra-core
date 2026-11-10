use super::*;

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
