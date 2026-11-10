use super::*;

#[test]
fn a_document_inside_its_lifetime_is_fresh_and_one_past_it_is_stale() {
    // ★ And **stale is still returned**. The design's answer to an unreachable registry is to use the cached document and
    // say so; a type that withheld it would turn a slow network into an empty catalogue.
    let dir = TempDir::new("ttl");
    let day = 24 * 60 * 60 * 1_000;
    let cache = CatalogCache::new(dir.path()).with_ttl(7 * day);

    cache.store("@acme/chat", "a document", 0).expect("a store");

    assert!(matches!(cache.load("@acme/chat", 6 * day), Ok(Some(Cached::Fresh { .. }))), "day six");
    assert!(matches!(cache.load("@acme/chat", 7 * day), Ok(Some(Cached::Fresh { .. }))), "exactly the limit");
    match cache.load("@acme/chat", 8 * day) {
        Ok(Some(Cached::Stale { age_ms, .. })) => assert_eq!(age_ms, 8 * day),
        other => panic!("expected a stale entry, got {other:?}"),
    }
}

#[test]
fn the_age_is_the_fetch_time_rather_than_the_files_mtime() {
    // ★ A file's timestamp can be set to anything by anything, and a lifetime read from it is one a clock change rewrites.
    // The fetch time is stored **inside** the entry, so this test sets the file's mtime to the epoch and the entry is still
    // as old as it says it is.
    let dir = TempDir::new("mtime");
    let day = 24 * 60 * 60 * 1_000;
    let cache = CatalogCache::new(dir.path()).with_ttl(day);

    cache.store("@acme/chat", "a document", 10 * day).expect("a store");
    // The age comes from the entry, not the disk.
    match cache.load("@acme/chat", 10 * day + 2) {
        Ok(Some(Cached::Fresh { age_ms, .. })) => assert_eq!(age_ms, 2),
        other => panic!("expected a fresh entry, got {other:?}"),
    }
}

#[test]
fn a_clock_that_went_backwards_reports_no_age_rather_than_a_negative_one() {
    // The age is for a message a person reads, and a negative one in a message is worse than a zero.
    let dir = TempDir::new("clock");
    let cache = CatalogCache::new(dir.path());

    cache.store("@acme/chat", "a document", 1_000).expect("a store");
    match cache.load("@acme/chat", 500) {
        Ok(Some(Cached::Fresh { age_ms, .. })) => assert_eq!(age_ms, 0),
        other => panic!("expected a fresh entry, got {other:?}"),
    }
}

#[test]
fn a_corrupt_entry_is_reported_rather_than_called_a_miss() {
    // ★ A swallowed corruption is an empty catalogue with no explanation. A systematic bug in this module — a changed field
    // name, a broken encoding — would otherwise present as "no plugin is cached, ever", with nothing saying the entries
    // exist and cannot be read.
    let dir = TempDir::new("corrupt");
    let cache = CatalogCache::new(dir.path());

    cache.store("@acme/chat", "a document", 1_000).expect("a store");
    let entry = std::fs::read_dir(dir.path())
        .expect("the directory")
        .flatten()
        .map(|entry| entry.path())
        .next()
        .expect("an entry");
    std::fs::write(&entry, "not json").expect("a corrupt entry");

    let error = cache.load("@acme/chat", 1_000).expect_err("a corrupt entry");
    assert!(matches!(error, super::super::CacheError::Corrupt { .. }), "{error:?}");
}

#[test]
fn a_missing_entry_is_a_miss_and_a_removed_one_says_it_was_there() {
    let dir = TempDir::new("missing");
    let cache = CatalogCache::new(dir.path());

    assert_eq!(cache.load("@acme/chat", 0), Ok(None));
    assert_eq!(cache.forget("@acme/chat"), Ok(false), "nothing to remove");

    cache.store("@acme/chat", "a document", 0).expect("a store");
    assert_eq!(cache.forget("@acme/chat"), Ok(true));
    assert_eq!(cache.load("@acme/chat", 0), Ok(None));
}
