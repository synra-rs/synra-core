use super::*;

#[test]
fn a_plugin_name_is_a_key_rather_than_a_path() {
    // ★ The trap this escaping exists for. A scoped name contains a separator, so the obvious
    // `dir.join(name).with_extension("json")` creates a **subdirectory** — and `../../etc/passwd` is a path out of the cache.
    let dir = TempDir::new("escape");
    let cache = CatalogCache::new(dir.path());
    let mut stored = 0;

    for name in [
        "@acme/chat",
        "../../etc/passwd",
        r"..\..\windows\system32",
        "a/b/c",
        "CON",
        "name with spaces",
        "trailing.",
    ] {
        cache.store(name, "a document", 1_000).expect("a store");
        stored += 1;
        // ★ Every entry is a **direct child** of the cache directory: no name produces a subdirectory, and none produces a
        // path outside. Counted as the loop goes, because the first version asserted "exactly one entry" on every pass and so
        // failed on the second name for a reason that had nothing to do with escaping.
        let entries: Vec<PathBuf> = std::fs::read_dir(dir.path())
            .expect("the directory")
            .flatten()
            .map(|entry| entry.path())
            .collect();
        assert_eq!(entries.len(), stored, "{name} produced more than one entry");
        for written in &entries {
            assert_eq!(written.parent(), Some(dir.path()), "{name} was written outside the cache");
            assert!(written.is_file(), "{name} did not produce a file");
        }

        let loaded = cache.load(name, 1_000).expect("a load").expect("an entry");
        assert_eq!(loaded.text(), "a document", "{name}");
        assert!(cache.forget(name).expect("a forget"));
        assert_eq!(cache.load(name, 1_000), Ok(None));
        stored -= 1;
    }
}

#[test]
fn two_names_that_would_escape_the_same_way_do_not_share_an_entry() {
    // ★ The other half of escaping: it has to be **injective**, or two plugins share one cache entry and a catalogue for the
    // wrong package is served. `_` is escaped too, so `a/b` and `a_b` cannot collide.
    let dir = TempDir::new("injective");
    let cache = CatalogCache::new(dir.path());

    let names = ["a/b", "a_b", "a.b", "a b", "a%2Fb"];
    for (index, name) in names.iter().enumerate() {
        cache.store(name, &format!("document {index}"), 1_000).expect("a store");
    }
    for (index, name) in names.iter().enumerate() {
        let loaded = cache.load(name, 1_000).expect("a load").expect("an entry");
        assert_eq!(loaded.text(), format!("document {index}"), "{name} shares an entry");
    }
}

#[test]
fn a_name_too_long_to_cache_is_refused_with_the_numbers() {
    // ★ Escaping triples the worst case, so a long plugin name produces a file name no filesystem accepts. Left to the
    // filesystem the caller would get an `Io` error from an operation it did not know was about length; refused here, with
    // both numbers, because "this name cannot be cached" is a fact about the name.
    let dir = TempDir::new("too-long");
    let cache = CatalogCache::new(dir.path());

    // All alphanumeric, so it escapes to itself: the file name is the name plus the prefix and the extension. The first
    // version of this test used 200 characters, which **fits** — `packument-` and `.json` add fifteen — and the failure it
    // reported was its own arithmetic rather than the limit.
    let long = "x".repeat(300);
    let error = cache.store(&long, "a document", 0).expect_err("too long");
    let text = error.to_string();
    assert!(text.contains("315"), "the name plus the prefix and extension: {text}");
    assert!(text.contains("255"), "{text}");

    // And a name that fits still works, so the limit is not simply refusing everything.
    let fits = "x".repeat(100);
    cache.store(&fits, "a document", 0).expect("a store");
}

#[test]
fn an_empty_name_is_refused_rather_than_written_to_the_directory_itself() {
    let dir = TempDir::new("empty-name");
    let cache = CatalogCache::new(dir.path());

    assert!(cache.store("", "a document", 1_000).is_err());
    assert!(cache.load("", 1_000).is_err());
}
