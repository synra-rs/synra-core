use super::*;

#[test]
fn a_mirror_that_answers_is_used_and_what_it_sent_is_cached() {
    let dir = TempDir::new("client-hit");
    let url = "https://registry.example";
    let fetcher = Scripted::answering(url, &packument("@acme/chat", "1.2.3"));
    let cache = CatalogCache::new(dir.path());
    let client = CatalogClient::new(config(&[("https://registry.example", 1)]), cache, &fetcher);

    let fetched = client.packument("@acme/chat", 1_000).expect("a packument");
    assert_eq!(fetched.packument.name, "@acme/chat");
    assert_eq!(fetched.origin, Origin::Registry { mirror: "https://registry.example".to_owned() });

    // ★ Cached **before** it was returned, so the next call survives a registry that has since gone away. This is the window
    // in which a machine goes offline.
    assert!(client.cache().load("@acme/chat", 1_000).expect("a load").is_some());
}

#[test]
fn the_second_mirror_is_tried_when_the_first_refuses() {
    let dir = TempDir::new("client-mirrors");
    let first = "https://first.example";
    let second = "https://second.example";
    let fetcher = Scripted::answering(second, &packument("@acme/chat", "1.2.3"));
    let client = CatalogClient::new(
        config(&[("https://first.example", 1), ("https://second.example", 2)]),
        CatalogCache::new(dir.path()),
        &fetcher,
    );

    let fetched = client.packument("@acme/chat", 1_000).expect("a packument");
    assert_eq!(fetched.origin, Origin::Registry { mirror: "https://second.example".to_owned() });
    // And the first was actually tried, so the ordering is the configuration's rather than luck.
    assert!(
        fetcher.asked().first().is_some_and(|asked| asked.starts_with(first)),
        "{:?}",
        fetcher.asked()
    );
}

#[test]
fn a_mirror_that_answers_with_something_else_does_not_end_the_search() {
    // ★ A registry that has started answering with an error page must not hide the second mirror. The bad answer is recorded
    // rather than skipped, because it is worth seeing.
    let dir = TempDir::new("client-garbage");
    let first = "https://first.example";
    let second = "https://second.example";
    let fetcher = Scripted::answering(first, "<html>we are down</html>");
    fetcher
        .answers
        .borrow_mut()
        .insert(second.to_owned(), Ok(packument("@acme/chat", "1.2.3")));
    let client = CatalogClient::new(
        config(&[("https://first.example", 1), ("https://second.example", 2)]),
        CatalogCache::new(dir.path()),
        &fetcher,
    );

    let fetched = client.packument("@acme/chat", 1_000).expect("the second mirror's document");
    assert_eq!(fetched.packument.name, "@acme/chat");
    assert_eq!(fetched.origin, Origin::Registry { mirror: "https://second.example".to_owned() });
}

#[test]
fn every_mirror_failing_falls_back_to_the_cache_and_says_how_old_it_is() {
    // ★ The design's first offline row, end to end: registry unreachable → the cached packument, with the age a screen shows
    // "offline mode" from.
    let dir = TempDir::new("client-offline");
    let cache = CatalogCache::new(dir.path());
    let day = 24 * 60 * 60 * 1_000;
    cache.store("@acme/chat", &packument("@acme/chat", "1.0.0"), 0).expect("a store");

    let fetcher = Scripted::failing("https://registry.example", "connection refused");
    let client = CatalogClient::new(config(&[("https://registry.example", 1)]), cache, &fetcher);

    // Eight days later the entry is past its seven-day lifetime, and it is **still returned** — marked.
    let fetched = client.packument("@acme/chat", 8 * day).expect("the cached document");
    assert_eq!(fetched.packument.name, "@acme/chat");
    match fetched.origin {
        Origin::Cache { age_ms, stale } => {
            assert_eq!(age_ms, 8 * day);
            assert!(stale, "eight days is past a seven-day lifetime");
        }
        other => panic!("expected the cache, got {other:?}"),
    }
}

#[test]
fn a_fresh_cache_entry_is_reported_as_fresh_when_it_is_used() {
    // The other side of the same flag: the caller shows "offline mode" for a stale entry and not for a fresh one, so the two
    // have to be distinguishable at the point of use rather than only inside the cache.
    let dir = TempDir::new("client-fresh");
    let cache = CatalogCache::new(dir.path());
    cache.store("@acme/chat", &packument("@acme/chat", "1.0.0"), 0).expect("a store");

    let fetcher = Scripted::failing("https://registry.example", "offline");
    let client = CatalogClient::new(config(&[("https://registry.example", 1)]), cache, &fetcher);

    match client.packument("@acme/chat", 1_000).expect("the cached document").origin {
        Origin::Cache { age_ms, stale } => {
            assert_eq!(age_ms, 1_000);
            assert!(!stale);
        }
        other => panic!("expected the cache, got {other:?}"),
    }
}

#[test]
fn nothing_at_all_is_an_error_that_names_every_attempt() {
    // ★ "The registry is unreachable" is not actionable. "Mirror A timed out, mirror B answered 503, and nothing was cached"
    // is — which is why the attempts are carried rather than summarised.
    let dir = TempDir::new("client-nothing");
    let first = "https://first.example";
    let second = "https://second.example";
    let fetcher = Scripted::default();
    fetcher.answers.borrow_mut().insert(first.to_owned(), Err("timed out".to_owned()));
    fetcher.answers.borrow_mut().insert(second.to_owned(), Err("503".to_owned()));
    let client = CatalogClient::new(
        config(&[("https://first.example", 1), ("https://second.example", 2)]),
        CatalogCache::new(dir.path()),
        &fetcher,
    );

    match client.packument("@acme/chat", 0) {
        Err(CatalogError::Unreachable { attempts, .. }) => {
            // ★ The configured mirrors first and in order, then the default registry — which `resolve` appends whether or not
            // it was configured, and which is why this asserts on a prefix rather than on the whole list.
            assert!(attempts.len() >= 2, "{attempts:?}");
            assert_eq!(attempts[0], ("https://first.example".to_owned(), "timed out".to_owned()));
            assert_eq!(attempts[1], ("https://second.example".to_owned(), "503".to_owned()));
            assert!(
                attempts.iter().any(|(mirror, _)| mirror.contains("registry.npmjs.org")),
                "the default registry is tried too: {attempts:?}"
            );
        }
        other => panic!("expected the attempts, got {other:?}"),
    }
}

#[test]
fn an_override_sends_one_package_somewhere_else() {
    // The configuration's own feature, exercised through the client so the two cannot disagree about which URL a package
    // resolves to.
    let dir = TempDir::new("client-override");
    let url = "https://internal.example";
    let fetcher = Scripted::answering(url, &packument("@acme/chat", "9.9.9"));
    let client = CatalogClient::new(
        config(&[("https://registry.example", 1)])
            .with_override(PackagePattern::new("@acme/chat"), "https://internal.example"),
        CatalogCache::new(dir.path()),
        &fetcher,
    );

    let fetched = client.packument("@acme/chat", 0).expect("a packument");
    assert_eq!(fetched.origin, Origin::Registry { mirror: "https://internal.example".to_owned() });
    // And the URL it asked for is the override's, with the path the convention spells.
    assert_eq!(fetcher.asked(), vec![format!("{url}/%40acme/chat")]);
}

#[test]
fn a_packument_url_keeps_the_scope_in_the_path() {
    // The npm convention: a scoped name's separator is part of the path, and escaping it would address a different document.
    assert_eq!(packument_url("https://registry.example", "@acme/chat"), "https://registry.example/%40acme/chat");
    // A trailing slash in the configuration would otherwise double up.
    assert_eq!(packument_url("https://registry.example/", "@acme/chat"), "https://registry.example/%40acme/chat");
    assert_eq!(packument_url("https://registry.example", "plain"), "https://registry.example/plain");
}
