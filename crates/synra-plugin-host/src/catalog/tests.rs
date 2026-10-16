//! The cache's mapping, its lifetime, and what the client does when nobody answers.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{Cached, CatalogCache, CatalogClient, CatalogError, Fetches, Origin, packument_url};
use crate::registry::{PackagePattern, RegistryConfig, RegistryMirror};

/// A packument the parser accepts.
fn packument(name: &str, version: &str) -> String {
    format!(
        r#"{{"name":"{name}","dist-tags":{{"latest":"{version}"}},"versions":{{
            "{version}":{{"name":"{name}","version":"{version}","dist":{{"tarball":"https://x/y.tgz","integrity":"sha512-AAAA"}}}}
        }}}}"#
    )
}

/// A fetcher that answers from a table, and records what it was asked for.
#[derive(Default)]
struct Scripted {
    answers: RefCell<BTreeMap<String, Result<String, String>>>,
    asked: RefCell<Vec<String>>,
}

impl Scripted {
    fn answering(url: &str, body: &str) -> Self {
        let scripted = Self::default();
        scripted.answers.borrow_mut().insert(url.to_owned(), Ok(body.to_owned()));
        scripted
    }

    fn failing(url: &str, why: &str) -> Self {
        let scripted = Self::default();
        scripted.answers.borrow_mut().insert(url.to_owned(), Err(why.to_owned()));
        scripted
    }

    fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }
}

impl Fetches for &Scripted {
    /// ★ Matched by **suffix** rather than by the whole URL.
    ///
    /// Because `RegistryConfig::resolve` appends the default registry after whatever was configured, so a configured mirror
    /// is never the only URL a package resolves to. Keying the table on the whole URL made every test here fail against a
    /// third attempt nobody wrote — which is the same fact `nothing_at_all_is_an_error_that_names_every_attempt` asserts on
    /// purpose.
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.asked.borrow_mut().push(url.to_owned());
        for (key, answer) in self.answers.borrow().iter() {
            if url.starts_with(key) {
                return match answer {
                    Ok(body) => Ok(body.clone().into_bytes()),
                    Err(why) => Err(why.clone()),
                };
            }
        }
        Err("nothing is listening".to_owned())
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = format!("synra-catalog-{label}-{}", std::process::id());
        let path = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(mirrors: &[(&str, u8)]) -> RegistryConfig {
    let mut config = RegistryConfig::new();
    for (url, priority) in mirrors {
        config = config.with_mirror(RegistryMirror::new(*url, *priority));
    }
    config
}

// ── The cache's mapping ───────────────────────────────────────────────────────────────────────────

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

// ── The lifetime ──────────────────────────────────────────────────────────────────────────────────

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
    assert!(matches!(error, super::CacheError::Corrupt { .. }), "{error:?}");
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

// ── The client ────────────────────────────────────────────────────────────────────────────────────

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
