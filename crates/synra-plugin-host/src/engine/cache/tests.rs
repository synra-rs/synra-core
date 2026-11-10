use std::{fs, path::PathBuf};
use super::{BackendKind, CACHED_EXTENSION, CacheError, CompileCache};

/// A directory that removes itself, per the repository's rule for temporary paths.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let unique = format!(
            "synra-cache-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos())
        );
        let path = std::env::temp_dir().join(unique.replace(['\\', ':', '.', ' '], "-"));
        let _ = fs::create_dir_all(&path);
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cache(directory: &TempDir) -> CompileCache {
    CompileCache::open(&directory.0, "x86_64-pc-windows-msvc").expect("a cache")
}

fn digest(seed: char) -> String {
    // 64 hex characters, which is what a sha256 digest is: the safety check insists on hex.
    std::iter::repeat_n(seed, 64).collect()
}

#[test]
fn a_key_names_every_input_that_changes_the_bytes() {
    let directory = TempDir::new();
    let cache = cache(&directory);
    let key = cache.key(digest('a'), BackendKind::WasmtimeCranelift, "48.0.0");
    let name = key.file_name();
    for part in [digest('a'), "wasmtime-cranelift".to_owned(), "48.0.0".to_owned(), cache.target().to_owned()] {
        assert!(name.contains(&part), "{part} is not in {name}");
    }
    assert!(name.ends_with(CACHED_EXTENSION));
}

#[test]
fn a_different_engine_version_is_a_different_key() {
    // ★ The upgrade this catches: precompiled artefacts are only loadable by the engine that produced them, and a
    // cache that ignored the version would hand a new engine bytes from the old one.
    let directory = TempDir::new();
    let cache = cache(&directory);
    let old = cache.key(digest('a'), BackendKind::WasmtimeWinch, "48.0.0");
    let new = cache.key(digest('a'), BackendKind::WasmtimeWinch, "49.0.0");
    assert_ne!(old.file_name(), new.file_name());
    assert_ne!(old.describe(), new.describe());
}

#[test]
fn a_different_backend_is_a_different_key() {
    let directory = TempDir::new();
    let cache = cache(&directory);
    for (first, second) in [
        (BackendKind::WasmtimeCranelift, BackendKind::WasmtimeWinch),
        (BackendKind::WasmtimeCranelift, BackendKind::Wasmi),
        (BackendKind::Wasmi, BackendKind::Scripted),
    ] {
        assert_ne!(
            cache.key(digest('a'), first, "1").file_name(),
            cache.key(digest('a'), second, "1").file_name(),
            "{first} and {second} share a key"
        );
    }
}

#[test]
fn a_different_target_is_a_different_key() {
    let directory = TempDir::new();
    let first = CompileCache::open(&directory.0, "x86_64-pc-windows-msvc").expect("a cache");
    let second = CompileCache::open(&directory.0, "aarch64-linux-android").expect("a cache");
    assert_ne!(
        first.key(digest('a'), BackendKind::WasmtimeCranelift, "48").file_name(),
        second.key(digest('a'), BackendKind::WasmtimeCranelift, "48").file_name()
    );
}

#[test]
fn a_miss_is_not_an_error() {
    let directory = TempDir::new();
    let cache = cache(&directory);
    let key = cache.key(digest('b'), BackendKind::Wasmi, "1");
    assert_eq!(cache.load(&key).expect("a cold cache"), None);
}

#[test]
fn what_was_stored_comes_back() {
    let directory = TempDir::new();
    let cache = cache(&directory);
    let key = cache.key(digest('c'), BackendKind::WasmtimeCranelift, "48");
    cache.store(&key, b"compiled bytes", 1_000).expect("stored");
    assert_eq!(cache.load(&key).expect("a hit").as_deref(), Some(&b"compiled bytes"[..]));
}

#[test]
fn no_partial_file_is_left_behind() {
    // The rename is what makes a killed write harmless. A `.part` left in the directory is a file the next sweep
    // removes and the next load never sees — and this asserts the ordinary path leaves none at all.
    let directory = TempDir::new();
    let cache = cache(&directory);
    let key = cache.key(digest('d'), BackendKind::Wasmi, "1");
    cache.store(&key, b"x", 0).expect("stored");
    let names: Vec<String> = cache.entries().expect("readable").into_iter().map(|(name, _)| name).collect();
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].ends_with(CACHED_EXTENSION), "{names:?}");
}

#[test]
fn a_key_that_is_not_a_file_name_is_refused() {
    // ★ The digest is the field most likely to have come from an artefact rather than from this code, so a key
    // that would escape the cache directory has to be a refusal. The empty digest comes through the same check:
    // `all` over an empty iterator is true, so the length is what refuses it.
    let directory = TempDir::new();
    let cache = cache(&directory);
    for digest in ["../../etc/passwd", "a/b", r"a\b", "not hex at all", "aa bb", ""] {
        let key = cache.key(digest, BackendKind::Wasmi, "1");
        assert!(!key.is_safe(), "{digest:?} was accepted as a key");
        assert!(matches!(cache.load(&key), Err(CacheError::BadKey { .. })));
        assert!(matches!(cache.store(&key, b"x", 0), Err(CacheError::BadKey { .. })));
    }
    // And a digest of exactly the right shape is accepted, so the check is not one that refuses everything.
    assert!(cache.key(digest('a'), BackendKind::Wasmi, "1").is_safe());
}

#[test]
fn clearing_removes_only_our_files() {
    let directory = TempDir::new();
    let cache = cache(&directory);
    let key = cache.key(digest('e'), BackendKind::Wasmi, "1");
    cache.store(&key, b"one", 0).expect("stored");
    let stranger = directory.0.join("notes.txt");
    fs::write(&stranger, "not ours").expect("wrote");

    assert_eq!(cache.clear().expect("cleared"), 1);
    assert!(stranger.exists(), "a file that is not a cache entry was removed");
    assert_eq!(cache.load(&key).expect("cold"), None);
}

#[test]
fn the_report_lists_what_is_held() {
    let directory = TempDir::new();
    let cache = cache(&directory);
    cache.store(&cache.key(digest('f'), BackendKind::Wasmi, "1"), b"1234", 0).expect("stored");
    cache
        .store(&cache.key(digest('0'), BackendKind::Wasmi, "1"), b"123456", 0)
        .expect("stored");
    let entries = cache.entries().expect("readable");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries.iter().map(|(_, bytes)| *bytes).sum::<u64>(), 10);
}

#[test]
fn every_backend_has_a_distinct_name() {
    // The name is a cache key part, so two backends sharing one would share artefacts — which is the failure the
    // whole key exists for, arriving through the one field that looks too trivial to check.
    let mut names: Vec<&str> = BackendKind::ALL.iter().map(|kind| kind.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), BackendKind::ALL.len());
}
