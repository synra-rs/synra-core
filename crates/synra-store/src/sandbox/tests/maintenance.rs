use crate::paths::PathError;
use super::super::{CACHE, FILES, PluginDataRoot, SandboxMeta};
use super::{Fixture, unique_suffix};

#[test]
fn measuring_counts_both_subdirectories() {
    let fixture = Fixture::new();
    let files = fixture.sandbox.root().join(FILES);
    let cache = fixture.sandbox.root().join(CACHE);
    std::fs::write(files.join("a.txt"), vec![b'x'; 100]).expect("writes");
    std::fs::create_dir_all(files.join("nested")).expect("creates");
    std::fs::write(files.join("nested/b.txt"), vec![b'x'; 50]).expect("writes");
    std::fs::write(cache.join("c.bin"), vec![b'x'; 25]).expect("writes");

    let meta = fixture.sandbox.measure(1_000).expect("measures");
    assert_eq!(meta.files_bytes, 150);
    assert_eq!(meta.cache_bytes, 25);
    assert_eq!(meta.total_bytes(), 175);
    assert_eq!(meta.plugin_id, "@synra-plugin/chat");
    assert_eq!(meta.measured_at_ms, 1_000);
    assert!(meta.is_cache_disposable());
}

#[test]
fn measuring_an_empty_sandbox_reports_zero() {
    let fixture = Fixture::new();
    let meta = fixture.sandbox.measure(0).expect("measures");
    assert_eq!(meta.total_bytes(), 0);
}

#[test]
fn clearing_the_cache_leaves_the_data_and_recreates_the_directory() {
    let fixture = Fixture::new();
    let files = fixture.sandbox.root().join(FILES);
    let cache = fixture.sandbox.root().join(CACHE);
    std::fs::write(files.join("keep.txt"), b"keep").expect("writes");
    std::fs::write(cache.join("drop.bin"), b"drop").expect("writes");

    fixture.sandbox.clear_cache().expect("clears");

    assert!(files.join("keep.txt").exists(), "the data survives");
    assert!(!cache.join("drop.bin").exists(), "the cache is gone");
    assert!(
        cache.is_dir(),
        "the directory is recreated so the next resolve works"
    );
    // And a resolve still works afterwards, which is the reason it is recreated.
    assert!(fixture.sandbox.resolve(CACHE, "after.txt").is_ok());
}

#[test]
fn clearing_a_cache_that_is_already_gone_is_not_an_error() {
    // A user may have deleted the whole directory, and a plugin calling clear must not see a failure for
    // something that is already the desired state.
    let fixture = Fixture::new();
    std::fs::remove_dir_all(fixture.sandbox.root().join(CACHE)).expect("removes");
    fixture.sandbox.clear_cache().expect("clears");
    assert!(fixture.sandbox.root().join(CACHE).is_dir());
}

#[test]
fn removing_the_sandbox_takes_everything() {
    let fixture = Fixture::new();
    let root = fixture.sandbox.root().to_path_buf();
    std::fs::write(root.join(FILES).join("x.txt"), b"x").expect("writes");

    fixture.sandbox.remove_all().expect("removes");
    assert!(!root.exists());
}

#[test]
fn two_plugins_get_two_sandboxes() {
    let parent = std::env::temp_dir().join(format!("synra-sandbox-two-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&parent);

    let chat = PluginDataRoot::ensure(&parent, "@synra-plugin/chat").expect("creates");
    let notes = PluginDataRoot::ensure(&parent, "@synra-plugin/notes").expect("creates");

    assert_ne!(chat.root(), notes.root());
    assert!(!chat.contains(notes.root()));
    assert!(!notes.contains(chat.root()));
    // And writing in one is invisible from the other.
    std::fs::write(chat.root().join(FILES).join("secret.txt"), b"secret").expect("writes");
    assert!(matches!(
        notes.resolve(FILES, "secret.txt"),
        Ok(path) if !path.exists()
    ));

    let _ = std::fs::remove_dir_all(&parent);
}

#[test]
fn opening_an_existing_sandbox_does_not_create_anything() {
    let fixture = Fixture::new();
    let reopened =
        PluginDataRoot::open(fixture.sandbox.root(), "@synra-plugin/chat").expect("opens");
    assert_eq!(reopened.root(), fixture.sandbox.root());
    assert_eq!(reopened.plugin_id(), "@synra-plugin/chat");
}

#[test]
fn opening_a_missing_sandbox_is_unresolvable() {
    let missing = std::env::temp_dir().join(format!("synra-nope-{}", unique_suffix()));
    assert!(matches!(
        PluginDataRoot::open(&missing, "@synra-plugin/chat"),
        Err(PathError::Unresolvable { .. })
    ));
}

#[test]
fn a_meta_record_round_trips_through_json() {
    let meta = SandboxMeta {
        plugin_id: "@synra-plugin/chat".to_owned(),
        files_bytes: 100,
        cache_bytes: 20,
        measured_at_ms: 5,
    };
    let json = serde_json::to_string(&meta).expect("serialises");
    assert!(json.contains("filesBytes"), "{json}");
    let back: SandboxMeta = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, meta);
}

#[test]
fn a_total_that_would_overflow_saturates() {
    // Two counts near the limit is not a realistic plugin, but an overflow would report a small number for a
    // large one — which is the direction that hides a problem.
    let meta = SandboxMeta {
        plugin_id: "x".to_owned(),
        files_bytes: u64::MAX,
        cache_bytes: 1,
        measured_at_ms: 0,
    };
    assert_eq!(meta.total_bytes(), u64::MAX);
}
