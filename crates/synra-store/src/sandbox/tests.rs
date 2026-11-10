use super::*;

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// A sandbox in a fresh temporary directory.
struct Fixture {
    parent: PathBuf,
    sandbox: PluginDataRoot,
}

impl Fixture {
    fn new() -> Self {
        let parent = std::env::temp_dir().join(format!("synra-sandbox-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&parent);
        let sandbox =
            PluginDataRoot::ensure(&parent, "@synra-plugin/chat").expect("creates the sandbox");
        Self { parent, sandbox }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.parent);
    }
}

#[test]
fn ensuring_creates_both_subdirectories() {
    let fixture = Fixture::new();
    assert!(fixture.sandbox.root().is_dir());
    for name in SUBDIRECTORIES {
        assert!(
            fixture
                .sandbox
                .subdirectory(name)
                .expect("resolves")
                .is_dir(),
            "{name} was not created"
        );
    }
}

#[test]
fn the_root_is_canonicalised_so_a_linked_parent_still_works() {
    // A user who moved their data directory and linked it back would otherwise have every resolution fail,
    // because the configured path and the real one differ.
    let fixture = Fixture::new();
    assert!(fixture.sandbox.root().is_absolute());
    assert_eq!(
        fixture.sandbox.root(),
        std::fs::canonicalize(fixture.parent.join("synra-plugin+chat")).expect("canonical")
    );
}

#[test]
fn only_the_two_subdirectories_may_be_named() {
    let fixture = Fixture::new();
    assert!(fixture.sandbox.subdirectory("files").is_ok());
    assert!(fixture.sandbox.subdirectory("cache").is_ok());

    // Not a mistyped path: a directory that was never promised to the plugin.
    for name in ["", "..", "/", "keys", "files/../cache", "secrets"] {
        match fixture.sandbox.subdirectory(name) {
            Err(PathError::BadComponent { .. }) => {}
            other => panic!("{name:?} should not resolve, got {other:?}"),
        }
    }
}

#[test]
fn a_plain_relative_path_resolves_inside_its_subdirectory() {
    let fixture = Fixture::new();
    // The parent has to exist, because that is the part which is canonicalised and therefore the part that
    // carries the escape risk. A caller writing a file creates its directory first.
    std::fs::create_dir_all(fixture.sandbox.root().join(FILES).join("notes")).expect("creates");

    let resolved = fixture
        .sandbox
        .resolve(FILES, "notes/today.txt")
        .expect("resolves");

    let files = std::fs::canonicalize(fixture.sandbox.root().join(FILES)).expect("canonical");
    assert!(resolved.starts_with(&files), "{}", resolved.display());
    assert!(resolved.ends_with("today.txt"));
}

#[test]
fn a_path_at_the_top_of_a_subdirectory_resolves() {
    let fixture = Fixture::new();
    assert!(fixture.sandbox.resolve(FILES, "a.txt").is_ok());
    // An empty relative path names the directory, not a file, so it is refused rather than treated as "the
    // subdirectory itself" — which would make a write into it ambiguous.
    assert!(fixture.sandbox.resolve(FILES, "").is_err());
    assert!(fixture.sandbox.resolve(FILES, ".").is_err());
}

#[test]
fn an_absolute_path_is_refused() {
    // `Path::join` replaces rather than appends, so this would not be an error without the check: it would
    // be a read of `/etc/passwd`.
    let fixture = Fixture::new();
    // A path on the current platform that is rooted: `/etc/passwd` is absolute on Unix and merely
    // drive-relative on Windows, so the fixture is built rather than written out.
    let rooted = if cfg!(windows) {
        "C:\\Windows\\System32"
    } else {
        "/etc/passwd"
    };
    for path in [rooted, "\\\\server\\share"] {
        assert!(
            matches!(
                fixture.sandbox.resolve(FILES, path),
                Err(PathError::Absolute(_))
            ),
            "{path:?} should be refused"
        );
    }
}

#[test]
fn a_traversal_is_refused() {
    let fixture = Fixture::new();
    // `..` from `files/` reaches the sandbox root, and one more reaches the parent directory.
    for path in [
        "../cache",
        "../x",
        "../../x",
        "a/../../x",
        "a/../../../etc/passwd",
    ] {
        match fixture.sandbox.resolve(FILES, path) {
            Err(PathError::Escapes { .. }) | Err(PathError::Unresolvable { .. }) => {}
            other => panic!("{path:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn a_traversal_that_stays_inside_is_allowed() {
    // `files/a/../b.txt` is `files/b.txt`, which is inside. Refusing it would be an over-correction that
    // breaks plugins doing ordinary path arithmetic.
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.sandbox.root().join(FILES).join("a")).expect("creates");
    let resolved = fixture
        .sandbox
        .resolve(FILES, "a/../b.txt")
        .expect("resolves");

    let files = std::fs::canonicalize(fixture.sandbox.root().join(FILES)).expect("canonical");
    assert!(resolved.starts_with(&files), "{}", resolved.display());
    assert!(resolved.ends_with("b.txt"));
}

#[cfg(unix)]
#[test]
fn a_symlink_pointing_out_is_refused() {
    // The case that makes "count the `..`s" insufficient: a plugin can create a symlink inside its own
    // sandbox, and counting components cannot see where it points.
    let fixture = Fixture::new();
    let outside = fixture.parent.join("outside");
    std::fs::create_dir_all(&outside).expect("creates");
    std::fs::write(outside.join("secret.txt"), b"secret").expect("writes");

    let link = fixture.sandbox.root().join(FILES).join("escape");
    std::os::unix::fs::symlink(&outside, &link).expect("links");

    match fixture.sandbox.resolve(FILES, "escape/secret.txt") {
        Err(PathError::Escapes { .. }) => {}
        other => panic!("a symlink out of the sandbox should be refused, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_pointing_inside_is_allowed() {
    // A plugin laying out its own storage with links is ordinary use, and refusing it would be an
    // over-correction.
    let fixture = Fixture::new();
    let target = fixture.sandbox.root().join(FILES).join("real");
    std::fs::create_dir_all(&target).expect("creates");

    let link = fixture.sandbox.root().join(FILES).join("link");
    std::os::unix::fs::symlink(&target, &link).expect("links");

    assert!(fixture.sandbox.resolve(FILES, "link/x.txt").is_ok());
}

#[test]
fn a_missing_parent_is_unresolvable_rather_than_accepted() {
    // The file's parent has to be canonicalised, so it has to exist. Accepting a missing parent would mean
    // returning a path that was never checked against the sandbox.
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.sandbox.resolve(FILES, "no/such/directory/x.txt"),
        Err(PathError::Unresolvable { .. })
    ));
}

#[test]
fn a_resolved_path_is_always_inside_the_sandbox() {
    // The invariant a caller relies on, asserted over every shape a path can take.
    let fixture = Fixture::new();
    let candidates = [
        "a.txt",
        "a/b/c.txt",
        "a/../b.txt",
        "./a.txt",
        "a/./b.txt",
        "a//b.txt",
    ];
    for candidate in candidates {
        if let Ok(resolved) = fixture.sandbox.resolve(FILES, candidate) {
            assert!(
                fixture.sandbox.contains(&resolved),
                "{candidate:?} resolved outside the sandbox to {}",
                resolved.display()
            );
        }
    }
}

#[test]
fn containing_a_path_compares_against_the_root() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .sandbox
            .contains(&fixture.sandbox.root().join("files/x"))
    );
    assert!(fixture.sandbox.contains(fixture.sandbox.root()));
    // A sibling plugin's sandbox is not this one's, even sharing a prefix.
    assert!(
        !fixture
            .sandbox
            .contains(&fixture.parent.join("synra-plugin+notes/files/x"))
    );
    assert!(!fixture.sandbox.contains(Path::new("/etc")));
}

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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// A path a plugin might supply, including the shapes that are meant to escape.
    fn arbitrary_plugin_path() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]{1,8}",
            "[a-z]{1,8}/[a-z]{1,8}",
            "\\.\\./[a-z]{1,8}",
            "\\.\\./\\.\\./[a-z]{1,8}",
            "/[a-z]{1,8}",
            "/etc/[a-z]{1,8}",
            "[a-z]{1,8}/\\.\\./[a-z]{1,8}",
            "\\./[a-z]{1,8}",
            "[a-z]{1,8}//[a-z]{1,8}",
        ]
    }

    proptest! {
        /// Whatever a plugin supplies, a successful resolution is inside the sandbox. This is the property the
        /// whole module exists for: a resolved path a caller then opens must not be able to name the user's
        /// files.
        #[test]
        fn a_resolved_path_is_always_inside(path in arbitrary_plugin_path()) {
            let parent = std::env::temp_dir().join(format!("synra-sandbox-prop-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&parent);
            let sandbox = match PluginDataRoot::ensure(&parent, "@synra-plugin/prop") {
                Ok(sandbox) => sandbox,
                Err(_) => return Ok(()),
            };

            if let Ok(resolved) = sandbox.resolve(FILES, &path) {
                prop_assert!(
                    sandbox.contains(&resolved),
                    "{:?} resolved outside the sandbox to {}",
                    path,
                    resolved.display(),
                );
            }

            let _ = std::fs::remove_dir_all(&parent);
        }

        /// A subdirectory name that is not one of the two is always refused, whatever it looks like. The list is
        /// closed so a plugin cannot name a directory it was never promised.
        #[test]
        fn only_the_documented_subdirectories_resolve(name in ".{0,20}") {
            let parent = std::env::temp_dir().join(format!("synra-sandbox-sub-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&parent);
            let sandbox = match PluginDataRoot::ensure(&parent, "@synra-plugin/prop") {
                Ok(sandbox) => sandbox,
                Err(_) => return Ok(()),
            };

            let allowed = SUBDIRECTORIES.contains(&name.as_str());
            prop_assert_eq!(sandbox.subdirectory(&name).is_ok(), allowed);

            let _ = std::fs::remove_dir_all(&parent);
        }
    }
}
