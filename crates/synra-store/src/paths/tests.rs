use std::path::Path;

use super::{PathError, Paths, is_within, sanitise_component};

fn paths() -> Paths {
    Paths::new("/data", "/cache")
}

#[test]
fn the_layout_puts_each_thing_where_the_design_says() {
    let paths = paths();
    assert_eq!(paths.data_dir(), Path::new("/data"));
    assert_eq!(paths.cache_dir(), Path::new("/cache"));
    assert_eq!(paths.log_dir(), Path::new("/data/logs"));
    assert_eq!(paths.db_path(), Path::new("/data/kernel.db"));
    assert_eq!(
        paths.bootstrap_config_path(),
        Path::new("/data/config.json")
    );
    assert_eq!(paths.plugins_dir(), Path::new("/data/plugins"));
    assert_eq!(paths.plugin_data_dir(), Path::new("/data/plugin-data"));
    assert_eq!(paths.keys_dir(), Path::new("/data/keys"));
    assert_eq!(paths.wasm_cache_dir(), Path::new("/cache/wasm"));
    assert_eq!(paths.catalog_cache_dir(), Path::new("/cache/catalog"));
    assert_eq!(
        paths.diagnostics_cache_dir(),
        Path::new("/cache/diagnostics")
    );
    assert_eq!(paths.crash_dir(), Path::new("/data/logs/crash"));
}

#[test]
fn keys_live_with_the_data_and_not_with_the_cache() {
    // A key deleted on a cache sweep is a key the user has to re-establish, which means re-pairing every
    // device — so the assertion is about which root it hangs off, not about its name.
    let paths = paths();
    assert!(paths.keys_dir().starts_with(paths.data_dir()));
    assert!(!paths.keys_dir().starts_with(paths.cache_dir()));
}

#[test]
fn caches_live_with_the_cache() {
    // Deleting all of it costs a recompile and nothing else, which is only true if nothing in it is
    // irreplaceable.
    let paths = paths();
    for directory in [
        paths.wasm_cache_dir(),
        paths.catalog_cache_dir(),
        paths.diagnostics_cache_dir(),
    ] {
        assert!(
            directory.starts_with(paths.cache_dir()),
            "{}",
            directory.display()
        );
    }
}

#[test]
fn one_root_is_used_twice_when_the_platform_does_not_separate_them() {
    let paths = Paths::under("/everything");
    assert_eq!(paths.data_dir(), paths.cache_dir());
    assert!(paths.db_path().starts_with("/everything"));
    assert!(paths.wasm_cache_dir().starts_with("/everything"));
}

#[test]
fn a_plugin_id_becomes_one_path_component() {
    // An id contains a `/` and an `@`, one of which is a path separator and neither of which is a legal
    // directory name everywhere.
    assert_eq!(
        sanitise_component("@synra-plugin/chat"),
        "synra-plugin+chat"
    );
    assert_eq!(
        sanitise_component("@imba97/synra-plugin-notes"),
        "imba97+synra-plugin-notes"
    );
}

#[test]
fn a_plugin_id_cannot_name_a_directory_outside_the_plugins_directory() {
    // The property that matters: whatever the id, the joined path stays under the root.
    for id in [
        "../../etc",
        "@scope/../../..",
        "..",
        "./..",
        "@scope//x",
        "a/b/c",
    ] {
        let sanitised = sanitise_component(id);
        assert!(!sanitised.contains('/'), "{id} -> {sanitised}");
        assert!(!sanitised.contains('\\'), "{id} -> {sanitised}");
        assert!(!sanitised.contains(".."), "{id} -> {sanitised}");
        assert!(!sanitised.starts_with('.'), "{id} -> {sanitised}");

        let joined = paths().plugin_dir(id);
        assert!(
            is_within(Path::new("/data/plugins"), &joined),
            "{id} escaped to {}",
            joined.display()
        );
    }
}

#[test]
fn sanitising_an_id_that_becomes_empty_yields_something_usable() {
    // An id of `@` or `` would otherwise produce the plugins directory itself, which one plugin could then
    // fill with another's files.
    for id in ["", "@", "...", "@@"] {
        let sanitised = sanitise_component(id);
        assert!(!sanitised.is_empty(), "{id:?}");
        assert_ne!(sanitised, ".", "{id:?}");
    }
}

#[test]
fn distinct_ids_stay_distinct_after_sanitising() {
    // A substitution that collapsed two ids would let one plugin read another's data, which is the one thing
    // the per-plugin directory exists to prevent.
    let ids = [
        "@synra-plugin/chat",
        "@synra-plugin/notes",
        "@imba97/synra-plugin-chat",
    ];
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        assert!(seen.insert(sanitise_component(id)), "{id} collided");
    }
}

#[test]
fn a_sibling_directory_is_not_inside() {
    // `/data` is a string prefix of `/database`, so a string comparison would accept it. This is the check
    // the sandbox relies on, so the mistake would be a path escape.
    assert!(is_within(Path::new("/data"), Path::new("/data/plugins")));
    assert!(is_within(Path::new("/data"), Path::new("/data")));
    assert!(!is_within(Path::new("/data"), Path::new("/database")));
    assert!(!is_within(Path::new("/data"), Path::new("/datax/plugins")));
    assert!(!is_within(Path::new("/data/plugins"), Path::new("/data")));
}

#[test]
fn a_relative_root_is_compared_component_wise() {
    assert!(is_within(Path::new("a/b"), Path::new("a/b/c")));
    assert!(!is_within(Path::new("a/b"), Path::new("a/bc")));
}

#[test]
fn the_layout_reports_whether_a_path_is_its_own() {
    let paths = paths();
    assert!(paths.contains(Path::new("/data/kernel.db")));
    assert!(paths.contains(Path::new("/cache/wasm/x.cwasm")));
    assert!(!paths.contains(Path::new("/elsewhere/kernel.db")));
    assert!(!paths.contains(Path::new("/datax/kernel.db")));
}

#[test]
fn every_required_directory_is_listed_once_and_under_a_root() {
    let paths = paths();
    let directories = paths.required_directories();

    let mut seen = std::collections::HashSet::new();
    for directory in &directories {
        assert!(
            seen.insert(directory.clone()),
            "{directory:?} is listed twice"
        );
        assert!(
            directory.starts_with(paths.data_dir()) || directory.starts_with(paths.cache_dir()),
            "{directory:?} is under neither root"
        );
    }
    // The two roots themselves are included, so a caller can create the layout from nothing.
    assert!(directories.contains(&paths.data_dir().to_path_buf()));
    assert!(directories.contains(&paths.cache_dir().to_path_buf()));
}

#[test]
fn ensuring_the_directories_creates_them_all() {
    let directory = tempfile::tempdir().expect("a unique directory per test");
    let paths = Paths::under(directory.path().join("data"));

    paths.ensure_directories().expect("creates");
    for directory in paths.required_directories() {
        assert!(
            directory.is_dir(),
            "{} was not created",
            directory.display()
        );
    }

    // Idempotent, because start-up can run more than once in a session.
    paths.ensure_directories().expect("creates again");
}

#[test]
fn a_layout_that_cannot_be_created_reports_which_directory() {
    // A path under an existing regular file cannot become a directory on any platform.
    let directory = tempfile::tempdir().expect("a unique directory per test");
    let root = directory.path().join("file");
    std::fs::write(&root, b"not a directory").expect("writes");

    let paths = Paths::under(root.join("under-a-file"));
    match paths.ensure_directories() {
        Err(PathError::Unwritable { path, .. }) => assert!(!path.is_empty()),
        other => panic!("expected an unwritable directory, got {other:?}"),
    }
}

#[test]
fn path_errors_explain_themselves() {
    let errors = vec![
        PathError::Unwritable {
            path: "a".to_owned(),
            detail: "b".to_owned(),
        },
        PathError::Escapes {
            path: "a".to_owned(),
            root: "b".to_owned(),
        },
        PathError::Absolute("a".to_owned()),
        PathError::Unresolvable {
            path: "a".to_owned(),
            detail: "b".to_owned(),
        },
        PathError::BadComponent {
            path: "a".to_owned(),
            component: "b".to_owned(),
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text:?}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
