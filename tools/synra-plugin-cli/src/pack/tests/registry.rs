use super::super::pack_plugin;
use super::{manifest, scratch};

#[test]
fn a_registry_flag_is_checked_and_shown_as_the_command_to_run() {
    // ★ Nothing is uploaded. The flag answers "is this a registry the installing side could read?" and turns the
    // answer into the command an author would run, so the address is stated once instead of retyped.
    let root = scratch("registry");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: Some(root.join("out.tgz")),
        index: None,
        registry: Some("https://r.example".to_owned()),
        dry_run: false,
    })
    .expect("it packs");
    let crate::run::Outcome::Archive { lines, .. } = outcome else {
        panic!("expected an archive outcome");
    };

    assert!(
        lines.iter().any(|line| line.contains("npm publish --registry https://r.example")),
        "{lines:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_registry_that_could_not_be_read_is_refused() {
    let root = scratch("bad-registry");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");

    for (url, acceptable) in [
        ("https://r.example", true),
        ("https://r.example/", true),
        ("http://127.0.0.1:4873", true),
        ("http://r.example", false),
        ("ftp://r.example", false),
        ("https://r.example/path", false),
        ("https://", false),
    ] {
        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            index: None,
            registry: Some(url.to_owned()),
            dry_run: true,
        })
        .expect("a decision");
        let accepted = matches!(&outcome, crate::run::Outcome::Archive { .. });
        assert_eq!(accepted, acceptable, "for {url}: {outcome:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}
