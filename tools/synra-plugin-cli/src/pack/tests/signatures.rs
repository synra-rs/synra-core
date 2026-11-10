use super::super::pack_plugin;
use super::{manifest, scratch, sign};

#[test]
fn a_signature_that_covers_the_package_is_kept() {
    let root = scratch("signed");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");
    sign(&root);

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: Some(root.join("out.tgz")),
        index: None,
        registry: None,
        dry_run: false,
    })
    .expect("a signed package packs");
    let crate::run::Outcome::Archive { signature, .. } = &outcome else {
        panic!("expected an archive outcome");
    };
    assert!(signature.is_some(), "the signature travels with the archive");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_tampered_artifact_after_signing_is_refused() {
    // ★ The whole point of checking at the publish boundary: the author signed one build, then rebuilt — the archive
    // must not carry a signature that says "trust this" about bytes it does not cover.
    let root = scratch("tampered");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");
    sign(&root);
    std::fs::write(
        root.join("plugin.wasm"),
        [crate::test_component::component(), vec![0, 2, 1, b'x']].concat(),
    )
    .expect("a changed artifact");

    let crate::run::Outcome::Reported { lines, failure, .. } =
        pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: None,
            index: None,
            registry: None,
            dry_run: false,
        })
        .expect("a report")
    else {
        panic!("expected a report");
    };

    assert!(failure);
    assert!(lines.iter().any(|line| line.contains("signature")), "{lines:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_changed_manifest_after_signing_is_refused() {
    let root = scratch("re-manifest");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");
    sign(&root);
    // Same files, one more permission: the manifest digest the signature covers no longer names this manifest.
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*", "device:send:*"]))
        .expect("a changed manifest");

    let crate::run::Outcome::Reported { failure, .. } = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: None,
        index: None,
        registry: None,
        dry_run: false,
    })
    .expect("a report") else {
        panic!("expected a report");
    };

    assert!(failure);
    let _ = std::fs::remove_dir_all(&root);
}
