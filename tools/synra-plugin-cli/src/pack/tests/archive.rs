use super::super::{artifact_names, pack_plugin, write_archive};
use super::{manifest, scratch, sign};

#[test]
fn a_packed_plugin_is_the_archive_the_installer_reads() {
    // ★ The property that matters is not "a file appeared": it is that `extract_tgz` — the code the registry install
    // runs — finds the three files at the depths it expects.
    let root = scratch("ok");
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
    .expect("it packs");
    let crate::run::Outcome::Archive { target, manifest, artifacts, signature, .. } = &outcome else {
        panic!("expected an archive outcome");
    };
    write_archive(target, manifest, artifacts, signature.as_deref()).expect("it writes");

    let destination = scratch("unpacked");
    let files = synra_registry::extract_tgz(
        &std::fs::read(target).expect("the archive"),
        &destination,
        Some("package"),
        synra_registry::Limits::default(),
    )
    .expect("the archive is what the installer reads");
    assert_eq!(files.len(), 3);
    assert!(destination.join("manifest.json").is_file());
    assert!(destination.join("plugin.wasm").is_file());
    assert!(destination.join("signature.json").is_file());
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&destination);
}

#[test]
fn packing_twice_produces_the_same_bytes() {
    // ★ A registry's digest is of the bytes it received. A pack that embedded the clock would make the same version
    // different on every machine, and every republish a new digest for unchanged content.
    let root = scratch("stable");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");

    let pack = |name: &str| {
        let target = root.join(name);
        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(target.clone()),
            index: None,
        registry: None,
        dry_run: false,
        })
        .expect("it packs");
        let crate::run::Outcome::Archive { manifest, artifacts, signature, .. } = &outcome else {
            panic!("expected an archive outcome");
        };
        write_archive(&target, manifest, artifacts, signature.as_deref()).expect("it writes");
        std::fs::read(target).expect("the archive")
    };
    assert_eq!(pack("one.tgz"), pack("two.tgz"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_missing_artifact_is_named_rather_than_packed_around() {
    let root = scratch("missing");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"])).expect("a manifest");

    let crate::run::Outcome::Reported { lines, failure, .. } = pack_plugin(&crate::args::PackArgs {
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
    assert!(lines.iter().any(|line| line.contains("plugin.wasm")), "{lines:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_archive_is_named_after_the_id_and_version() {
    let root = scratch("name");
    std::fs::write(root.join("manifest.json"), manifest("2.0.0", &[])).expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: None,
        index: None,
        registry: None,
        dry_run: false,
    })
    .expect("it packs");
    let crate::run::Outcome::Archive { target, .. } = outcome else {
        panic!("expected an archive outcome");
    };
    assert_eq!(target.file_name().and_then(|name| name.to_str()), Some("@acme-hello-2.0.0.tgz"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_package_that_fails_verification_is_not_packed() {
    // ★ Pack runs the checks `verify` runs. An empty artifact is refused by both, and the failure is a report rather
    // than a second implementation of the rule.
    let root = scratch("broken");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"])).expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), b"").expect("an empty artifact");

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: None,
        index: None,
        registry: None,
        dry_run: false,
    })
    .expect("the decision is a report, not an error");

    let crate::run::Outcome::Reported { lines, code, failure } = outcome else {
        panic!("expected a report");
    };
    assert_eq!(code, 1);
    assert!(failure);
    assert!(lines.iter().any(|line| line.contains("wasm")), "{lines:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_artifact_list_is_the_manifests() {
    let manifest = synra_plugin_api::Manifest::from_json(&manifest("1.0.0", &[])).expect("a manifest");
    assert_eq!(artifact_names(&manifest), ["plugin.wasm"]);
}
