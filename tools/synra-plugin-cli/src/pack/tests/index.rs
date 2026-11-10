use super::super::{merge_index, pack_plugin};
use super::{manifest, scratch, sign};

#[test]
fn a_static_index_is_written_beside_the_archive() {
    // ★ The author's half of static publishing: one document per package, at the path a `static:` registry reads, with
    // the tarball URL and the key that signed it. A hand-edited index is a second description of the same pack.
    let root = scratch("index");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");
    sign(&root);

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: Some(root.join("out.tgz")),
        index: Some("https://static.example.com/plugins".to_owned()),
        registry: None,
        dry_run: false,
    })
    .expect("it packs");
    let executed = crate::execute::execute(&outcome, false);
    assert_eq!(executed.code, 0);

    let index_path = root.join("@acme").join("hello.json");
    assert!(index_path.is_file(), "the index is written at the id's path");
    let index = synra_registry::parse_static_index(
        &std::fs::read_to_string(&index_path).expect("the index"),
    )
    .expect("the index parses");
    let latest = index.document.latest().expect("a latest");
    assert_eq!(latest.version, "1.2.3");
    assert_eq!(
        latest.dist.tarball,
        "https://static.example.com/plugins/out.tgz"
    );
    assert!(
        index.publishers.contains_key("acme"),
        "the index names the key that signed it"
    );
    assert_eq!(latest.synra.as_ref().expect("the manifest").title, "Hello");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_unsigned_package_writes_an_index_with_no_publisher() {
    let root = scratch("index-unsigned");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: Some(root.join("out.tgz")),
        index: Some("https://static.example.com/plugins".to_owned()),
        registry: None,
        dry_run: false,
    })
    .expect("it packs");
    let _ = crate::execute::execute(&outcome, false);

    let index = synra_registry::parse_static_index(
        &std::fs::read_to_string(root.join("@acme").join("hello.json")).expect("the index"),
    )
    .expect("the index parses");
    assert!(index.publishers.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_second_version_is_added_to_the_index() {
    // ★ The index is the package's history. Re-packing 1.3.0 must not drop 1.2.0: an install that asks for the older
    // version still has to find it.
    let root = scratch("index-history");
    let pack = |version: &str, out: &str| {
        std::fs::write(root.join("manifest.json"), manifest(version, &["log:*"]))
            .expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
            .expect("an artifact");
        sign(&root);
        let outcome = pack_plugin(&crate::args::PackArgs {
            dir: root.clone(),
            out: Some(root.join(out)),
            index: Some("https://static.example.com/plugins".to_owned()),
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let executed = crate::execute::execute(&outcome, false);
        assert_eq!(executed.code, 0);
    };
    pack("1.2.3", "one.tgz");
    pack("1.3.0", "two.tgz");

    let index = synra_registry::parse_static_index(
        &std::fs::read_to_string(root.join("@acme").join("hello.json")).expect("the index"),
    )
    .expect("the index parses");
    assert_eq!(index.document.versions.len(), 2);
    assert_eq!(index.document.latest().expect("a latest").version, "1.3.0");
    assert_eq!(
        index.document.at("1.2.3").expect("the old version").dist.tarball,
        "https://static.example.com/plugins/one.tgz"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn merging_replaces_a_version_rather_than_listing_it_twice() {
    let manifest_value: serde_json::Value =
        serde_json::from_str(&manifest("1.0.0", &["log:*"])).expect("a manifest document");
    let first = merge_index(
        None,
        "@acme/hello",
        "1.0.0",
        "https://static.example.com/one.tgz",
        &manifest_value,
        None,
    )
    .expect("an index");
    let second = merge_index(
        Some(&first),
        "@acme/hello",
        "1.0.0",
        "https://static.example.com/two.tgz",
        &manifest_value,
        None,
    )
    .expect("an index");

    let index = synra_registry::parse_static_index(&second).expect("it parses");
    assert_eq!(index.document.versions.len(), 1);
    assert_eq!(
        index.document.at("1.0.0").expect("the version").dist.tarball,
        "https://static.example.com/two.tgz"
    );
}

#[test]
fn an_index_this_tool_cannot_read_is_not_overwritten() {
    let refused = merge_index(
        Some("not json"),
        "@acme/hello",
        "1.0.0",
        "https://static.example.com/one.tgz",
        &serde_json::json!({}),
        None,
    )
    .expect_err("it is not an index");
    assert!(refused.contains("not JSON"), "{refused}");
}

#[test]
fn an_index_without_a_base_names_the_tarball_relatively() {
    // ★ The author does not know the bucket's public URL at pack time; the client resolves the name against the
    // index's own URL, so publishing is "upload these two files".
    let root = scratch("index-relative");
    std::fs::write(root.join("manifest.json"), manifest("1.2.3", &["log:*"]))
        .expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");

    let outcome = pack_plugin(&crate::args::PackArgs {
        dir: root.clone(),
        out: Some(root.join("one.tgz")),
        index: Some(String::new()),
        registry: None,
        dry_run: false,
    })
    .expect("it packs");
    let _ = crate::execute::execute(&outcome, false);

    let index = synra_registry::parse_static_index(
        &std::fs::read_to_string(root.join("@acme").join("hello.json")).expect("the index"),
    )
    .expect("the index parses");
    assert_eq!(
        index.document.latest().expect("a latest").dist.tarball,
        "one.tgz"
    );
    let _ = std::fs::remove_dir_all(&root);
}
