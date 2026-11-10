use super::*;

#[test]
fn installing_a_ui_plugin_unpacks_its_bundle_beside_the_artifact() {
    // ★ The step this asserts is the reason a UI plugin's page can be served at all: the zip is verified like any other
    // artifact, and then written out where the `synra-plugin://` handler will look — before the rename, so a bundle that
    // cannot be unpacked is a failed install rather than an installed plugin with a blank window.
    let dir = TempDir::new("install-ui");
    let ui = ui_zip(&[("index.html", b"<!doctype html>")]);
    let source = package(
        dir.path(),
        "source",
        &ui_manifest(&["log:*"], "plugin.wasm", "ui.zip"),
        &[("plugin.wasm", wasm()), ("ui.zip", &ui)],
    );
    let mut db = database();

    let installed =
        from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect("the package is installed");

    assert!(
        installed.path.join("ui").join("index.html").is_file(),
        "the page is unpacked under ui/: {:?}",
        installed.path
    );
}
