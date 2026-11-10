use super::*;

#[test]
fn ui_archives_entries_limits_and_links_are_checked_by_the_actual_command() {
    use std::io::Write as _;
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "plugin.wasm", &[]);
    std::fs::write(root.path().join("plugin.wasm"), fixture::component()).unwrap();
    let bundle = root.path().join("frontend.zip");
    let write_zip = |path: &Path, link: bool| {
        let mut writer = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        writer
            .start_file("start.html", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"hello").unwrap();
        if link {
            writer
                .add_symlink(
                    "escape",
                    "../private",
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
        }
        writer.finish().unwrap();
    };
    write_zip(&bundle, false);
    let manifest_path = root.path().join("manifest.json");
    let mut source: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    source
        .get_mut("runtime")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "ui".to_owned(),
            serde_json::json!({ "artifact": "frontend.zip", "entry": "start.html" }),
        );
    std::fs::write(&manifest_path, source.to_string()).unwrap();
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    for entry in ["missing.html", "../plugin.wasm"] {
        *source.pointer_mut("/runtime/ui/entry").unwrap() = serde_json::json!(entry);
        std::fs::write(&manifest_path, source.to_string()).unwrap();
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
    *source.pointer_mut("/runtime/ui/entry").unwrap() = serde_json::json!("start.html");
    std::fs::write(&manifest_path, source.to_string()).unwrap();
    std::fs::File::create(&bundle)
        .unwrap()
        .set_len(synra_plugin_ui::artifact::MAX_ARCHIVE_BYTES + 1)
        .unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("limit"), "{report}");
    write_zip(&bundle, true);
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    let outside = tempfile::tempdir().unwrap();
    write_zip(&outside.path().join("ui.zip"), false);
    directory_link(outside.path(), &root.path().join("escape"));
    *source.pointer_mut("/runtime/ui/artifact").unwrap() = serde_json::json!("escape/ui.zip");
    std::fs::write(&manifest_path, source.to_string()).unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("outside"), "{report}");
}

#[cfg(windows)]
fn directory_link(source: &Path, target: &Path) {
    // A junction requires no administrator/developer-mode symlink privilege.
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(target)
        .arg(source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn directory_link(source: &Path, target: &Path) {
    std::os::unix::fs::symlink(source, target).unwrap();
}
