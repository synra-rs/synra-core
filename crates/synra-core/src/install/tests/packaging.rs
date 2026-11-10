use super::super::package_directory;
use super::{scratch, write_source};

#[test]
fn packaging_an_installed_plugin_leaves_the_unpacked_ui_out() {
    // ★ `ui.zip` is the artifact; `ui/` is this device's rendering of it. Shipping both would send the same files
    // twice and give the installer two sources for one directory.
    let root = scratch("ui");
    let source = root.join("source");
    write_source(&source);
    std::fs::create_dir_all(source.join("ui")).expect("a ui directory");
    std::fs::write(source.join("ui").join("index.html"), b"<html></html>").expect("a ui file");
    std::fs::write(source.join("ui.zip"), b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").expect("a ui zip");
    let archive = root.join("hello.synra");
    package_directory(&source, &archive).expect("the package is written");

    let mut zip = zip::ZipArchive::new(std::fs::File::open(&archive).expect("the archive")).expect("a zip");
    let mut names: Vec<String> = (0..zip.len())
        .map(|index| zip.by_index(index).expect("an entry").name().to_owned())
        .collect();
    names.sort();

    assert!(names.contains(&"ui.zip".to_owned()), "{names:?}");
    assert!(!names.iter().any(|name| name.starts_with("ui/")), "the unpacked UI was packaged: {names:?}");
    assert!(names.contains(&"manifest.json".to_owned()));
    let _ = std::fs::remove_dir_all(&root);
}
