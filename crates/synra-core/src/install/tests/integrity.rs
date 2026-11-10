use std::io::Write as _;

use synra_plugin_host::verify::HostFacts;
use crate::transfer::ObjectDigest;
use super::super::{from_package, unpack_published_tarball};
use super::{backend, database, manifest, scratch};

#[test]
fn a_package_that_escapes_its_directory_is_refused_before_anything_is_installed() {
    // ★ The archive's own rules, not the installer's: an entry named `../escape.txt` is a package asking to write
    // outside the directory it is unpacked into. `unpack` refuses it and removes what it wrote, and the installer is
    // never reached.
    let root = scratch("escape");
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).expect("the plugins directory");
    let archive = root.join("evil.synra");
    {
        let file = std::fs::File::create(&archive).expect("a file");
        let mut writer = zip::ZipWriter::new(file);
        for (name, bytes) in [
            ("manifest.json", manifest().into_bytes()),
            ("../escape.txt", b"outside".to_vec()),
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .expect("an entry");
            writer.write_all(&bytes).expect("the bytes");
        }
        writer.finish().expect("a finished archive");
    }

    let mut db = database();
    let refused = from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
        .expect_err("the entry escapes");

    assert_eq!(refused.stage, "archive", "{}", refused.reason);
    assert!(!root.join("escape.txt").exists(), "the entry was written outside the package");
    assert!(
        !plugins.join("@acme/hello").exists(),
        "a refused package left an installed plugin behind"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_package_with_no_manifest_is_refused_by_the_installer() {
    let root = scratch("no-manifest");
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).expect("the plugins directory");
    let archive = root.join("empty.synra");
    {
        let file = std::fs::File::create(&archive).expect("a file");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("plugin.wasm", zip::write::SimpleFileOptions::default())
            .expect("an entry");
        writer.write_all(b"\0asm\x01\0\0\0").expect("the bytes");
        writer.finish().expect("a finished archive");
    }

    let mut db = database();
    let refused = from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
        .expect_err("there is no manifest");

    assert_eq!(refused.stage, "read", "{}", refused.reason);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_published_tarball_without_a_digest_is_refused_before_anything_is_written() {
    // ★ "No integrity string" is not "skip the check": there is nothing to compare the bytes against. It is refused
    // with the same `IntegrityMismatch` code a wrong digest gets, because both mean the bytes are not vouched for.
    let root = scratch("tarball-no-integrity");
    let refusal = unpack_published_tarball(b"not even a tarball", None, "hello.tgz", &root, 1)
        .expect_err("bytes nothing vouches for are not opened");
    assert_eq!(refusal.stage, "integrity");
    assert_eq!(refusal.code(), synra_protocol::error::ErrorCode::IntegrityMismatch);
    assert!(!root.exists(), "nothing should have been created: {}", root.display());
}

#[test]
fn a_published_tarball_whose_bytes_do_not_match_its_digest_is_refused() {
    let root = scratch("tarball-mismatch");
    let declared = ObjectDigest::of(b"the bytes the publisher signed").as_sri().to_string();
    let refusal = unpack_published_tarball(b"other bytes", Some(&declared), "hello.tgz", &root, 1)
        .expect_err("a mismatch is not unpacked");
    assert_eq!(refusal.stage, "integrity");
    assert!(refusal.reason.contains("digest") || refusal.reason.contains("integrity"), "{}", refusal.reason);
    assert!(!root.exists(), "nothing should have been created: {}", root.display());
}
