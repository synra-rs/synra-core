use super::{local_tarball, publish_plugin, validate};

fn manifest(version: &str) -> String {
    serde_json::json!({
        "id": "@acme/hello",
        "version": version,
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": synra_plugin_host::host_world(),
        "capabilities": [{ "cap": "log:*" }],
        "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
    })
    .to_string()
}

fn scratch(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("synra-publish-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a directory");
    path
}

/// Packs the fixture the way an author would, and returns the index path.
fn packed(root: &std::path::Path, version: &str) -> std::path::PathBuf {
    std::fs::write(root.join("manifest.json"), manifest(version)).expect("a manifest");
    std::fs::write(root.join("plugin.wasm"), crate::test_component::component())
        .expect("an artifact");
    let key = crate::sign::SigningKeyFile::generate().expect("a key");
    let content = crate::sign::SignedContent::read(root).expect("what a signature covers");
    std::fs::write(
        root.join("signature.json"),
        key.sign(&content, "2026-01-01T00:00:00Z"),
    )
    .expect("a signature");
    let outcome = crate::pack::pack_plugin(&crate::args::PackArgs {
        dir: root.to_path_buf(),
        out: None,
        index: Some(String::new()),
        registry: None,
        dry_run: false,
    })
    .expect("it packs");
    let _ = crate::execute::execute(&outcome, false);
    root.join("dist").join("@acme").join("hello.json")
}

#[test]
fn a_packed_index_passes_the_check() {
    // ★ The property is that `publish` reads the files the way an install would: index → tarball → unpack → signature.
    let root = scratch("ok");
    let index = packed(&root, "1.0.0");

    let outcome = publish_plugin(&crate::args::PublishArgs { index, base: None, verify: false });

    let crate::run::Outcome::Reported { lines, code, .. } = outcome else {
        panic!("expected a report");
    };
    assert_eq!(code, 0, "{lines:?}");
    assert!(lines.iter().any(|line| line.contains("signed")), "{lines:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_missing_tarball_is_named() {
    let root = scratch("missing");
    let index = packed(&root, "1.0.0");
    std::fs::remove_file(root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz"))
        .expect("the tarball is gone");

    let outcome = publish_plugin(&crate::args::PublishArgs { index, base: None, verify: false });
    let crate::run::Outcome::Reported { lines, failure, .. } = outcome else {
        panic!("expected a report");
    };
    assert!(failure);
    assert!(lines.iter().any(|line| line.contains("1.0.0.tgz")), "{lines:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_signature_that_no_longer_covers_the_tarball_is_refused() {
    let root = scratch("tampered");
    let index = packed(&root, "1.0.0");
    let tarball = root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz");
    // The manifest gains a permission after it was signed: the archive is well formed, the signature is genuine, and
    // it no longer covers what shipped.
    let mut changed: serde_json::Value =
        serde_json::from_str(&manifest("1.0.0")).expect("a manifest document");
    changed["capabilities"] = serde_json::json!([{ "cap": "log:*" }, { "cap": "device:send:*" }]);
    std::fs::write(root.join("manifest.json"), changed.to_string()).expect("the changed manifest");
    crate::pack::write_archive(
        &tarball,
        &root.join("manifest.json"),
        &["plugin.wasm".to_owned()],
        Some(&root.join("signature.json")),
    )
    .expect("the changed archive");

    let outcome = publish_plugin(&crate::args::PublishArgs { index, base: None, verify: false });
    let crate::run::Outcome::Reported { lines, failure, .. } = outcome else {
        panic!("expected a report");
    };
    assert!(failure);
    assert!(
        lines.iter().any(|line| line.contains("signature")),
        "{lines:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn verify_reads_the_bucket_back() {
    // ★ The question is not "did the upload succeed" but "does the bucket serve what was packed": the remote index is
    // parsed by the installing side's parser and the tarballs are compared by digest.
    use std::io::{BufRead, BufReader, Write as _};

    let root = scratch("verify");
    let index_path = packed(&root, "1.0.0");
    let index_bytes = std::fs::read(&index_path).expect("the index");
    let tarball_bytes = std::fs::read(root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz"))
        .expect("the tarball");
    let base = serve(index_bytes, tarball_bytes);

    let outcome = publish_plugin(&crate::args::PublishArgs {
        index: index_path,
        base: Some(base),
        verify: true,
    });
    let crate::run::Outcome::Reported { lines, code, .. } = outcome else {
        panic!("expected a report");
    };
    assert_eq!(code, 0, "{lines:?}");
    assert!(lines.iter().any(|line| line.contains("digest matches")), "{lines:?}");
    let _ = std::fs::remove_dir_all(&root);

    fn serve(index: Vec<u8>, tarball: Vec<u8>) -> String {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("a clone"));
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                        break;
                    }
                }
                let body = if line.contains(".json") { index.clone() } else { tarball.clone() };
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        base
    }
}

#[test]
fn verify_refuses_a_bucket_that_serves_different_bytes() {
    use std::io::{BufRead, BufReader, Write as _};

    let root = scratch("verify-tampered");
    let index_path = packed(&root, "1.0.0");
    let index_bytes = std::fs::read(&index_path).expect("the index");
    let mut tarball_bytes = std::fs::read(root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz"))
        .expect("the tarball");
    if let Some(byte) = tarball_bytes.last_mut() {
        *byte ^= 0xFF;
    }

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port");
    let base = format!("http://{}", listener.local_addr().expect("an address"));
    std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut reader = BufReader::new(stream.try_clone().expect("a clone"));
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                    break;
                }
            }
            let body = if line.contains(".json") { index_bytes.clone() } else { tarball_bytes.clone() };
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });

    let outcome = publish_plugin(&crate::args::PublishArgs {
        index: index_path,
        base: Some(base),
        verify: true,
    });
    let crate::run::Outcome::Reported { lines, failure, .. } = outcome else {
        panic!("expected a report");
    };
    assert!(failure);
    assert!(
        lines.iter().any(|line| line.contains("different bytes")),
        "{lines:?}"
    );
    // ★ The second half of the answer: which file, and where it goes.
    assert!(
        lines.iter().any(|line| line.contains("re-upload") && line.contains("1.0.0")),
        "{lines:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_absolute_tarball_needs_the_base_to_be_found_locally() {
    let root = scratch("base");
    assert!(validate(&crate::args::PublishArgs {
        index: root.join("missing.json"),
        base: None,
        verify: false,
    })
    .is_err());
    assert_eq!(
        local_tarball(&root, Some("https://bucket.example/plugins"), "https://bucket.example/plugins/x.tgz"),
        Ok(root.join("x.tgz"))
    );
    assert!(local_tarball(&root, None, "https://bucket.example/x.tgz").is_err());
    assert!(local_tarball(&root, None, "../x.tgz").is_err());
}
