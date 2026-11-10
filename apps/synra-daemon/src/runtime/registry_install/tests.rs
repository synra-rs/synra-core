use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use synra_plugin_host::Backend;

use super::*;

/// A registry that answers with bytes this test wrote.
struct Fake {
    packument: Vec<u8>,
    tarball: Vec<u8>,
}

impl Fetch for Fake {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        // The scoped name is percent-encoded in the URL the client builds, so the fake matches the path's tail rather
        // than the spelling of the package.
        if url.contains("acme/hello") && !url.ends_with(".tgz") {
            Ok(self.packument.clone())
        }
        else if url.ends_with(".tgz") {
            Ok(self.tarball.clone())
        }
        else {
            Err(format!("the fake registry has nothing at {url}"))
        }
    }
}

/// A scratch root, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-registry-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn staging(&self) -> PathBuf {
        self.0.join("staging")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn database() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    db
}

fn backend() -> Backend {
    Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new()))
}

/// A tarball with `package/manifest.json` and `package/plugin.wasm`, as a registry publishes one.
fn tarball() -> Vec<u8> {
    let manifest = format!(
        r#"{{"id": "@acme/hello", "version": "1.0.0", "title": "Hello",
                "publisher": {{"id": "@acme"}}, "sdk": {{"min": "0.1.0"}},
                "wit": "{}", "capabilities": [{{"cap": "log:*"}}],
                "runtime": {{"headless": {{"artifact": "plugin.wasm", "stateful": false}}}}}}"#,
        synra_plugin_host::host_world()
    );
    let mut builder = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("package/manifest.json", manifest.into_bytes()),
        (
            "package/plugin.wasm",
            synra_testkit::component::inert_component().expect("a valid component"),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, bytes.as_slice()).expect("a tar entry");
    }
    let tar = builder.into_inner().expect("the tar ends");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar).expect("the gzip body");
    encoder.finish().expect("the gzip ends")
}

fn packument(integrity: Option<&str>) -> Vec<u8> {
    let dist = match integrity {
        Some(integrity) => format!(
            r#"{{"tarball":"https://registry.test/@acme/hello/-/hello-1.0.0.tgz","integrity":"{integrity}"}}"#
        ),
        None => r#"{"tarball":"https://registry.test/@acme/hello/-/hello-1.0.0.tgz"}"#.to_owned(),
    };
    serde_json::json!({
        "name": "@acme/hello",
        "dist-tags": { "latest": "1.0.0" },
        "versions": { "1.0.0": { "name": "@acme/hello", "version": "1.0.0", "dist": serde_json::from_str::<serde_json::Value>(&dist).expect("JSON") } }
    })
    .to_string()
    .into_bytes()
}

fn integrity_of(bytes: &[u8]) -> String {
    synra_core::ObjectDigest::of(bytes).as_sri().to_string()
}

#[test]
fn a_registry_package_installs_from_the_bytes_it_declares() {
    let scratch = Scratch::new("install");
    let bytes = tarball();
    let declared = integrity_of(&bytes);
    let fake = Fake { packument: packument(Some(&declared)), tarball: bytes };
    let plugins = scratch.0.join("plugins");

    let installed = install_from_registry(
        &mut database(),
        &backend(),
        &plugins,
        &scratch.staging(),
        &fake,
        "@acme/hello",
        None,
        1_000,
    )
    .expect("installs");

    assert_eq!(installed.plugin_id, "@acme/hello");
    assert_eq!(installed.version, "1.0.0");
    assert!(installed.path.join("plugin.wasm").is_file());
    // The unpacked copy is not left behind: a second copy nothing reads is what makes a data directory grow.
    assert!(
        !scratch.staging().exists() || std::fs::read_dir(scratch.staging()).expect("staging").next().is_none(),
        "the unpacked package was left in the staging directory"
    );
}

#[test]
fn bytes_that_do_not_match_the_declared_integrity_are_refused() {
    let scratch = Scratch::new("mismatch");
    let wrong = integrity_of(b"something else");
    let bytes = tarball();
    let fake = Fake { packument: packument(Some(&wrong)), tarball: bytes };

    let refusal = install_from_registry(
        &mut database(),
        &backend(),
        &scratch.0.join("plugins"),
        &scratch.staging(),
        &fake,
        "@acme/hello",
        None,
        1_000,
    )
    .expect_err("a mismatch is refused");
    assert_eq!(refusal.code, ErrorCode::IntegrityMismatch, "{refusal:?}");
}

#[test]
fn a_document_without_integrity_installs_nothing() {
    let scratch = Scratch::new("no-integrity");
    let bytes = tarball();
    let fake = Fake { packument: packument(None), tarball: bytes };

    let refusal = install_from_registry(
        &mut database(),
        &backend(),
        &scratch.0.join("plugins"),
        &scratch.staging(),
        &fake,
        "@acme/hello",
        None,
        1_000,
    )
    .expect_err("nothing to verify against");
    assert_eq!(refusal.code, ErrorCode::Unsupported, "{refusal:?}");
    assert!(refusal.message.contains("no integrity"), "{refusal:?}");
}

#[test]
fn an_unknown_version_is_named_rather_than_guessed() {
    let scratch = Scratch::new("version");
    let bytes = tarball();
    let fake = Fake { packument: packument(Some("sha256-aaaa")), tarball: bytes };

    let refusal = install_from_registry(
        &mut database(),
        &backend(),
        &scratch.0.join("plugins"),
        &scratch.staging(),
        &fake,
        "@acme/hello",
        Some("2.0.0"),
        1_000,
    )
    .expect_err("a version that is not there is refused");
    assert_eq!(refusal.code, ErrorCode::Unsupported, "{refusal:?}");
    assert!(refusal.message.contains("2.0.0"), "{refusal:?}");
}

#[test]
fn a_registry_that_answers_nothing_is_reported_as_offline() {
    struct Silent;
    impl Fetch for Silent {
        fn get(&self, _: &str) -> Result<Vec<u8>, String> {
            Err("connection refused".to_owned())
        }
    }

    let scratch = Scratch::new("offline");
    let refusal = install_from_registry(
        &mut database(),
        &backend(),
        &scratch.0.join("plugins"),
        &scratch.staging(),
        &Silent,
        "@acme/hello",
        None,
        1_000,
    )
    .expect_err("no mirror answered");
    assert_eq!(refusal.code, ErrorCode::DeviceOffline, "{refusal:?}");
}
