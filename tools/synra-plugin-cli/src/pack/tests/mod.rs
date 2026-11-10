mod archive;
mod index;
mod registry;
mod signatures;

fn manifest(version: &str, capabilities: &[&str]) -> String {
    let declared: Vec<serde_json::Value> =
        capabilities.iter().map(|cap| serde_json::json!({ "cap": cap })).collect();
    serde_json::json!({
        "id": "@acme/hello",
        "version": version,
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": synra_plugin_host::host_world(),
        "capabilities": declared,
        "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
    })
    .to_string()
}

fn scratch(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("synra-pack-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a directory");
    path
}

/// Signs the package the way the `sign` command does, so the tests exercise the same document format.
fn sign(root: &std::path::Path) {
    let key = crate::sign::SigningKeyFile::generate().expect("a key");
    let content = crate::sign::SignedContent::read(root).expect("what a signature covers");
    let document = key.sign(&content, "2026-01-01T00:00:00Z");
    std::fs::write(root.join("signature.json"), document).expect("a signature");
}
