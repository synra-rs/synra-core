//! The actual command must inspect component contracts and enforce manifest coverage.

// Assertions and bounded child-process control retain local failure diagnostics.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Seek as _};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "support/component.rs"]
mod fixture;

fn manifest(root: &Path, artifact: &str, capabilities: &[&str]) {
    std::fs::write(root.join("manifest.json"), serde_json::json!({
        "id": "@acme/verify", "version": "1.0.0", "title": "Verify",
        "publisher": { "id": "acme" }, "sdk": { "min": "0.1.0" },
        "wit": synra_plugin_host::host_world(),
        "capabilities": capabilities.iter().map(|cap| serde_json::json!({ "cap": cap })).collect::<Vec<_>>(),
        "runtime": { "headless": { "artifact": artifact, "stateful": false } }
    }).to_string()).unwrap();
}

fn verify(root: &Path) -> (ExitStatus, serde_json::Value) {
    let mut log = tempfile::tempfile().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_synra-plugin"))
        .args(["verify", "--json", "--dir"])
        .arg(root)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("verify exceeded its process deadline");
        }
        // Bounded process observation; no timing-dependent product assertion.
        std::thread::sleep(Duration::from_millis(20));
    };
    log.rewind().unwrap();
    let mut text = String::new();
    log.read_to_string(&mut text).unwrap();
    let report = serde_json::from_str(&text).unwrap_or_else(|error| panic!("{error}: {text}"));
    (status, report)
}

#[test]
fn malformed_bytes_and_core_modules_fail_through_the_command() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "plugin.wasm", &[]);
    for bytes in [
        b"not wasm".as_slice(),
        b"\0asm\x01\0\0\0",
        b"\0asm\x0d\0\x01\0",
    ] {
        std::fs::write(root.path().join("plugin.wasm"), bytes).unwrap();
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
}

#[test]
fn a_real_component_is_read_from_the_manifest_path_and_its_actual_imports_are_checked() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("dist")).unwrap();
    std::fs::write(
        root.path().join("dist/custom.wasm"),
        fixture::from_contract(fixture::CONTRACT),
    )
    .unwrap();
    // A stale conventional output cannot replace the manifest's declared component.
    std::fs::write(root.path().join("plugin.wasm"), b"stale").unwrap();
    let capabilities = synra_plugin_host::host_surface::CAPABILITIES;
    manifest(root.path(), "dist/custom.wasm", capabilities);
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    assert!(!report.to_string().contains("warn"), "{report}");
    let scoped: Vec<&str> = capabilities
        .iter()
        .map(|cap| match *cap {
            "network:fetch:*" => "network:fetch:api.github.com:GET",
            "log:*" => "log:info",
            "event:emit:*" => "event:emit:_plugin.@acme/verify.ready",
            cap => cap,
        })
        .collect();
    manifest(root.path(), "dist/custom.wasm", &scoped);
    let path = root.path().join("manifest.json");
    let mut declaration: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    declaration.as_object_mut().unwrap().insert(
        "network".to_owned(),
        serde_json::json!({ "outbound": [{ "host": "api.github.com", "methods": ["GET"] }] }),
    );
    declaration.as_object_mut().unwrap().insert(
        "events".to_owned(),
        serde_json::json!([{ "name": "_plugin.@acme/verify.ready", "payload": {
            "type": "object", "properties": {}, "additionalProperties": false
        }}]),
    );
    std::fs::write(path, declaration.to_string()).unwrap();
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    let without_open: Vec<&str> = capabilities
        .iter()
        .copied()
        .filter(|cap| *cap != "platform:open-url")
        .collect();
    manifest(root.path(), "dist/custom.wasm", &without_open);
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(
        report
            .to_string()
            .contains("synra:plugin/host#platform-open-url"),
        "{report}"
    );
    assert!(
        report
            .to_string()
            .contains("not covered by manifest capabilities"),
        "{report}"
    );
}

#[test]
fn a_verified_zero_import_component_passes_without_an_unread_warning() {
    let root = tempfile::tempdir().unwrap();
    let source = fixture::CONTRACT.replace("    import host;", "");
    assert_ne!(source, fixture::CONTRACT);
    std::fs::write(
        root.path().join("plugin.wasm"),
        fixture::from_contract(&source),
    )
    .unwrap();
    manifest(root.path(), "plugin.wasm", &[]);
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    assert!(report.to_string().contains("0 actual import"), "{report}");
}

#[test]
fn actual_import_versions_resources_and_wrong_host_or_guest_signatures_fail() {
    let root = tempfile::tempdir().unwrap();
    manifest(
        root.path(),
        "plugin.wasm",
        synra_plugin_host::host_surface::CAPABILITIES,
    );
    for source in [
        fixture::CONTRACT.replace("@1.0.0", "@9.0.0"),
        fixture::CONTRACT.replace(
            "platform-open-url: func(url: string) -> outcome;",
            "platform-open-url: func(url: u32) -> outcome;",
        ),
        fixture::CONTRACT.replace(
            "activate: func(config-json: string) -> outcome;",
            "activate: func(config-json: u32) -> outcome;",
        ),
        fixture::CONTRACT.replace(
            "interface host {",
            "interface host {\n    resource forbidden;",
        ),
        fixture::CONTRACT.replace("    export actions;", ""),
    ] {
        assert_ne!(source, fixture::CONTRACT);
        std::fs::write(
            root.path().join("plugin.wasm"),
            fixture::from_contract(&source),
        )
        .unwrap();
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
}

#[test]
fn invalid_nested_function_bodies_do_not_pass_on_interface_metadata_alone() {
    let root = tempfile::tempdir().unwrap();
    manifest(
        root.path(),
        "plugin.wasm",
        synra_plugin_host::host_surface::CAPABILITIES,
    );
    let mut bytes = fixture::component();
    let range = wasmparser::Parser::new(0)
        .parse_all(&bytes)
        .find_map(|payload| match payload.unwrap() {
            wasmparser::Payload::CodeSectionEntry(body) => Some(body.range()),
            _ => None,
        })
        .unwrap();
    let instruction = bytes.get_mut(range.end.checked_sub(2).unwrap()).unwrap();
    assert_eq!(
        *instruction, 0,
        "the dummy body's final instruction must be unreachable"
    );
    *instruction = 0xff;
    std::fs::write(root.path().join("plugin.wasm"), bytes).unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("opcode"), "{report}");
}

#[test]
fn missing_escaping_and_oversized_artifacts_cannot_hide_behind_a_valid_default_file() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("plugin.wasm"), fixture::component()).unwrap();
    for artifact in ["missing.wasm", "../plugin.wasm", ""] {
        manifest(root.path(), artifact, &[]);
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
    let oversized = root.path().join("large.wasm");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(synra_plugin_cli::MAX_WASM_BYTES + 1)
        .unwrap();
    manifest(root.path(), "large.wasm", &[]);
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("limit"), "{report}");
}

#[test]
fn ui_entry_paths_sizes_and_directory_links_are_checked_in_the_declared_bundle() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "plugin.wasm", &[]);
    std::fs::write(root.path().join("plugin.wasm"), fixture::component()).unwrap();
    let bundle = root.path().join("frontend");
    std::fs::create_dir(&bundle).unwrap();
    std::fs::write(bundle.join("start.html"), "hello").unwrap();
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
            serde_json::json!({ "artifact": "frontend", "entry": "start.html" }),
        );
    std::fs::write(&manifest_path, source.to_string()).unwrap();
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    *source.pointer_mut("/runtime/ui/entry").unwrap() = serde_json::json!("missing.html");
    std::fs::write(&manifest_path, source.to_string()).unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    *source.pointer_mut("/runtime/ui/entry").unwrap() = serde_json::json!("start.html");
    std::fs::write(&manifest_path, source.to_string()).unwrap();
    let large = bundle.join("large.bin");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(synra_plugin_cli::MAX_UI_BYTES + 1)
        .unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("limits"), "{report}");
    std::fs::remove_file(large).unwrap();
    let private = root.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::write(private.join("secret"), "outside the UI").unwrap();
    directory_link(&private, &bundle.join("escape"));
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("outside the UI"), "{report}");
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

#[test]
fn oversized_manifests_fail_before_json_or_artifact_inspection() {
    let root = tempfile::tempdir().unwrap();
    std::fs::File::create(root.path().join("manifest.json"))
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("manifest.json is"), "{report}");
    assert!(report.to_string().contains("limit"), "{report}");
}
