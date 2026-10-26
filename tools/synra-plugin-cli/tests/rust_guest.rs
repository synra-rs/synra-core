//! Explicit authoring gate: a real SDK guest and a real CLI-generated project reach PluginSet.

// Assertions and fixture construction deliberately fail with their diagnostic context.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Seek as _};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use synra_core::dispatch::{PluginSet, PluginSetError, PluginSpec};
use synra_plugin_host::engine::WasmtimeBackend;
use synra_plugin_host::{Backend, BackendKind, CallBudget, CallOutcome, InstancePolicy, Work};
use synra_protocol::PluginId;

#[path = "rust_guest/isolated_sdk.rs"]
mod isolated_sdk;

fn set() -> PluginSet {
    PluginSet::new(
        Backend::new(Arc::new(
            WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap(),
        )),
        Arc::new(synra_plugin_host::testing::RefusingHost),
    )
}

fn spec(bytes: Vec<u8>, granted: bool) -> PluginSpec {
    let mut spec = PluginSpec {
        id: PluginId::parse("@acme/rust-guest").unwrap(),
        version: "0.1.0".to_owned(),
        wasm: bytes,
        grants: Default::default(),
        policy: InstancePolicy::Stateless,
        limit: 1,
        quota: synra_plugin_host::quota::Quota::default(),
    };
    if granted {
        spec.grants.insert_str("platform:open-url").unwrap();
    }
    spec
}

#[test]
fn the_rust_sdk_guest_loads_through_core_and_its_actual_calls_require_grants() {
    let path = std::env::var_os("SYNRA_RUST_GUEST")
        .expect("set SYNRA_RUST_GUEST to the freshly built wasm32-unknown-unknown SDK core module");
    let module = std::fs::read(path).unwrap();
    let bytes = synra_plugin_cli::build::component::encode(&module).unwrap();
    let mut plugins = set();
    let denied = plugins.load(spec(bytes.clone(), false));
    assert!(
        matches!(denied, Err(PluginSetError::UndeclaredImport { import, .. }) if import == "synra:plugin/host#platform-open-url")
    );
    let spec = spec(bytes, true);
    let id = spec.id.clone();
    plugins.load(spec).unwrap();
    for _ in 0..2 {
        let result = plugins
            .call(
                &id,
                &Work::Activate {
                    config_json: "{}".to_owned(),
                },
                CallBudget::unlimited(),
                0,
            )
            .unwrap();
        assert_eq!(result, CallOutcome::Ok("0.0.0".to_owned()));
    }
    let input = "你好 \"quoted\"";
    let result = plugins
        .call(
            &id,
            &Work::CanHandle {
                item_json: input.to_owned(),
            },
            CallBudget::unlimited(),
            0,
        )
        .unwrap();
    assert_eq!(result, CallOutcome::Ok(input.to_owned()));
}

fn run(command: &mut Command) -> (ExitStatus, String) {
    // A separate Cargo target directory avoids recursive Cargo's workspace build lock.
    // This deadline bounds compiler processes; no assertion relies on an arbitrary sleep duration.
    let mut log = tempfile::tempfile().unwrap();
    let mut child = command
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the authoring command exceeded its five minute deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    log.rewind().unwrap();
    let mut text = String::new();
    log.read_to_string(&mut text).unwrap();
    (status, text)
}

#[test]
fn a_headless_scaffold_builds_a_component_and_a_failed_rebuild_preserves_it() {
    let dir = tempfile::tempdir().unwrap();
    let scaffold = synra_plugin_cli::template::Scaffold::new(
        "@acme/template",
        "0.1.0",
        "Template",
        synra_plugin_cli::template::TemplateKind::Headless,
    )
    .unwrap();
    for file in scaffold.files {
        let path = dir.path().join(file.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.contents).unwrap();
    }
    let sdk = isolated_sdk::copy(dir.path());
    let cargo = dir.path().join("Cargo.toml");
    let source = std::fs::read_to_string(&cargo)
        .unwrap()
        .replace("[lib]", "[lib]\nname = \"differently_named_guest\"");
    // The package is unpublished; patch only dependency resolution, leaving the generated Rust source intact.
    let path = serde_json::to_string(&sdk.to_string_lossy().replace('\\', "/")).unwrap();
    std::fs::write(
        cargo,
        format!("{source}\n[patch.crates-io]\nsynra-plugin-sdk = {{ path = {path} }}\n"),
    )
    .unwrap();
    let cache = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sdk-authoring");
    let toolchain = include_str!("../../../rust-toolchain.toml")
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"');
    let build = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_synra-plugin"));
        command
            .args(["build", "--dir"])
            .arg(dir.path())
            .env("CARGO_TARGET_DIR", &cache)
            .env("RUSTUP_TOOLCHAIN", toolchain)
            .env("CARGO_NET_OFFLINE", "true");
        run(&mut command)
    };
    let (status, log) = build();
    assert!(status.success(), "{log}");
    let bytes = std::fs::read(dir.path().join("plugin.wasm")).unwrap();
    assert_eq!(bytes.get(..8), Some(b"\0asm\x0d\0\x01\0".as_slice()));
    let mut plugins = set();
    let spec = spec(bytes.clone(), false);
    let id = spec.id.clone();
    plugins.load(spec).unwrap();
    assert_eq!(
        plugins
            .call(
                &id,
                &Work::Activate {
                    config_json: "{}".to_owned()
                },
                CallBudget::unlimited(),
                0
            )
            .unwrap(),
        CallOutcome::Ok(String::new())
    );
    assert_eq!(
        plugins
            .call(
                &id,
                &Work::CanHandle {
                    item_json: "{}".to_owned()
                },
                CallBudget::unlimited(),
                0
            )
            .unwrap(),
        CallOutcome::Ok(r#"{"handled":false}"#.to_owned())
    );
    std::fs::write(dir.path().join("src/lib.rs"), "pub fn not_a_plugin() {}").unwrap();
    let (status, log) = build();
    assert!(!status.success(), "{log}");
    assert_eq!(
        std::fs::read(dir.path().join("plugin.wasm")).unwrap(),
        bytes
    );
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "compile_error!(\"intentional rebuild failure\");",
    )
    .unwrap();
    let (status, log) = build();
    assert!(!status.success(), "{log}");
    assert_eq!(
        std::fs::read(dir.path().join("plugin.wasm")).unwrap(),
        bytes
    );
}
