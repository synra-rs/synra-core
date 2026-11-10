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

mod isolated_sdk;
mod headless;
mod hybrid;

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
    verify_actual_guest(&bytes);
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

fn verify_actual_guest(bytes: &[u8]) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("actual.wasm"), bytes).unwrap();
    for granted in [false, true] {
        let capabilities = if granted {
            serde_json::json!([{ "cap": "platform:open-url" }])
        } else {
            serde_json::json!([])
        };
        std::fs::write(
            root.path().join("manifest.json"),
            serde_json::json!({
                "id": "@acme/sdk", "version": "1.0.0", "title": "SDK",
                "publisher": { "id": "acme" }, "sdk": { "min": "0.1.0" },
                "wit": synra_plugin_host::host_world(), "capabilities": capabilities,
                "runtime": { "headless": { "artifact": "actual.wasm", "stateful": false } }
            })
            .to_string(),
        )
        .unwrap();
        let (status, report) = run(Command::new(env!("CARGO_BIN_EXE_synra-plugin"))
            .args(["verify", "--json", "--dir"])
            .arg(root.path()));
        assert_eq!(status.success(), granted, "{report}");
        if !granted {
            assert!(
                report.contains("synra:plugin/host#platform-open-url"),
                "{report}"
            );
        }
    }
}

fn build_guest(dir: &Path) -> (ExitStatus, String) {
    let cache = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sdk-authoring");
    let toolchain = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rust-toolchain.toml"))
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"');
    run(Command::new(env!("CARGO_BIN_EXE_synra-plugin"))
        .args(["build", "--dir"])
        .arg(dir)
        .env("CARGO_TARGET_DIR", cache)
        .env("RUSTUP_TOOLCHAIN", toolchain)
        .env("CARGO_NET_OFFLINE", "true"))
}

fn patch_sdk(cargo: &Path, source: &str, sdk: &Path) {
    let path = serde_json::to_string(&sdk.to_string_lossy().replace('\\', "/")).unwrap();
    std::fs::write(
        cargo,
        format!("{source}\n[patch.crates-io]\nsynra-plugin-sdk = {{ path = {path} }}\n"),
    )
    .unwrap();
}
