//! The verifier's tests.

use super::*;

/// A manifest for a headless plugin.
const HEADLESS: &str = r#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
  "capabilities": []
}"#;

/// A manifest for a UI plugin.
const UI: &str = r#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "ui": { "artifact": "ui", "entry": "index.html" } },
  "capabilities": []
}"#;

fn target(manifest: &str) -> Target {
    Target {
        manifest_json: Ok(manifest.to_owned()),
        wasm: Err("the declared component is missing".to_owned()),
        ui_bundle: Err("the declared UI directory is missing".to_owned()),
    }
}

fn headless_ok() -> Target {
    Target {
        wasm: component(1_024, &[]),
        ..target(HEADLESS)
    }
}

fn component(bytes: u64, imports: &[&str]) -> Result<ComponentInfo, String> {
    Ok(ComponentInfo {
        bytes,
        imports: imports.iter().map(|name| (*name).to_owned()).collect(),
    })
}

mod manifest;
mod artifacts;
mod imports;
mod report;
