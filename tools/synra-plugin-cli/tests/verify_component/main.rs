//! The actual command must inspect component contracts and enforce manifest coverage.

// Assertions and bounded child-process control retain local failure diagnostics.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Seek as _};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "../support/component.rs"]
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

mod contracts;
mod artifacts;
mod archives;
