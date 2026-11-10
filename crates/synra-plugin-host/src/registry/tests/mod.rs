//! The registry rules, driven from the side that gets them wrong.
//!
//! The two assertions that matter most are negative: an integrity failure must **not** fall through to another mirror,
//! and an exact override must **not** fall back to the public registry. Both are tested by building the configuration
//! that would do it and asserting the refusal.

use sha2::{Sha256, Sha384, Sha512};
use super::*;

fn config() -> RegistryConfig {
    RegistryConfig::new()
}

fn packument_json() -> Vec<u8> {
    serde_json::json!({
        "name": "@acme/chat",
        "dist-tags": { "latest": "1.10.0" },
        "versions": {
            "1.9.0": { "version": "1.9.0", "dist": { "tarball": "https://r/chat-1.9.0.tgz", "integrity": "sha512-abc" } },
            "1.10.0": {
                "version": "1.10.0",
                "dist": {
                    "tarball": "https://r/chat-1.10.0.tgz",
                    "integrity": "sha512-def",
                    "synra": {
                        "manifestDigest": "sha256-m",
                        "artifacts": { "plugin.wasm": "sha256-a" },
                        "capabilities": ["device:send:*", "storage:local:read"],
                        "size": { "wasm": 1234, "ui": 56 }
                    }
                }
            }
        }
    })
    .to_string()
    .into_bytes()
}

mod mirrors;
mod packument;
mod integrity;
