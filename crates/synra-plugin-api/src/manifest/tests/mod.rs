//! The manifest's tests.
//!
//! # Why the case-by-case tests are separate from the property tests
//!
//! Because they assert different things. These name a case and its expected refusal; `proptests` assert a property over
//! generated input. A reader asking "what does a version comparison guarantee" should not have to pass a hundred
//! case-by-case tests to find it.

use super::types::Manifest;

mod capabilities;
mod compatibility;
mod composition;
mod digest;
mod errors;
mod events;
mod handles;
mod identity;
mod network;
mod pages;
mod parsing;
mod payload_schema;
mod presentation;
mod round_trip;
mod runtime;
mod version;

/// A minimal manifest that passes every check, so a test can change one thing.
const MINIMAL: &str = r#"{
        "id": "@synra-plugin/chat",
        "version": "1.0.0",
        "title": "Chat",
        "publisher": { "id": "synra-official" },
        "sdk": { "min": "1.0.0" },
        "wit": "synra:plugin@1.0.0",
        "runtime": { "headless": { "artifact": "dist/plugin.wasm", "stateful": false } },
        "capabilities": [{ "cap": "log:*" }]
    }"#;

fn parse(text: &str) -> Manifest {
    Manifest::from_json(text).expect("the fixture parses")
}

fn minimal() -> Manifest {
    parse(MINIMAL)
}
