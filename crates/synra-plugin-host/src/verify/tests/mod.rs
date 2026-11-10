//! The eleven checks, driven with a package for every way one can be refused.
//!
//! A pipeline test that only ever fed a good package would pass against one that ran a single check and returned
//! `Pass` eleven times. So every stage has a case that must stop there, and the assertion is *which* stage — because
//! "it was refused" is not the answer an author needs.

use ed25519_dalek::{Signer as _, SigningKey};
use synra_plugin_api::publisher::{ALGORITHM, Digests, SIGNATURE_VERSION, SigningSubject};

use super::{Candidate, DependencyGraph, HostFacts, host_world};

mod dependencies;
mod imports;
mod manifest;
mod pipeline;
mod platform;
mod signatures;

/// A publisher's key, derived from a byte so a test can name it.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A manifest with the given capabilities.
fn manifest_json(capabilities: &[&str]) -> String {
    let declared: Vec<serde_json::Value> = capabilities
        .iter()
        .map(|capability| serde_json::json!({ "cap": capability }))
        .collect();
    serde_json::json!({
        "id": "@acme/hello",
        "version": "1.2.3",
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": host_world(),
        "capabilities": declared,
        "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
    })
    .to_string()
}

/// A candidate that passes every check, which each test then breaks in one place.
struct Fixture {
    manifest: String,
    artifact: Vec<u8>,
    digest: String,
    manifest_digest: String,
    artifacts: Digests,
    graph: DependencyGraph,
}

impl Fixture {
    fn new() -> Self {
        // The digests the subject below is signed over, so a signed fixture describes the package it is attached to.
        // A fixture whose subject was about other bytes would make every signature test fail at the coverage check
        // instead of at the thing the test is named for.
        let mut artifacts = Digests::new();
        artifacts.insert("plugin.wasm", "sha256-abc");
        Self {
            manifest: manifest_json(&["log:*"]),
            artifact: synra_testkit::component::inert_component().expect("a real component"),
            digest: "sha256-abc".to_owned(),
            manifest_digest: "sha256-manifest".to_owned(),
            artifacts,
            graph: DependencyGraph::new(),
        }
    }

    /// A candidate borrowing the fixture, with an optional signature.
    fn candidate<'a>(&'a self, signature: Option<&'a str>, required: bool) -> Candidate<'a> {
        Candidate {
            manifest_json: &self.manifest,
            artifact: &self.artifact,
            declared_digest: Some(&self.digest),
            actual_digest: &self.digest,
            manifest_digest: &self.manifest_digest,
            artifacts: &self.artifacts,
            signature,
            signature_required: required,
            dependencies: &self.graph,
            host: HostFacts::desktop(),
        }
    }
}

/// Build actual imports, instead of handing the verifier caller-controlled metadata.
fn importing_component(import: &str) -> Vec<u8> {
    let function = import.split('#').next_back().unwrap();
    let foreign = import == "wasi:filesystem/types@0.2.0";
    let source = if foreign {
        "package wasi:filesystem@0.2.0; interface types { touch: func(); } world plugin { import types; }".to_owned()
    } else {
        include_str!("../../../wit/synra-plugin.wit").replace("env-sdk-version", function)
    };
    let mut resolve = wit_parser::Resolve::default();
    let package = resolve.push_str("fixture.wit", &source).unwrap();
    let world = resolve.select_world(&[package], Some("plugin")).unwrap();
    if !foreign {
        let interfaces: Vec<_> = resolve.worlds[world]
            .imports
            .values()
            .filter_map(|item| match item {
                wit_parser::WorldItem::Interface { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        for id in interfaces {
            resolve.interfaces[id]
                .functions
                .retain(|name, _| name == function);
        }
    }
    let mut module =
        wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
    wit_component::embed_component_metadata(
        &mut module,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
    )
    .unwrap();
    wit_component::ComponentEncoder::default()
        .module(&module)
        .unwrap()
        .validate(true)
        .encode()
        .unwrap()
}

/// A signature document over a subject, signed by a key.
fn signed(subject: &SigningSubject, publisher_id: &str, seed: u8) -> String {
    let signing = key(seed);
    let signature = signing.sign(&subject.canonical_bytes());
    serde_json::to_string(&serde_json::json!({
        "version": SIGNATURE_VERSION,
        "publisher": { "id": publisher_id },
        "algorithm": ALGORITHM,
        "signedAt": "unix-ms:1",
        "pubkey": base64_of(signing.verifying_key().as_bytes()),
        "subject": { "manifest": subject.manifest, "artifacts": subject.artifacts },
        "signature": base64_of(&signature.to_bytes()),
    }))
    .expect("a document")
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn subject() -> SigningSubject {
    let mut artifacts = Digests::new();
    artifacts.insert("plugin.wasm", "sha256-abc");
    SigningSubject { manifest: "sha256-manifest".to_owned(), artifacts }
}
