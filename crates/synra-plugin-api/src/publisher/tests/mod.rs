//! The signature and the trust decision, driven from both sides.
//!
//! A signature test that only ever checks a *good* signature proves nothing about the check: it would pass against a
//! verifier that returned `Good` unconditionally. So every property here has a case that must fail — a tampered
//! subject, an artifact that was swapped, a key that changed — and the cases are asserted as outcomes rather than as
//! "it did not panic".

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};

use super::{ALGORITHM, BASE64, Digests, Engine, SIGNATURE_VERSION, SigningSubject};
use crate::manifest::Manifest;

/// A publisher's key, derived from a byte so a test can name it.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A signature document over a subject, signed by a key.
fn signed(subject: &SigningSubject, publisher_id: &str, seed: u8) -> String {
    let signing = key(seed);
    let public = signing.verifying_key();
    let signature = signing.sign(&subject.canonical_bytes());
    let document = serde_json::json!({
        "version": SIGNATURE_VERSION,
        "publisher": { "id": publisher_id, "name": "A Publisher" },
        "algorithm": ALGORITHM,
        "signedAt": "2026-07-22T10:00:00Z",
        "pubkey": BASE64.encode(public.as_bytes()),
        "subject": {
            "manifest": subject.manifest.clone(),
            "artifacts": subject.artifacts.iter().map(|(name, digest)| (name.to_owned(), digest.to_owned())).collect::<BTreeMap<String, String>>(),
        },
        "signature": BASE64.encode(signature.to_bytes()),
    });
    serde_json::to_string(&document).expect("a document")
}

fn subject() -> SigningSubject {
    let mut artifacts = Digests::new();
    artifacts.insert("plugin.wasm", "sha256-aaa");
    SigningSubject { manifest: "sha256-bbb".to_owned(), artifacts }
}

/// A manifest that names the artifact the subject covers.
fn manifest() -> Manifest {
    let text = r#"{
        "id": "@acme/hello",
        "version": "1.2.3",
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": "1.0.0",
        "capabilities": [],
        "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
    }"#;
    serde_json::from_str(text).expect("a manifest")
}

fn digests() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let _ = map.insert("plugin.wasm".to_owned(), "sha256-aaa".to_owned());
    map
}

mod canonical;
mod verification;
mod package;
mod trust;
