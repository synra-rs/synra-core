//! A static index: the smallest metadata a bucket can serve.
//!
//! # Why a second shape
//!
//! An npm registry answers a packument from a database; a bucket on S3, R2 or a static site cannot. The design's path A
//! assumes npm compatibility, and this module keeps that assumption from becoming a requirement: an author who can upload
//! files can publish by writing one JSON document and the tarballs beside it (16 §4.4).
//!
//! # The document
//!
//! ```jsonc
//! {
//!   "name": "@acme/hello",
//!   "latest": "1.2.0",                       // optional; the last entry when absent
//!   "versions": [
//!     {
//!       "version": "1.2.0",
//!       "tarball": "https://static.example.com/@acme/hello-1.2.0.tgz",
//!       "integrity": "sha512-…",             // optional, a claim
//!       "manifest": { /* the inline manifest */ }
//!     }
//!   ]
//! }
//! ```
//!
//! # Why "the last entry" rather than a version comparison
//!
//! Because this crate has no semver implementation and the documents are small enough for an author to order. A reader that
//! sorted version strings itself would rank `1.10.0` below `1.9.0`, which is the kind of quiet wrong answer a format should
//! not invite; stating `latest` is the honest way to say it, and the fallback is the order the author wrote.
//!
//! # What is still verified
//!
//! Nothing more than a packument's claims: the tarball address and the inline manifest are the author's words, and the
//! install checks the bytes against a signature before believing them.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::packument::{Dist, Packument, PackumentError, Version};

/// The document a static host serves.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    name: String,
    /// The version an install without one takes; the last entry when absent.
    #[serde(default)]
    latest: Option<String>,
    versions: Vec<Entry>,
}

/// One version in the index.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    version: String,
    tarball: String,
    #[serde(default)]
    integrity: Option<String>,
    /// The registry-specific block a packument carries under `dist.synra`.
    #[serde(default)]
    synra: Option<serde_json::Value>,
    /// The full manifest, inline, as a packument carries it.
    #[serde(default)]
    manifest: Option<synra_plugin_api::Manifest>,
}

/// Parses a static index into the shape the install pipeline already reads.
///
/// # Errors
///
/// [`PackumentError::Unreadable`] when the text is not JSON, names no versions, lists one twice, or names a `latest` that
/// the list does not carry. The last is a refusal rather than a fallback: a document that says one thing and lists another
/// is not a document this build guesses about.
pub fn parse(text: &str) -> Result<Packument, PackumentError> {
    let index: Index = serde_json::from_str(text)
        .map_err(|error| PackumentError::Unreadable(error.to_string()))?;
    if index.versions.is_empty() {
        return Err(PackumentError::Unreadable("it lists no versions".to_owned()));
    }

    let mut versions = BTreeMap::new();
    for entry in &index.versions {
        if versions.contains_key(&entry.version) {
            return Err(PackumentError::Unreadable(format!(
                "version {} is listed twice",
                entry.version
            )));
        }
        versions.insert(
            entry.version.clone(),
            Version {
                name: index.name.clone(),
                version: entry.version.clone(),
                dist: Dist {
                    tarball: entry.tarball.clone(),
                    integrity: entry.integrity.clone(),
                    synra: entry.synra.clone(),
                },
                synra: entry.manifest.clone(),
            },
        );
    }

    let latest = match &index.latest {
        Some(latest) if versions.contains_key(latest) => latest.clone(),
        Some(latest) => {
            return Err(PackumentError::Unreadable(format!(
                "latest names {latest}, which is not listed"
            )));
        }
        // The author's order, not a string comparison; see the module docs.
        None => index
            .versions
            .last()
            .map(|entry| entry.version.clone())
            .unwrap_or_default(),
    };

    let mut dist_tags = BTreeMap::new();
    dist_tags.insert("latest".to_owned(), latest);
    Ok(Packument { name: index.name, dist_tags, versions })
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn document(versions: &[&str], latest: Option<&str>) -> String {
        let entries: Vec<serde_json::Value> = versions
            .iter()
            .map(|version| {
                serde_json::json!({
                    "version": version,
                    "tarball": format!("https://static.example.com/hello-{version}.tgz"),
                })
            })
            .collect();
        let mut body = serde_json::json!({ "name": "@acme/hello", "versions": entries });
        if let Some(latest) = latest {
            body["latest"] = serde_json::json!(latest);
        }
        body.to_string()
    }

    #[test]
    fn a_stated_latest_wins() {
        let index = parse(&document(&["1.0.0", "1.2.0"], Some("1.0.0"))).expect("an index");
        assert_eq!(index.latest().expect("a latest").version, "1.0.0");
        assert_eq!(
            index.latest().expect("a latest").dist.tarball,
            "https://static.example.com/hello-1.0.0.tgz"
        );
    }

    #[test]
    fn without_latest_the_last_entry_is_used() {
        // ★ The order the author wrote, not a version comparison: this crate has no semver, and `1.9.0` sorts after
        // `1.10.0` as text — a fallback someone could not see would be wrong exactly where releases are.
        let index = parse(&document(&["1.10.0", "1.9.0"], None)).expect("an index");
        assert_eq!(index.latest().expect("a latest").version, "1.9.0");
    }

    #[test]
    fn a_latest_the_list_does_not_carry_is_refused() {
        let refused = parse(&document(&["1.0.0"], Some("2.0.0"))).expect_err("it names a missing version");
        assert!(refused.to_string().contains("2.0.0"), "{refused}");
    }

    #[test]
    fn a_version_listed_twice_is_refused() {
        let refused = parse(&document(&["1.0.0", "1.0.0"], None)).expect_err("one version, twice");
        assert!(refused.to_string().contains("listed twice"), "{refused}");
    }

    #[test]
    fn the_inline_manifest_is_read_with_the_contracts_own_type() {
        let body = serde_json::json!({
            "name": "@acme/hello",
            "versions": [{
                "version": "1.2.0",
                "tarball": "https://static.example.com/hello-1.2.0.tgz",
                "manifest": {
                    "id": "@acme/hello",
                    "version": "1.2.0",
                    "title": "Hello",
                    "publisher": { "id": "acme" },
                    "sdk": { "min": "1.0.0" },
                    // The manifest only has to deserialize here; the world string is checked by the installer's own
                    // validation, which is not what this parser is about.
                    "wit": "synra:plugin/plugin@0.1.0",
                    "capabilities": [{ "cap": "log:*" }],
                    "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
                }
            }]
        })
        .to_string();
        let index = parse(&body).expect("an index");
        let manifest = index.at("1.2.0").expect("the version").synra.as_ref().expect("the manifest");
        assert_eq!(manifest.capabilities.first().expect("a capability").cap, "log:*");
    }

    #[test]
    fn something_that_is_not_json_is_a_named_refusal() {
        assert!(parse("not json").is_err());
    }
}
