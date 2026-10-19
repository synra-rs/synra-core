//! The metadata document a registry serves for one package.
//!
//! # What is believed, and what is not
//!
//! Everything here is a **claim**. The tarball address, the integrity string and the inline manifest are the server's
//! words; the install checks the bytes against a signature before it believes any of them. This module's job is to refuse
//! a document that is not shaped like the design's packument (16 §4.1), not to judge whether its claims are true.
//!
//! # Why `synra` is typed
//!
//! Because the design puts the full manifest inline so a screen can show permissions and size **before** downloading the
//! artifact. Parsing it with the contract's own type means the panel and the installer cannot disagree about what the
//! document said.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The metadata for one package.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Packument {
    /// The package's name, which the caller asked for.
    pub name: String,
    /// The tags the publisher set; `latest` is the one an install without a version uses.
    ///
    /// ★ The rename is explicit because `rename_all = "camelCase"` turns `dist_tags` into `distTags`, and the registry
    /// spells this one with a hyphen. A field that parsed as empty made every document look like one with no `latest`.
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: BTreeMap<String, String>,
    /// Every published version, by its version string.
    #[serde(default)]
    pub versions: BTreeMap<String, Version>,
}

/// One published version of a package.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Version {
    /// The package name, repeated inside the version entry.
    pub name: String,
    /// The version string, which is also the key in [`Packument::versions`].
    pub version: String,
    /// Where the artefact is and what the publisher says it is.
    pub dist: Dist,
    /// The full manifest, inline (16 §4.1).
    ///
    /// Optional because a package published by somebody who has not adopted the inline-manifest convention is still a
    /// readable packument; an install simply cannot pre-check it.
    #[serde(default)]
    pub synra: Option<synra_plugin_api::Manifest>,
}

/// What a version's `dist` object carries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Dist {
    /// The tarball's address.
    pub tarball: String,
    /// The publisher's integrity string, in SRI form.
    ///
    /// Recorded and **not trusted**: it is compared with the bytes by the installer, and a document that named its own
    /// digest as the truth would be a document that verifies itself.
    #[serde(default)]
    pub integrity: Option<String>,
    /// The registry's own extension block, kept as JSON for a screen that wants a field this build does not name.
    #[serde(default)]
    pub synra: Option<serde_json::Value>,
}

/// Why a document could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PackumentError {
    /// The text is not the shape this module describes.
    #[error("the packument could not be read: {0}")]
    Unreadable(String),
}

impl Packument {
    /// Parses a document.
    ///
    /// # Errors
    ///
    /// [`PackumentError::Unreadable`] when the text is not JSON or not a packument.
    pub fn parse(text: &str) -> Result<Self, PackumentError> {
        serde_json::from_str(text).map_err(|error| PackumentError::Unreadable(error.to_string()))
    }

    /// The version the `latest` tag names, when the tag and the entry both exist.
    ///
    /// A tag that names a version the document does not carry answers `None` rather than the highest key: the design's
    /// rule is that the publisher chooses `latest`, and a client that overrode it would install a version the publisher
    /// deliberately did not tag.
    #[must_use]
    pub fn latest(&self) -> Option<&Version> {
        self.dist_tags.get("latest").and_then(|version| self.versions.get(version))
    }

    /// One version by its string.
    #[must_use]
    pub fn at(&self, version: &str) -> Option<&Version> {
        self.versions.get(version)
    }

    /// Every version, oldest first by the document's own ordering.
    pub fn version_names(&self) -> impl Iterator<Item = &str> {
        self.versions.keys().map(String::as_str)
    }

    /// The version a request names: an exact version, a semver range, or `latest`.
    ///
    /// # Why a range is resolved here rather than at each caller
    ///
    /// Because "the newest version matching `^1.2`" is an ordering question, and string comparison answers it wrong for
    /// `1.10` against `1.9`. The packument already holds every version; this is the one place that decides which one a
    /// request means, so the shell and the daemon cannot disagree about it.
    ///
    /// # Errors
    ///
    /// [`SelectError::NoLatest`] when no version was asked for and the document has no `latest` tag;
    /// [`SelectError::NoSuchVersion`] when the exact version is absent and the request is not a range that matches one of
    /// the published versions.
    pub fn select<'a>(&'a self, requested: Option<&str>) -> Result<&'a Version, SelectError> {
        let Some(requested) = requested else {
            return self
                .latest()
                .ok_or_else(|| SelectError::NoLatest(self.name.clone()));
        };
        if let Some(version) = self.at(requested) {
            return Ok(version);
        }
        let range = semver::VersionReq::parse(requested)
            .map_err(|_| SelectError::NoSuchVersion(self.name.clone(), requested.to_owned()))?;
        let mut best: Option<semver::Version> = None;
        let mut chosen: Option<&Version> = None;
        for (name, version) in &self.versions {
            let Ok(parsed) = semver::Version::parse(name) else {
                continue;
            };
            if !range.matches(&parsed) {
                continue;
            }
            if best.as_ref().is_none_or(|current| &parsed > current) {
                best = Some(parsed);
                chosen = Some(version);
            }
        }
        chosen.ok_or_else(|| SelectError::NoSuchVersion(self.name.clone(), requested.to_owned()))
    }
}

/// Why a version request could not be satisfied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// The document has no `latest` tag, and no version was asked for.
    #[error("the registry has no `latest` tag for {0}")]
    NoLatest(String),
    /// The requested version and range both match nothing.
    #[error("{0} does not publish {1}")]
    NoSuchVersion(String, String),
}

#[cfg(test)]
mod tests {
    use super::{Packument, PackumentError};

    const DOCUMENT: &str = r#"{
        "name": "@synra-plugin/chat",
        "dist-tags": { "latest": "1.2.0", "beta": "1.3.0-beta.1" },
        "versions": {
            "1.2.0": {
                "name": "@synra-plugin/chat",
                "version": "1.2.0",
                "dist": {
                    "tarball": "https://registry.example.com/@synra-plugin/chat/-/chat-1.2.0.tgz",
                    "integrity": "sha512-abc"
                }
            },
            "1.3.0-beta.1": {
                "name": "@synra-plugin/chat",
                "version": "1.3.0-beta.1",
                "dist": { "tarball": "https://registry.example.com/@synra-plugin/chat/-/chat-1.3.0-beta.1.tgz" }
            }
        }
    }"#;

    #[test]
    fn the_latest_tag_chooses_the_version() {
        // ★ Not the highest key: the publisher sets `latest`, and a client that sorted versions itself would install one
        // the publisher deliberately did not tag.
        let packument = Packument::parse(DOCUMENT).expect("a document");
        let latest = packument.latest().expect("a latest");
        assert_eq!(latest.version, "1.2.0");
        assert_eq!(
            latest.dist.tarball,
            "https://registry.example.com/@synra-plugin/chat/-/chat-1.2.0.tgz"
        );
        assert_eq!(latest.dist.integrity.as_deref(), Some("sha512-abc"));
    }

    #[test]
    fn a_named_version_is_read_even_when_it_is_not_latest() {
        let packument = Packument::parse(DOCUMENT).expect("a document");
        let beta = packument.at("1.3.0-beta.1").expect("the beta");
        assert_eq!(beta.version, "1.3.0-beta.1");
        let names: Vec<&str> = packument.version_names().collect();
        assert_eq!(names, ["1.2.0", "1.3.0-beta.1"], "ordered by the document");
    }

    #[test]
    fn a_tag_naming_a_version_the_document_lacks_is_not_a_latest() {
        // A registry that lost a version — or a document still being written — must not make a client fall back to
        // whichever key sorts last.
        let document = r#"{
            "name": "x",
            "dist-tags": { "latest": "9.9.9" },
            "versions": { "1.0.0": { "name": "x", "version": "1.0.0", "dist": { "tarball": "https://e/x.tgz" } } }
        }"#;
        let packument = Packument::parse(document).expect("a document");
        assert!(packument.latest().is_none());
        assert!(packument.at("1.0.0").is_some());
    }

    #[test]
    fn something_that_is_not_a_packument_is_a_named_refusal() {
        assert!(matches!(
            Packument::parse("not json"),
            Err(PackumentError::Unreadable(_))
        ));
        assert!(matches!(
            Packument::parse(r#"{"name": "x"}"#),
            Ok(packument) if packument.latest().is_none()
        ));
    }

    #[test]
    fn a_range_picks_the_newest_matching_version() {
        // ★ `1.10.0` sorts before `1.9.0` as a string and after it as a version; the whole reason this uses semver.
        let document = serde_json::json!({
            "name": "x",
            "dist-tags": { "latest": "1.9.0" },
            "versions": {
                "1.9.0": { "name": "x", "version": "1.9.0", "dist": { "tarball": "https://e/x-1.9.0.tgz" } },
                "1.10.0": { "name": "x", "version": "1.10.0", "dist": { "tarball": "https://e/x-1.10.0.tgz" } },
                "2.0.0": { "name": "x", "version": "2.0.0", "dist": { "tarball": "https://e/x-2.0.0.tgz" } }
            }
        })
        .to_string();
        let packument = Packument::parse(&document).expect("a document");

        assert_eq!(packument.select(Some("^1.9")).expect("a match").version, "1.10.0");
        assert_eq!(packument.select(Some("~1.9.0")).expect("a match").version, "1.9.0");
        assert_eq!(packument.select(Some("1.10.0")).expect("exact").version, "1.10.0");
        assert_eq!(packument.select(None).expect("latest").version, "1.9.0");
        assert!(matches!(
            packument.select(Some("^2")),
            Ok(version) if version.version == "2.0.0"
        ));
        assert!(matches!(
            packument.select(Some("^3")),
            Err(super::SelectError::NoSuchVersion(_, _))
        ));
    }

    #[test]
    fn a_request_that_is_neither_a_version_nor_a_range_is_named() {
        let packument = Packument::parse(DOCUMENT).expect("a document");
        assert!(matches!(
            packument.select(Some("not-a-version")),
            Err(super::SelectError::NoSuchVersion(_, _))
        ));
    }

    #[test]
    fn a_document_without_a_latest_cannot_be_asked_for_nothing() {
        let packument = Packument::parse(r#"{"name": "x"}"#).expect("a document");
        assert!(matches!(
            packument.select(None),
            Err(super::SelectError::NoLatest(_))
        ));
    }
}
