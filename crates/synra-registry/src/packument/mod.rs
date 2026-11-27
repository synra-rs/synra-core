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
use synra_plugin_api::manifest::{ManifestError, PluginVersion, PluginVersionReq};

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
        self.dist_tags
            .get("latest")
            .and_then(|version| self.versions.get(version))
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

    /// The publisher's latest entry when it advances the installed version.
    ///
    /// # Errors
    /// Reports invalid installed or published versions and a dangling `latest` tag.
    pub fn latest_upgrade(&self, installed: &str) -> Result<Option<&Version>, SelectError> {
        let installed = PluginVersion::parse(installed)?;
        let Some(key) = self.dist_tags.get("latest") else {
            return Ok(None);
        };
        let (entry, version) = self.exact(key)?;
        Ok(version.cmp_precedence(&installed).is_gt().then_some(entry))
    }

    /// The version a request names: an exact version, a publisher tag, or a SemVer range.
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
        let requested = requested.unwrap_or("latest");
        if requested != "latest"
            && (self.versions.contains_key(requested) || PluginVersion::parse(requested).is_ok())
        {
            return self.exact(requested).map(|(entry, _)| entry);
        }
        if let Some(key) = self.dist_tags.get(requested) {
            return self.exact(key).map(|(entry, _)| entry);
        }
        if requested == "latest" {
            return Err(SelectError::NoLatest(self.name.clone()));
        }
        let range = PluginVersionReq::parse(requested)
            .map_err(|_| SelectError::NoSuchVersion(self.name.clone(), requested.to_owned()))?;
        let mut best: Option<(&Version, PluginVersion)> = None;
        for (key, entry) in &self.versions {
            let candidate = parse_entry(key, entry)?;
            // Keys are visited in string order, so equivalent builds have a deterministic tie-break.
            if range.matches(&candidate)
                && best
                    .as_ref()
                    .is_none_or(|(_, current)| candidate.cmp_precedence(current).is_gt())
            {
                best = Some((entry, candidate));
            }
        }
        best.map(|(entry, _)| entry)
            .ok_or_else(|| SelectError::NoSuchVersion(self.name.clone(), requested.to_owned()))
    }

    fn exact(&self, key: &str) -> Result<(&Version, PluginVersion), SelectError> {
        let entry = self
            .at(key)
            .ok_or_else(|| SelectError::NoSuchVersion(self.name.clone(), key.to_owned()))?;
        Ok((entry, parse_entry(key, entry)?))
    }
}

fn parse_entry(key: &str, entry: &Version) -> Result<PluginVersion, SelectError> {
    if entry.version != key {
        return Err(SelectError::MismatchedVersion {
            key: key.to_owned(),
            entry: entry.version.clone(),
        });
    }
    Ok(PluginVersion::parse(key)?)
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
    /// An installed version or an entry being considered has invalid SemVer.
    #[error(transparent)]
    InvalidVersion(#[from] ManifestError),
    /// The registry names two different versions for one entry.
    #[error("registry version key {key:?} identifies an entry for {entry:?}")]
    MismatchedVersion {
        /// Version map key.
        key: String,
        /// Version reported by its entry.
        entry: String,
    },
}

#[cfg(test)]
mod tests;
