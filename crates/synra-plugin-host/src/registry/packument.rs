//! Packument data and version lookup.

use serde::{Deserialize, Serialize};

use super::digests::ArtifactDigests;
use super::integrity::compare_versions;
use super::{FetchFailure, MAX_PACKUMENT_BYTES, MAX_VERSIONS};
use super::versions::{VersionTags, Versions};
use synra_plugin_api::publisher::SignatureFile;

/// What a registry says about one version of a package.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionEntry {
    /// The version, as the registry spells it.
    pub version: String,
    /// Where the tarball is, and what it must hash to.
    pub dist: Dist,
}

/// Where the bytes are and what they must be.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dist {
    /// The tarball's URL.
    pub tarball: String,
    /// Its integrity, as an SRI string.
    ///
    /// `Option` because the field is what npm *should* always send and what a private mirror sometimes omits. A
    /// missing integrity is not a licence to skip the check: [`Integrity::parse`] refuses an empty string, and a
    /// caller that has no integrity has nothing to verify against — which is a decision for the pipeline above, not
    /// something this type invents an answer to.
    #[serde(default)]
    pub integrity: Option<String>,
    /// The `synra` block the registry carries, when it carries one.
    #[serde(default)]
    pub synra: Option<SynraBlock>,
}

/// What a registry says about a package *as a Synra plugin*.
///
/// # Why this is here and not left to the manifest
///
/// Because it is what lets an interface show what a plugin asks for **before** the artifact is downloaded. A user
/// deciding whether to install something should not have to fetch a megabyte of Wasm to find out that it wants their
/// clipboard.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SynraBlock {
    /// The signature document, inline.
    #[serde(default)]
    pub signature: Option<SignatureFile>,
    /// The digest of the manifest, as an SRI string.
    #[serde(default)]
    pub manifest_digest: Option<String>,
    /// Each artifact's digest, by file name.
    #[serde(default)]
    pub artifacts: ArtifactDigests,
    /// What the plugin asks for, so a catalog can filter without downloading.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// What the artifact weighs, so a prompt can say so.
    #[serde(default)]
    pub size: Option<SizeBlock>,
}

/// How large the parts of a package are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SizeBlock {
    /// The headless artifact.
    #[serde(default)]
    pub wasm: u64,
    /// The interface bundle.
    #[serde(default)]
    pub ui: u64,
}

/// Everything a registry says about a package.
///
/// The renaming is **not** uniform, and deliberately: the surrounding document is npm's and its field is spelled
/// `dist-tags` with a hyphen, while the `synra` block this design adds is camel case to match the manifest and the IPC
/// surface. A single `rename_all` would have to be wrong about one of them, and being wrong about `dist-tags` means a
/// package whose `latest` tag is silently absent.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Packument {
    /// The package's name.
    pub name: String,
    /// Which version each tag points at, such as `latest`.
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: VersionTags,
    /// Every published version.
    #[serde(default)]
    pub versions: Versions,
}

impl Packument {
    /// Parses a packument.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::Malformed`] when it is not JSON, is larger than [`MAX_PACKUMENT_BYTES`], lists more than
    /// [`MAX_VERSIONS`] versions, or does not have the shape a packument has — each with the reason, because "could
    /// not read the packument" leaves whoever is configuring a mirror with nothing to check.
    pub fn parse(registry: &str, bytes: &[u8]) -> Result<Self, FetchFailure> {
        let malformed = |reason: String| FetchFailure::Malformed { registry: registry.to_owned(), reason };
        if bytes.len() > MAX_PACKUMENT_BYTES {
            return Err(malformed(format!(
                "it is {} bytes, and the limit is {MAX_PACKUMENT_BYTES}",
                bytes.len()
            )));
        }
        let packument: Self = serde_json::from_slice(bytes).map_err(|error| malformed(error.to_string()))?;
        if packument.name.is_empty() {
            return Err(malformed("it names no package".to_owned()));
        }
        if packument.versions.len() > MAX_VERSIONS {
            return Err(malformed(format!(
                "it lists {} versions, and the limit is {MAX_VERSIONS}",
                packument.versions.len()
            )));
        }
        Ok(packument)
    }

    /// The version a tag points at.
    ///
    /// `None` for a tag the registry does not have, which is the ordinary answer for `next` on a package that has
    /// never published one.
    #[must_use]
    pub fn tagged(&self, tag: &str) -> Option<&VersionEntry> {
        self.dist_tags.get(tag).and_then(|version| self.versions.get(version))
    }

    /// The newest version, as a registry orders them.
    ///
    /// # Why this is string ordering and not semantic
    ///
    /// Because a packument's `versions` is a map and JSON maps have no order, so "newest" has to be *decided*. The
    /// registry settles it with `dist-tags.latest`, and that is what [`Self::tagged`] reads. This fallback exists for
    /// a mirror that sent no tags, and it compares by the numeric components so that `1.10.0` sorts after `1.9.0`
    /// rather than before it — which plain string ordering gets wrong and which is the mistake that ships an old
    /// version to everybody.
    #[must_use]
    pub fn newest(&self) -> Option<&VersionEntry> {
        self.versions
            .values()
            .max_by(|first, second| compare_versions(&first.version, &second.version))
    }

    /// The version a caller asked for.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::NoSuchVersion`] naming what the package does have, because the caller's next step is to pick
    /// one of them.
    pub fn version(&self, package: &str, wanted: &str) -> Result<&VersionEntry, FetchFailure> {
        if let Some(found) = self.versions.get(wanted) {
            return Ok(found);
        }
        // A range is not resolved here: choosing a version from a requirement needs the semver rules, and they live
        // where the rest of the manifest's version handling does. What this does is the exact case and the tag case,
        // and it says what it has rather than guessing.
        if let Some(found) = self.tagged(wanted) {
            return Ok(found);
        }
        Err(FetchFailure::NoSuchVersion {
            package: package.to_owned(),
            wanted: wanted.to_owned(),
            available: self.versions.names().collect::<Vec<&str>>().join(", "),
        })
    }
}


