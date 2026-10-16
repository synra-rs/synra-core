//! The built-in revocation list, and the scan that acts on it.
//!
//! # Why this exists
//!
//! Because `PublisherTrustStore` could answer "is this **key** revoked" and nothing could answer "is this **version**
//! revoked" — the design's list names both, and only the first had a home. So a plugin withdrawn for malicious code kept
//! loading: the store's revocation set was a `HashMap<Fingerprint, String>` and the document's first entry shape
//! (`plugin` + `versions`) had no type at all, no file, and no code that read one.
//!
//! # The document
//!
//! ```json
//! { "revoked": [
//!     { "plugin": "@bad/plugin", "versions": ["1.0.0"], "reason": "malicious code", "at": "2026-01-01" },
//!     { "publisher": "evil-actor", "pubkeyFingerprint": "AAAA BBBB CCCC DDDD", "reason": "impersonation" }
//! ] }
//! ```
//!
//! It ships with the application and is replaced by a newer one, so this parses rather than fetches: **the offline case is
//! the built-in case**, and a list that could only be obtained over the network would leave a machine with no revocation
//! data at all. Fetching is the caller's business and deliberately not this module's.
//!
//! # Versions are compared as written
//!
//! ★ **This is exact string equality, not semver.** The design names exact versions, and interpreting them as ranges would
//! need a version parser and would widen what a list entry means — a `1.0.0` that revoked `1.0.0+build` would revoke
//! something nobody named.
//!
//! The cost is real and is the opposite risk: a list that spells a version differently from the manifest — `1.0.0` against
//! `v1.0.0` — **misses**, and a missed revocation is a plugin that keeps running. That is why [`RevocationList::must_disable`]
//! is a scan over what is installed rather than a check at the point of use: a version that does not match is visible in the
//! scan's input, whereas a check that returns "not revoked" looks the same as one that never ran.
//!
//! # Malformed entries are refused rather than skipped
//!
//! Because a list is the one document where a silently dropped entry is a security decision: a typo in a field name would
//! remove the revocation and leave everything looking healthy. Parsing fails, and the caller decides what to do about a bad
//! list — which is a decision it can only make if it is told.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::publisher::Fingerprint;

/// Why a revocation list could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// The document is not JSON, or not this shape.
    #[error("the revocation list is not readable: {detail}")]
    Malformed {
        /// What the parser said.
        detail: String,
    },
    /// An entry names neither a plugin version nor a publisher.
    #[error("entry {index} names neither a plugin version nor a publisher")]
    EmptyEntry {
        /// Which entry, counting from zero, as it appears in the document.
        index: usize,
    },
    /// An entry names a plugin but no versions.
    #[error("entry {index} names `{plugin}` and no versions")]
    NoVersions {
        /// The plugin it names.
        plugin: String,
        /// Which entry.
        index: usize,
    },
    /// A fingerprint that is not one.
    #[error("entry {index} has a fingerprint that is not one: {detail}")]
    BadFingerprint {
        /// Which entry.
        index: usize,
        /// What the parser said.
        detail: String,
    },
}

/// One line of the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pubkey_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<String>,
}

/// The document itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawList {
    revoked: Vec<RawEntry>,
}

/// One accepted entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Revocation {
    /// Named versions of a named plugin.
    Versions {
        /// The plugin.
        plugin: String,
        /// The versions, as the manifest spells them.
        versions: Vec<String>,
        /// Why.
        reason: String,
    },
    /// A publisher, by key fingerprint.
    ///
    /// # Why the key and not the name
    ///
    /// Because a publisher name is free — the design says so where it explains `Untrusted::KeyChanged`. Revoking a name
    /// would be revoking a claim, and the next person can make the same claim; revoking a fingerprint revokes the thing that
    /// actually signed.
    Publisher {
        /// The name, kept for the message a user reads.
        publisher: String,
        /// The key.
        fingerprint: Fingerprint,
        /// Why.
        reason: String,
    },
}

impl Revocation {
    /// Why the entry exists, as a user is shown it.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Versions { reason, .. } | Self::Publisher { reason, .. } => reason,
        }
    }
}

/// What is installed, as the scan needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed<'a> {
    /// The plugin's identifier.
    pub plugin: &'a str,
    /// The version, as the manifest spells it.
    pub version: &'a str,
}

/// A plugin that must be disabled, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disable {
    /// The plugin's identifier.
    pub plugin: String,
    /// The version that is revoked.
    pub version: String,
    /// The reason from the list.
    pub reason: String,
}

/// A parsed revocation list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationList {
    /// Named versions, by plugin.
    versions: BTreeMap<String, VersionRevocation>,
    /// Publishers, by fingerprint.
    ///
    /// ★ The **name is kept** rather than the reason alone, because a revocation is shown to a person and
    /// `@evil-actor` is what they recognise. The first version of this map stored only the reason, so the name the
    /// document went to the trouble of spelling was parsed and thrown away — and its own doc comment claimed otherwise.
    publishers: BTreeMap<Fingerprint, PublisherRevocation>,
}

/// One revoked publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PublisherRevocation {
    publisher: String,
    reason: String,
}

/// The versions of one plugin that are revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionRevocation {
    versions: Vec<String>,
    reason: String,
}

impl RevocationList {
    /// An empty list.
    ///
    /// ★ The honest name for "nothing is revoked yet". A device with no list has no revocations, and that is a state a
    /// caller can report; what it must not do is treat a **missing** list as an empty one without saying so, because the
    /// two look identical from here.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses the document.
    ///
    /// # Errors
    ///
    /// [`RevocationError`] for anything this cannot read, including an entry that names nothing — see the module
    /// documentation for why a dropped entry is the one failure this must not have.
    pub fn parse(text: &str) -> Result<Self, RevocationError> {
        let raw: RawList = serde_json::from_str(text).map_err(|error| RevocationError::Malformed {
            detail: error.to_string(),
        })?;

        let mut list = Self::empty();
        for (index, entry) in raw.revoked.into_iter().enumerate() {
            match (entry.plugin, entry.publisher, entry.pubkey_fingerprint) {
                (Some(plugin), publisher, fingerprint) => {
                    if entry.versions.is_empty() {
                        return Err(RevocationError::NoVersions { plugin, index });
                    }
                    // A version entry that also carries a fingerprint revokes the key as well: both facts were written down,
                    // and honouring one of them would be reading half the document.
                    //
                    // The publisher is taken from the bound value rather than from `entry.publisher`, which the `match`
                    // above moved into its own tuple — the same reason the name is bound at all.
                    if let Some(text) = fingerprint {
                        let key = parse_fingerprint(&text, index)?;
                        list.publishers.insert(key, PublisherRevocation {
                            publisher: publisher.unwrap_or_default(),
                            reason: reason_of(&entry.reason),
                        });
                    }
                    list.versions.insert(
                        plugin,
                        VersionRevocation { versions: entry.versions, reason: reason_of(&entry.reason) },
                    );
                }
                (None, Some(publisher), Some(text)) => {
                    let key = parse_fingerprint(&text, index)?;
                    list.publishers.insert(key, PublisherRevocation {
                        publisher,
                        reason: reason_of(&entry.reason),
                    });
                }
                // A publisher with no key is a claim with nothing behind it — the module documentation's reason for
                // revoking keys rather than names. Reported rather than accepted, and the name is not bound because an
                // entry that names no key is refused rather than read.
                (None, Some(_), None) | (None, None, _) => {
                    return Err(RevocationError::EmptyEntry { index });
                }
            }
        }
        Ok(list)
    }

    /// Whether there is nothing revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty() && self.publishers.is_empty()
    }

    /// How many plugins and publishers are revoked, together.
    #[must_use]
    pub fn len(&self) -> usize {
        self.versions.len() + self.publishers.len()
    }

    /// Why this plugin at this version is revoked, if it is.
    #[must_use]
    pub fn revokes(&self, plugin: &str, version: &str) -> Option<&str> {
        let entry = self.versions.get(plugin)?;
        entry
            .versions
            .iter()
            .any(|revoked| revoked == version)
            .then_some(entry.reason.as_str())
    }

    /// Why this signing key is revoked, if it is.
    #[must_use]
    pub fn revokes_key(&self, fingerprint: &Fingerprint) -> Option<&str> {
        self.publishers.get(fingerprint).map(|entry| entry.reason.as_str())
    }

    /// The publisher a revoked key belongs to, as the document names it.
    ///
    /// Separate from [`Self::revokes_key`] because the two are answers to different questions: *is this key revoked* is what
    /// a verification asks, and *whose key was it* is what a person is shown.
    #[must_use]
    pub fn revoked_publisher(&self, fingerprint: &Fingerprint) -> Option<&str> {
        self.publishers.get(fingerprint).map(|entry| entry.publisher.as_str())
    }

    /// Every installed plugin that must be disabled, in the order given.
    ///
    /// # Why a scan rather than a check at the point of use
    ///
    /// Because the failure this guards against is a **miss**, and a miss is invisible at the point of use: a check that
    /// answers "not revoked" cannot be told apart from one that never ran. A scan puts the installed set and the list side
    /// by side, so what was compared is a thing a caller can log and a test can assert on.
    #[must_use]
    pub fn must_disable(&self, installed: &[Installed<'_>]) -> Vec<Disable> {
        installed
            .iter()
            .filter_map(|plugin| {
                let reason = self.revokes(plugin.plugin, plugin.version)?;
                Some(Disable {
                    plugin: plugin.plugin.to_owned(),
                    version: plugin.version.to_owned(),
                    reason: reason.to_owned(),
                })
            })
            .collect()
    }

    /// Every plugin the list names, whether installed or not.
    ///
    /// The other half of the design's behaviour: an attempt to **install** a revoked version is refused with the same
    /// reason, so a caller needs to be able to ask without having something installed.
    ///
    /// No `#[must_use]`: an `impl Iterator` already is one, and saying it twice is the lint telling the truth.
    pub fn plugin_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.versions.keys().map(String::as_str)
    }
}

/// The reason, or a sentence saying there is none.
///
/// ★ A revocation with no reason is still a revocation. Refusing to parse it would leave the plugin running because of a
/// missing field, which inverts the point of the document.
fn reason_of(reason: &Option<String>) -> String {
    reason
        .clone()
        .unwrap_or_else(|| "revoked with no reason given".to_owned())
}

/// A fingerprint, or the error naming which entry.
fn parse_fingerprint(text: &str, index: usize) -> Result<Fingerprint, RevocationError> {
    Fingerprint::parse(text).map_err(|error| RevocationError::BadFingerprint {
        index,
        detail: error.to_string(),
    })
}

#[cfg(test)]
mod tests;
