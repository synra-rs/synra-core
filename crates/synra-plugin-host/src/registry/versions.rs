//! Version and tag maps returned by a registry.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::packument::VersionEntry;

/// Every published version, by version string.
///
/// # Why this is a type and not a `BTreeMap`
///
/// The same reason [`VersionTags`] is: a standard container in a public signature of a semi-stable crate is a promise
/// about `std::collections`. What it means here is "the versions this package has, found by the string the registry
/// spells them with", and that is a fact this crate can change the representation of.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(transparent)]
pub struct Versions(BTreeMap<String, VersionEntry>);

impl Versions {
    /// An empty set of versions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The entry for a version string, when the package has one.
    #[must_use]
    pub fn get(&self, version: &str) -> Option<&VersionEntry> {
        self.0.get(version)
    }

    /// Every version string, in version order as strings rather than as versions.
    ///
    /// # Why this is not ordered semantically
    ///
    /// Because it is used to *say what there is* — in a message listing the versions a package has — and a list in
    /// alphabetical order is one a reader can find a string in. Choosing between two versions is
    /// [`compare_versions`]'s job, and doing it by accident here is how `1.10.0` sorts before `1.9.0`.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Every entry, for a caller that has to look at all of them.
    pub fn values(&self) -> impl Iterator<Item = &VersionEntry> {
        self.0.values()
    }

    /// How many versions there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
/// Which version each tag points at.
///
/// # Why this is a type and not a `BTreeMap`
///
/// Because `synra-plugin-host` is semi-stable, and naming `std::collections::BTreeMap` in a public signature is a
/// promise about *the container* rather than about this crate. The rules this workspace states say a public signature
/// should name a type whose meaning is this crate's, and this is that type — with the one behaviour a tag map needs,
/// which is looking a tag up by name.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(transparent)]
pub struct VersionTags(BTreeMap<String, String>);

impl VersionTags {
    /// An empty set of tags.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The version a tag points at, when the registry has that tag.
    #[must_use]
    pub fn get(&self, tag: &str) -> Option<&str> {
        self.0.get(tag).map(String::as_str)
    }

    /// Whether the registry has that tag.
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.0.contains_key(tag)
    }

    /// Every `(tag, version)` pair, in tag order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(tag, version)| (tag.as_str(), version.as_str()))
    }

    /// How many tags there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

