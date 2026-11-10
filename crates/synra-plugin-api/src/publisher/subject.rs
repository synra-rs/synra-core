//! Canonical signing subjects and artifact digest sets.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::manifest::Manifest;

/// A set of artifact digests, by file name.
///
/// # Why this is a type and not a `BTreeMap`
///
/// Two reasons, and the second is the one that decided it.
///
/// A `BTreeMap` in a public signature is a promise about **the container**: `synra-plugin-api` is a *stable* crate, so
/// naming `std::collections::BTreeMap` makes "this crate changed no line" compatible with "a consumer's build broke"
/// — a standard-library change would do it. The stability rules this workspace states say a signature should name a
/// type whose meaning is this crate's, and this is that type.
///
/// And the ordering is not incidental: [`SigningSubject::canonical_bytes`] builds the bytes a signature is over, and
/// it relies on the iteration order being the key order. A `Digests` is ordered by name *because that is what it
/// means*, not because of which map happened to back it — so a future change to the representation cannot quietly
/// reorder the bytes two implementations compare.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digests(BTreeMap<String, String>);

impl Digests {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The digest for a file name, when it is one of them.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// Whether a file name has a digest.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// Adds or replaces a digest.
    pub fn insert(&mut self, name: impl Into<String>, digest: impl Into<String>) {
        let _ = self.0.insert(name.into(), digest.into());
    }

    /// Removes a digest, returning what it was.
    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.0.remove(name)
    }

    /// Forgets every digest.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Every `(name, digest)` pair, **in name order**.
    ///
    /// The order is the type's promise rather than the container's, which is what lets [`SigningSubject::canonical_bytes`]
    /// depend on it.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(name, digest)| (name.as_str(), digest.as_str()))
    }

    /// Every file name, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// How many digests there are.
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

impl std::fmt::Display for Digests {
    /// A comma-separated list of names, for a message.
    ///
    /// Names only: a digest is not a secret, but a message that carried thirty-two bytes of base64 per file would be
    /// one nobody reads.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.names().collect();
        formatter.write_str(&names.join(", "))
    }
}

impl FromIterator<(String, String)> for Digests {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}
/// What a publisher signed.
///
/// # Why the artifacts are a map and not a list
///
/// Because the signed bytes are built from it, and a list has an order — so two packages with the same files in a
/// different order would have different signed bytes, and a repackaging that changed nothing would invalidate a
/// signature. A `BTreeMap` also gives the fixed iteration order the canonical form needs, which is what makes "sort
/// the keys" a property of the type rather than a step somebody has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningSubject {
    /// The digest of the manifest, as an SRI string.
    pub manifest: String,
    /// Each artifact's digest, by file name.
    pub artifacts: Digests,
}

impl SigningSubject {
    /// The bytes a signature is over.
    ///
    /// # The shape, and why every choice in it matters
    ///
    /// * **No whitespace.** A pretty-printed form would make the payload depend on a formatting option.
    /// * **A fixed key order.** Not the order of the map — `BTreeMap` sorts, so it is the order of the alphabet.
    /// * **Escaping by the JSON rules, not by `Display`.** A file name with a quote in it would otherwise produce
    ///   bytes that two implementations read differently, and one of them would verify a signature over something
    ///   other than what it checked.
    /// * **The signature itself is absent.** It cannot sign itself.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::with_capacity(128);
        out.push_str("{\"manifest\":");
        push_json_string(&mut out, &self.manifest);
        out.push_str(",\"artifacts\":{");
        for (index, (name, digest)) in self.artifacts.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            push_json_string(&mut out, name);
            out.push(':');
            push_json_string(&mut out, digest);
        }
        out.push_str("}}");
        out.into_bytes()
    }

    /// Whether every artifact the manifest names is covered by the signature.
    ///
    /// # Why this is checked at all
    ///
    /// Because a signature over a *subset* of a package is a signature over a different package. A plugin whose
    /// manifest names `plugin.wasm` and `ui.zip`, signed over only `plugin.wasm`, is one where the interface half can
    /// be replaced by anybody — and the signature would still verify.
    #[must_use]
    pub fn covers(&self, manifest: &Manifest) -> Vec<String> {
        let mut missing = Vec::new();
        if let Some(headless) = &manifest.runtime.headless
            && !self.artifacts.contains(&headless.artifact)
        {
            missing.push(headless.artifact.clone());
        }
        if let Some(ui) = &manifest.runtime.ui
            && !self.artifacts.contains(&ui.artifact)
        {
            missing.push(ui.artifact.clone());
        }
        missing.sort();
        missing
    }

    /// The first difference between what was signed and what a package was found to contain.
    ///
    /// # Why this is on the subject rather than at each call site
    ///
    /// Because it was at each call site, and one of them did not do it. `tools/synra-plugin-cli` compared the manifest
    /// digest, the artifact map and the manifest's coverage; `synra-plugin-host`'s verify pipeline compared **none of
    /// the three** — so a package could carry a genuine signature over somebody else's bytes and pass every check.
    /// Both sides now call this, and there is one place for the rule.
    ///
    /// # Why a sentence rather than a boolean
    ///
    /// Because the caller has to tell an author *what* does not agree. "The signature covers different bytes" sends
    /// them to re-sign a package that may be perfectly good; "`plugin.wasm`: the signature covers X, the package has
    /// Y" tells them the artifact was rebuilt after it was signed.
    ///
    /// The comparison is by name order, so the sentence a test asserts is stable across runs.
    #[must_use]
    pub fn mismatch(&self, manifest_digest: &str, artifacts: &Digests) -> Option<String> {
        if self.manifest != manifest_digest {
            return Some(format!(
                "the signed manifest is {}, the package's is {manifest_digest}",
                self.manifest
            ));
        }
        if self.artifacts == *artifacts {
            return None;
        }
        for (name, signed) in self.artifacts.iter() {
            match artifacts.get(name) {
                Some(found) if found == signed => {}
                Some(found) => {
                    return Some(format!("{name}: the signature covers {signed}, the package has {found}"));
                }
                None => {
                    return Some(format!("{name}: the signature covers it and the package does not carry it"));
                }
            }
        }
        for name in artifacts.names() {
            if !self.artifacts.contains(name) {
                return Some(format!("{name}: the package carries it and the signature does not cover it"));
            }
        }
        // Unreachable while `Digests` is a map of the same pairs, and kept rather than `expect`: this crate is
        // `forbid(unsafe_code)` and `deny(unwrap_used)`, and "cannot happen" still has to return something.
        Some("the artifact digests differ".to_owned())
    }

    /// Whether what was signed is exactly what the package contains.
    #[must_use]
    pub fn matches(&self, manifest_digest: &str, artifacts: &Digests) -> bool {
        self.mismatch(manifest_digest, artifacts).is_none()
    }
}

/// Writes a string as a JSON string literal, following the JSON rules.
///
/// The escapes are the ones the specification requires. Everything else is passed through as-is, which is what makes
/// this the *same* bytes a conforming implementation produces rather than a locale- or platform-dependent rendering.
fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control < '\u{20}' => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}


