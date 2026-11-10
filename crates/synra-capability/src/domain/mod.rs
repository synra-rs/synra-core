//! The capability domains.
//!
//! A domain is the first prefix of every capability, and it decides what the rest of the string
//! means. `network:fetch:api.github.com` and `fs:read:/data/**` both have three prefixes, and the
//! third means a hostname in one and a path in the other.
//!
//! The set is closed and deliberately small. A new domain is a new *kind* of thing a plugin can do,
//! which is a change to the trust model rather than a feature — so it belongs in this file, in the
//! design document, and in the capability UI, all at once.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A capability domain.
///
/// The ordering is the declaration order and is **not** stable across versions: it exists so a domain
/// can index a bitmask, not so anything can be compared by it. Persist [`Domain::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Domain {
    /// Writing to the log.
    Log,
    /// The event bus: emitting, subscribing, and asking for a reply.
    Event,
    /// Anything involving another device: listing, sending, broadcasting.
    Device,
    /// The plugin's own storage.
    Storage,
    /// Network access, performed by the host on the plugin's behalf.
    Network,
    /// Files, inside the plugin's sandbox.
    Fs,
    /// Large-object transfer.
    File,
    /// Host system capabilities: opening a URL, simulating input, the clipboard.
    Platform,
    /// Calling, or being called by, another plugin.
    Action,
    /// Interface capabilities. Meaningful only for a plugin that has a UI.
    Ui,
}

impl Domain {
    /// Every domain, in declaration order.
    ///
    /// A slice rather than a `match` so that the bitmask, the parser and the exhaustiveness guard all
    /// read from one list.
    pub const ALL: &'static [Self] = &[
        Self::Log,
        Self::Event,
        Self::Device,
        Self::Storage,
        Self::Network,
        Self::Fs,
        Self::File,
        Self::Platform,
        Self::Action,
        Self::Ui,
    ];

    /// The name used in the DSL.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Event => "event",
            Self::Device => "device",
            Self::Storage => "storage",
            Self::Network => "network",
            Self::Fs => "fs",
            Self::File => "file",
            Self::Platform => "platform",
            Self::Action => "action",
            Self::Ui => "ui",
        }
    }

    /// The bit this domain occupies in a [`DomainMask`].
    ///
    /// Written as a `match` rather than an index into [`Self::ALL`], so it can be a `const fn` — the
    /// mask is used in constant contexts — and so that adding a domain without giving it a bit is a
    /// compile error rather than a silent collision with an existing one.
    #[must_use]
    pub const fn bit(self) -> u32 {
        match self {
            Self::Log => 1 << 0,
            Self::Event => 1 << 1,
            Self::Device => 1 << 2,
            Self::Storage => 1 << 3,
            Self::Network => 1 << 4,
            Self::Fs => 1 << 5,
            Self::File => 1 << 6,
            Self::Platform => 1 << 7,
            Self::Action => 1 << 8,
            Self::Ui => 1 << 9,
        }
    }

    /// Parses a domain name.
    ///
    /// # Errors
    ///
    /// The unknown name, so a typo can be reported with the string that caused it.
    pub fn parse(name: &str) -> Result<Self, UnknownDomain> {
        Self::ALL
            .iter()
            .copied()
            .find(|domain| domain.as_str() == name)
            .ok_or_else(|| UnknownDomain { name: name.to_owned() })
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name that is not a capability domain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name:?} is not a capability domain")]
pub struct UnknownDomain {
    /// The name that was offered.
    pub name: String,
}

/// A domain name with a stable numeric identity, for storage and for wire formats.
///
/// Persisting [`Domain`] itself would tie the database to the enum's declaration order, and
/// reordering the variants — which is a harmless edit — would silently change what every stored
/// grant means. This type exists so that cannot happen: it is written and read by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainId(u8);

impl DomainId {
    /// The id for a domain.
    ///
    /// Derived from the name rather than the declaration order, so inserting a variant cannot shift
    /// another domain's identity.
    #[must_use]
    pub const fn of(domain: Domain) -> Self {
        // A perfect hash over ten names. Written as a match so adding a domain without giving it an
        // id is a compile error rather than a collision.
        Self(match domain {
            Domain::Log => 0,
            Domain::Event => 1,
            Domain::Device => 2,
            Domain::Storage => 3,
            Domain::Network => 4,
            Domain::Fs => 5,
            Domain::File => 6,
            Domain::Platform => 7,
            Domain::Action => 8,
            Domain::Ui => 9,
        })
    }

    /// The numeric value, for storage.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The domain this identifies.
    ///
    /// # Errors
    ///
    /// [`UnknownDomain`] if the stored value names no domain. Reading a value written by a newer
    /// version is refused rather than mapped to something arbitrary: a grant for a domain we do not
    /// understand must not silently become a grant for one we do.
    pub fn domain(self) -> Result<Domain, UnknownDomain> {
        Domain::ALL
            .iter()
            .copied()
            .find(|domain| Self::of(*domain) == self)
            .ok_or_else(|| UnknownDomain { name: format!("domain id {}", self.0) })
    }
}

impl From<Domain> for DomainId {
    fn from(domain: Domain) -> Self {
        Self::of(domain)
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.domain() {
            Ok(domain) => write!(f, "{domain}"),
            Err(_) => write!(f, "domain#{}", self.0),
        }
    }
}

/// A set of domains, as a bitmask.
///
/// The fast negative path for capability checks. A plugin typically holds capabilities in two or
/// three domains, so "does this set contain anything in the `network` domain at all?" answers most
/// checks before any string is examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DomainMask(u32);

impl DomainMask {
    /// An empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// A set containing every domain.
    #[must_use]
    pub fn all() -> Self {
        let mut mask = Self(0);
        for domain in Domain::ALL {
            mask = mask.with(*domain);
        }
        mask
    }

    /// The same set plus one domain.
    #[must_use]
    pub const fn with(self, domain: Domain) -> Self {
        Self(self.0 | domain.bit())
    }

    /// Whether a domain is present.
    #[must_use]
    pub const fn has(self, domain: Domain) -> bool {
        self.0 & domain.bit() != 0
    }

    /// The same set without one domain.
    #[must_use]
    pub const fn without(self, domain: Domain) -> Self {
        Self(self.0 & !domain.bit())
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether no domain is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// How many domains are present.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// The domains present, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Domain> {
        Domain::ALL.iter().copied().filter(move |domain| self.has(*domain))
    }
}

impl fmt::Display for DomainMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for domain in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{domain}")?;
        }
        if first {
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
