//! Feature negotiation for established links.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A capability a link can negotiate.
///
/// Additive only. A new variant means a new optional capability, never a change to how an existing
/// one behaves, and a peer that does not list a feature simply does not get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Feature {
    /// Resume a transfer that was interrupted, from the blocks the receiver already has.
    TransferResume,
    /// Push live events to a user interface. Without it, an interface polls.
    EventStream,
    /// Run the same plugin on both devices, so the pair acts as one workspace.
    PluginMirroring,
    /// Share the clipboard between paired devices.
    ClipboardSync,
    /// Answer a request for a diagnostic bundle.
    DiagnosticsBundle,
    /// Find peers on the local network without a configured address.
    LanDiscovery,
    /// Report progress for a transfer in flight.
    TransferProgress,
}

impl Feature {
    /// Every feature this build understands.
    ///
    /// A slice rather than a match so that negotiation, the wire-name tests, and the catalogue guard
    /// all read from one list. Adding a variant without adding it here is caught by
    /// [`tests::feature_list_is_exhaustive`].
    pub const ALL: &'static [Self] = &[
        Self::TransferResume,
        Self::EventStream,
        Self::PluginMirroring,
        Self::ClipboardSync,
        Self::DiagnosticsBundle,
        Self::LanDiscovery,
        Self::TransferProgress,
    ];

    /// The name used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransferResume => "transfer-resume",
            Self::EventStream => "event-stream",
            Self::PluginMirroring => "plugin-mirroring",
            Self::ClipboardSync => "clipboard-sync",
            Self::DiagnosticsBundle => "diagnostics-bundle",
            Self::LanDiscovery => "lan-discovery",
            Self::TransferProgress => "transfer-progress",
        }
    }

    /// Parses a wire name.
    ///
    /// Returns `None` for a name this build does not know, which is not an error: a newer peer may
    /// offer capabilities we simply do not use.
    #[must_use]
    pub fn from_str_opt(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|feature| feature.as_str() == name)
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The features both sides can use, and the ones this side cannot do without.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Agreed {
    /// The features present in both lists.
    pub common: Vec<Feature>,
    /// Features this side required that the peer does not have.
    ///
    /// Non-empty means the link is refused. A required feature is one without which this side would
    /// behave incorrectly rather than merely less well: continuing would produce a wrong result
    /// instead of an error.
    pub missing_required: Vec<Feature>,
}

impl Agreed {
    /// Whether every required feature is available.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.missing_required.is_empty()
    }

    /// Whether a feature can be used on this link.
    ///
    /// The only correct way to ask. A caller that consulted its own list instead would assume a
    /// capability the peer never offered.
    #[must_use]
    pub fn supports(&self, feature: Feature) -> bool {
        self.common.contains(&feature)
    }
}

/// Negotiates the feature intersection.
///
/// Duplicates in either list are harmless: the result is a set. That is deliberate, so a caller
/// assembling a list from two sources does not have to de-duplicate before asking whether a link can
/// work.
///
/// The result is sorted by wire name rather than left in input order. Two negotiations of the same
/// pair must compare equal — the list is stored on the link and compared when a second connection is
/// considered, and an order that depended on which side dialled would make identical links look
/// different.
#[must_use]
pub fn negotiate(ours: &[Feature], theirs: &[Feature], required: &[Feature]) -> Agreed {
    let mut common: Vec<Feature> = Vec::new();
    for feature in ours {
        if theirs.contains(feature) && !common.contains(feature) {
            common.push(*feature);
        }
    }
    common.sort_unstable_by_key(|feature| feature.as_str());

    let missing_required = required
        .iter()
        .copied()
        .filter(|feature| !common.contains(feature))
        .collect();

    Agreed { common, missing_required }
}


