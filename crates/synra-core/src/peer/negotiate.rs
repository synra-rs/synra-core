//! What the two ends agree on: the features they have in common, and the session built from them.

use synra_protocol::handshake::{Agreed, Feature, PairingState};
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

use super::host::LocalPeer;

/// The result of a completed handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The peer's identifier.
    pub device_id: DeviceId,
    /// What the peer calls itself.
    pub display_name: String,
    /// What the peer is.
    pub platform: PlatformKind,
    /// The peer's build.
    pub app_version: String,
    /// The features both ends announced.
    pub agreed: Agreed,
    /// How the peer read our token, from our side of the exchange.
    ///
    /// `None` when we were the acceptor, because it is the dialer that presented a token.
    pub pairing: Option<PairingState>,
}
impl Negotiated {
    /// Whether the link can carry work.
    ///
    /// A refusal with no missing required features is still unusable: the peer said no, and continuing would be doing
    /// work on a link the other end has already declined.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.agreed.is_usable()
    }
}

/// Agrees on features from both announcements.
///
/// # Why this is a free function
///
/// Because it is the same computation on both sides of the exchange, and a dialer and an acceptor that disagreed would
/// be two devices that each believe a different set of features is available — with the failure landing at the first
/// transfer that used one of them.
#[must_use]
pub fn agree(ours: &LocalPeer, theirs_features: &[Feature], theirs_requires: &[Feature]) -> Agreed {
    // Common: what both announced.
    let common: Vec<Feature> = ours
        .features
        .iter()
        .copied()
        .filter(|feature| theirs_features.contains(feature))
        .collect();

    // Missing required: what either side needs and the other does not have. Both directions, because a link where the
    // peer requires something we lack is as unusable as the reverse — and a check that looked only at our own list
    // would let us start work the peer will refuse.
    let mut missing_required: Vec<Feature> = ours
        .requires
        .iter()
        .copied()
        .filter(|feature| !theirs_features.contains(feature))
        .collect();
    for required in theirs_requires {
        if !ours.features.contains(required) && !missing_required.contains(required) {
            missing_required.push(*required);
        }
    }

    Agreed { common, missing_required }
}
