use std::net::SocketAddr;
use std::time::Duration;

use synra_protocol::discovery::TrustLevel;
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

/// One device the kernel has heard about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Which device.
    pub device_id: DeviceId,
    /// What to show a person.
    ///
    /// Never the raw announced string: a name that failed validation is [`UNUSABLE_NAME`].
    pub display_name: String,
    /// What it claims to be, when it said.
    pub platform: Option<PlatformKind>,
    /// What it claims to run, when it said.
    pub app_version: Option<String>,
    /// What it claims it can do, when it said.
    ///
    /// A claim, and a caller that acts on it without a handshake is acting on an unauthenticated value. Kept because
    /// the handshake compares against it, which is what makes "the peer said it could resume and then could not"
    /// detectable.
    pub claimed_features: Vec<synra_protocol::handshake::Feature>,
    /// Where it said it listens.
    pub address: SocketAddr,
    /// How much of it to believe.
    pub trust: TrustLevel,
    /// When it was last heard from, as a wall-clock reading.
    ///
    /// A wall clock rather than a monotonic reading, because this crosses to a client and to the database — the same
    /// reasoning every other `*_ms` in the kernel follows.
    pub last_seen_ms: i64,
}

impl Candidate {
    /// Whether it is still worth showing.
    ///
    /// # Why a paired device never expires
    ///
    /// Because the pairing is recorded and the user approved it. A paired device that has gone quiet is one that is
    /// *offline*, which is a state the interface shows and the user can act on — and dropping it would make the device
    /// disappear until it was rediscovered, which reads as an unpairing.
    #[must_use]
    pub fn is_current(&self, now_ms: i64, ttl: Duration) -> bool {
        if self.trust == TrustLevel::Paired {
            return true;
        }
        let age = now_ms.saturating_sub(self.last_seen_ms);
        // `as_millis` on a `u128` into an `i64`: saturating, because a ttl beyond 292 million years is a caller mistake
        // rather than a duration this can represent.
        let ttl_ms = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
        age < ttl_ms
    }

    /// Whether the interface may show it.
    ///
    /// The protocol's own rule, delegated rather than restated.
    #[must_use]
    pub const fn is_displayable(&self) -> bool {
        self.trust.is_displayable()
    }
}

/// What the table decided about an announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Absorbed {
    /// A device the table had not heard of.
    New {
        /// Which device.
        device_id: DeviceId,
    },
    /// A device it had heard of, with something different to say.
    Updated {
        /// Which device.
        device_id: DeviceId,
        /// Whether the address changed, which is what makes a peer worth reconnecting to.
        moved: bool,
    },
    /// A device it had heard of, saying the same thing again.
    Unchanged {
        /// Which device.
        device_id: DeviceId,
    },
    /// The announcement was from this device.
    ///
    /// Ignored rather than refused: a device hears its own broadcasts, because that is what broadcasting means. Every
    /// kernel ignores its own datagrams, and a table that counted them would show the user their own machine as a peer.
    SelfAnnouncement,
    /// The announcement named a device that is now offline.
    Offline {
        /// Which device.
        device_id: DeviceId,
    },
}
