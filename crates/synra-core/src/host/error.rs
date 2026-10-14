use std::net::SocketAddr;

use synra_protocol::ids::DeviceId;

use crate::link::LinkError;
use crate::peer::HandshakeError;

/// Why a host operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// The listener could not be bound.
    #[error("could not listen on {address}: {why}")]
    Bind {
        /// Where it tried.
        address: SocketAddr,
        /// What the operating system said.
        why: String,
    },

    /// The handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),

    /// The link failed.
    #[error(transparent)]
    Link(#[from] LinkError),

    /// The peer was reached and refused the link, because a required feature is missing.
    ///
    /// # Why this is reported after the handshake rather than as a handshake failure
    ///
    /// Because the handshake *succeeded*: the two devices agreed who each other were and what they could do, and the
    /// answer was that they cannot work together. Collapsing it into a connection failure would tell the user their
    /// network is broken when the real answer is a version.
    #[error("the peer is reachable and the two cannot work together: missing {missing}")]
    Incompatible {
        /// The features one side required and the other lacks, as a list for a message.
        missing: String,
    },

    /// No session is open for that device.
    #[error("no session is open with {0}")]
    NoSession(DeviceId),

    /// Nothing this kernel knows is called that.
    #[error("no device is called {wanted} — run `synra devices --all` to see what is")]
    NoSuchDevice {
        /// What the user asked for.
        wanted: String,
    },

    /// More than one device is called that.
    ///
    /// # Why this is refused rather than resolved
    ///
    /// Picking one would send a message to a device the user did not choose, and the sender would never know: the message
    /// would arrive, and it would look deliberate. An identifier is the way to disambiguate, and saying so is more useful
    /// than guessing.
    #[error("{matches} devices are called {name} — use a device id instead")]
    AmbiguousName {
        /// The name.
        name: String,
        /// How many matched.
        matches: usize,
    },

    /// A device is known and this kernel has no address for it.
    #[error("there is no known address for {device_id} — it has never been seen on this network")]
    Unreachable {
        /// Which device.
        device_id: DeviceId,
    },
}
