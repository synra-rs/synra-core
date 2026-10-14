//! Why an operation on the registry was refused.

use super::super::identity::SessionKey;
use super::super::state::{ClosureReason, LinkState};

/// Why the registry refused something.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// There is no session with that key.
    #[error("no session {0}")]
    NoSuchSession(SessionKey),

    /// The session has ended.
    #[error("session {key} is closed: it ended because {}", .reason.explain())]
    AlreadyClosed {
        /// Which session.
        key: SessionKey,
        /// Why it ended.
        reason: ClosureReason,
    },

    /// The transition is not one a link may make.
    #[error("session {key} cannot go from {} to {}", .from.as_str(), .to.as_str())]
    IllegalTransition {
        /// Which session.
        key: SessionKey,
        /// Where it is.
        from: LinkState,
        /// Where it was asked to go.
        to: LinkState,
    },

    /// The link token does not match the one the session was opened with.
    ///
    /// A frame that arrives with the wrong token is one from a different link, or from before a reconnect, and applying
    /// it to this session would let the old link's frames move the new session's state.
    #[error("session {key} was opened with a different link token")]
    TokenMismatch {
        /// Which session.
        key: SessionKey,
    },
}
