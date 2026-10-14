//! What the registry reports when a session changes.


use super::super::identity::SessionKey;

use super::super::state::ClosureReason;

/// What the registry decided about a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryEvent {
    /// A session was opened.
    Opened(SessionKey),
    /// A session's handshake finished and it can carry work.
    Ready(SessionKey),
    /// A session began draining.
    Draining(SessionKey),
    /// A session ended, and why.
    Closed(SessionKey, ClosureReason),
    /// A peer opened a new session while an old one was alive, and the old one was closed.
    ///
    /// ★ The event a reconnect produces, and the one worth reporting: a UI that did not learn about it would show the
    /// device twice, and work sent to the old entry would go nowhere.
    Replaced {
        /// The session that ended.
        old: SessionKey,
        /// The session that replaced it.
        new: SessionKey,
    },
}
