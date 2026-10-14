//! The key a session is filed under.
//!
//! # Why this is not the peer's device identifier
//!
//! Because one device may be connected more than once — a reconnect that overlaps its predecessor, or two interfaces on
//! one host — and those are different sessions that must be tellable apart.

/// A session's identity, as the registry issued it.
///
/// # Why this is not `SessionId`
///
/// `SessionId` is the wire's identity for a session — what both ends put in an envelope. This is the *registry's* key,
/// and the difference matters on reconnect: the same peer makes a new session, and a caller holding the old
/// `SessionId` must not be handed the new session's state. Keeping the two apart is what makes that a type error rather
/// than a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionKey(pub(super) u64);

impl SessionKey {
    /// A key the registry never issued, for an error that has no session to name.
    ///
    /// # Why this exists rather than a `SessionKey(0)` at the call site
    ///
    /// The field is private so that a caller cannot name a session the registry did not issue — which is the property
    /// that makes a stale key an error rather than a lookup into somebody else's state. A named constant keeps that
    /// property while giving the "there is no session" case something to carry.
    pub const UNISSUED: Self = Self(0);

    /// The number, for a log line or a report.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s{}", self.0)
    }
}
