//! The flags a handshake runs under.

use std::time::Duration;

use synra_protocol::limits;

/// Flags a handshake runs under.
///
/// # Why a parameter rather than reading the environment
///
/// A test must be able to drive a timeout without waiting for one, and `TcpStream` has no way to make a loopback read
/// time out. Passing the flags makes the timeout a *value* a test chooses rather than a property of the operating
/// system — which is the only way the branch that reports one can be exercised at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// How long a read may wait before the handshake is abandoned.
    pub timeout: Option<Duration>,
}

impl Flags {
    /// The settings a real connection uses.
    #[must_use]
    pub const fn production() -> Self {
        Self { timeout: Some(limits::HELLO_TIMEOUT) }
    }

    /// No timeout, for a test that must not depend on the clock.
    #[must_use]
    pub const fn no_timeout() -> Self {
        Self { timeout: None }
    }
}

impl Default for Flags {
    fn default() -> Self {
        Self::production()
    }
}
