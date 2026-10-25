use synra_protocol::frame::FrameError;

/// Why a handshake failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// TLS-bound identities or the captured durable approval were refused.
    #[error("the handshake authorization failed: {why}")]
    Authorization {
        /// The failed identity or authorization check, without private credentials.
        why: String,
    },
    /// The stream failed.
    #[error("the connection failed: {why}")]
    Transport {
        /// What the operating system said.
        why: String,
    },

    /// The connection was closed before the handshake finished.
    ///
    /// # Why this is its own variant
    ///
    /// Because it is the ordinary shape of a peer that gave up, a scan that probed a port and left, and a user who
    /// closed a laptop — and a caller that had to tell it apart from a decode error would be one that logged a fault for
    /// every port scan.
    #[error("the peer closed the connection before the handshake finished")]
    Closed,

    /// A frame could not be encoded or decoded.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// The first frame was not the one the handshake expected.
    #[error("expected a {expected} frame and received a {found} frame")]
    Unexpected {
        /// What the exchange was waiting for.
        expected: &'static str,
        /// What arrived.
        found: String,
    },

    /// The payload was not the message it should be.
    #[error("the {message} payload could not be read: {why}")]
    Payload {
        /// Which message.
        message: &'static str,
        /// What the parser said.
        why: String,
    },

    /// The peer speaks a protocol this build does not.
    #[error("the peer speaks protocol {theirs} and this build speaks {ours}")]
    VersionMismatch {
        /// What the peer sent.
        theirs: u16,
        /// What this build speaks.
        ours: u16,
    },

    /// The peer refused the link, and said why.
    #[error("the peer refused the connection: {reason}")]
    Refused {
        /// The peer's own reason, as a string for a log line.
        reason: String,
    },

    /// The peer's `HelloAck` echoed a different nonce.
    ///
    /// # Why this is fatal
    ///
    /// The nonce is what ties an answer to the attempt that asked for it. An answer carrying a different one is a
    /// recorded or mis-routed message, and continuing would build a session on a reply to somebody else's question.
    #[error("the peer answered with a different nonce, so this is not a reply to our attempt")]
    NonceMismatch,

    /// The peer's announcement did not validate.
    #[error("the peer's announcement was refused: {why}")]
    Invalid {
        /// What the validator said.
        why: String,
    },
}
