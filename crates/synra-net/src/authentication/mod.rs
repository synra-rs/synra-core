//! TLS 1.3 mutual authentication for previously verified device credentials.
//!
//! A UUID, discovery announcement or pairing token never establishes trust here. The caller must obtain
//! the peer certificate through a verified pairing flow and persist that approval separately. Parsing a
//! [`PeerIdentity`] validates its certificate; it does not approve the peer. No application stream is returned
//! until the peer proves possession of the approved key, negotiates `synra/1`, and matches the exact pinned
//! certificate. Changed credentials require explicit verification again.
//!
//! [`pairing`] provides a restricted out-of-band certificate, consent and durable-receipt exchange.
//! The shared service must persist and recheck authorization separately. Store local PKCS#8 keys using the host's
//! protected secret backend; never place them in the ordinary configuration or peer database. Rebuild the
//! approved peer list on revocation and close existing sessions in the owning service.

mod credentials;
mod handshake;
pub mod pairing;
mod stream;

pub use credentials::{DeviceCredentials, PeerIdentity};
pub use stream::AuthenticatedStream;

/// Maximum encoded size of a certificate or private key accepted at the credential boundary.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
/// Maximum number of approved peers in one incoming authentication configuration.
pub const MAX_APPROVED_PEERS: usize = 256;
/// Maximum total TLS handshake time, including partial reads and writes.
pub const MAX_HANDSHAKE_TIME: std::time::Duration = std::time::Duration::from_secs(10);
/// Limit for rustls application plaintext and outgoing TLS buffers, not the process's total memory.
pub const TLS_BUFFER_BYTES: usize = 64 * 1024;

const ALPN: &[u8] = b"synra/1";

/// A failed credential check or authenticated channel establishment.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// The credential is malformed, too large, expired or inconsistent with its device id or key.
    #[error("invalid device credential: {0}")]
    InvalidCredential(String),
    /// The configured trust snapshot is empty, ambiguous or too large.
    #[error("invalid approved peer list: {0}")]
    InvalidPeerList(String),
    /// The peer failed TLS verification, the exact certificate pin, or protocol negotiation.
    #[error("device authentication rejected: {0}")]
    Rejected(String),
    /// The total handshake budget was exhausted.
    #[error("device authentication timed out")]
    TimedOut,
    /// Socket IO failed before authentication completed.
    #[error("device authentication transport failed: {0}")]
    Transport(String),
}

fn transport(error: &std::io::Error) -> AuthenticationError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            AuthenticationError::TimedOut
        }
        std::io::ErrorKind::InvalidData => AuthenticationError::Rejected(error.to_string()),
        _ => AuthenticationError::Transport(error.to_string()),
    }
}

#[cfg(test)]
mod tests;
