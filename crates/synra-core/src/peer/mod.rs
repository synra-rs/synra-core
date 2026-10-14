//! The first conversation two devices have.
//!
//! # What the handshake buys
//!
//! Before any work crosses a link, both ends agree on four things:
//!
//! * **Which protocol version.** A peer speaking a different one is refused, rather than failing on the third message
//!   with a decode error about a field neither end can name.
//! * **Which device is on the other end.** The identifier is what a pairing is recorded against, so learning it here is
//!   what makes every later message attributable.
//! * **Which features both have.** Negotiated once so that a transfer does not discover mid-way that the peer cannot
//!   resume it.
//! * **Whether this is a reconnection.** A presented token is checked against the pairings this device holds, and the
//!   answer distinguishes "still paired" from "I have no record of you" — which is not the same as a refusal, because the
//!   other device may have been reset.
//!
//! # Why the exchange is two messages and not a stream of them
//!
//! A dialer sends `Hello`, an acceptor answers `HelloAck`, and the link is ready. The protocol's own frames carry the
//! payloads, so there is nothing to negotiate step by step: an acceptor that needed a second round trip would be one
//! where a peer's features are unknown to the other end until after it has already decided something.
//!
//! # Why the socket is blocking
//!
//! Because the work on this channel is one exchange and then frames in both directions, and a kernel's peer link is one
//! connection per peer — a handful. An async runtime here would be a runtime, a task per link and a `Send` bound on
//! everything the peer layer touches, paid for concurrency a handful of links does not need. The daemon already runs
//! threads.
//!
//! # What is tested, and how
//!
//! The integration tests open a **real loopback socket** and run a real dialer against a real acceptor. The types here
//! are the ones that cross the wire, so a test that stubbed the transport would be a test of the stub — and the bug this
//! layer can have is a mismatch between what one side writes and the other reads.

mod config;
mod errors;
mod host;
mod link;
mod negotiate;
mod pairing;
mod wire;

pub use config::Flags;
pub use errors::HandshakeError;
pub use host::LocalPeer;
pub use link::{accept, accept_stream, dial};
pub use negotiate::{Negotiated, agree};
pub use pairing::pairing_state;
// `link` reaches for this one, and it was reachable at `crate::peer::peer_went_away` before the split, so the path
// stays the same.
pub(crate) use wire::peer_went_away;

#[cfg(test)]
mod tests;
