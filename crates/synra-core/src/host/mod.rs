//! The pieces tied together: who this device is, who it has heard of, and who it is talking to.
//!
//! # Why this exists
//!
//! [`crate::identity`], [`crate::discovery`], [`crate::sessions`], [`crate::peer`] and [`crate::link`] each answer one
//! question, and each was built and tested on its own. What none of them does is hold the others: a session registry with
//! no identity has nothing to check an envelope's target against, and a discovery table with no sessions has nobody to
//! record a handshake into.
//!
//! The composition is where a *sequence* becomes a rule. Dialling is the clearest case:
//!
//! 1. The candidate's address comes from the discovery table, which is unauthenticated.
//! 2. The handshake is what establishes identity, so nothing before it may be believed.
//! 3. The session is recorded **only after** the handshake, because a session for a device whose identity is unproven is
//!    a session that attributes work to the wrong peer.
//! 4. The trust level rises, because a completed connection is better evidence than a datagram.
//!
//! Any of those in a different order is a bug that no single module's tests can see, which is why this one exists and why
//! its tests drive two hosts against each other.
//!
//! # Why the state is behind one lock
//!
//! Because the four pieces are updated together and read together: a report that read the discovery table, then the
//! sessions, would show a device as found-and-not-connected while a handshake completed between the two reads — and the
//! user would see a candidate they are already talking to. One lock makes a report a snapshot of one moment.
//!
//! # What is not here
//!
//! The UDP socket. Discovery's *receiving* is I/O, and the datagrams are parsed by
//! [`synra_protocol::discovery::DiscoveryDatagram`]; what lives here is what to do with one once it has been parsed,
//! which is the part with decisions in it.
//!
//! # What is in here, and why it is a directory
//!
//! | Module | Holds |
//! | --- | --- |
//! | `kernel` | the [`Host`] itself: what it holds, what it is told, and what it will say about it |
//! | `connections` | the conversations: dialling, accepting, handshaking, sending |
//! | `records` | what the host keeps about its peers: the announcements it hears and the addresses it would dial |
//! | `clock` | the two clock conversions, one subject rather than two byte-identical copies |
//! | `sharing` | the handle an accept loop and a caller share, and the pair a caller drives it with |
//! | `error` | [`HostError`], the one place a host operation says why it failed |
//!
//! Every item is re-exported here, so `crate::host::X` names exactly what it named as one file.

mod clock;
mod connections;
mod error;
mod kernel;
mod records;
mod sharing;

pub use clock::{millis_reading, reading_millis};
pub use error::HostError;
pub use kernel::Host;
// ★ The two halves of a dial. Exported because a caller that holds a lock on the host must be able to perform the
// handshake without it — the whole reason they are two functions rather than the one method they used to be.
pub use connections::{DialConfig, Dialled, dial_peer};
pub use sharing::{Attached, SharedHost, shared};

#[cfg(test)]
mod tests;
