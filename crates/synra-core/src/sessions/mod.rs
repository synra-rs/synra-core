//! The sessions the kernel has with its peers, and when they are over.
//!
//! # What this is for
//!
//! A link to another device is not one thing. It starts as a socket, becomes a session once both ends agree on a
//! version and a set of features, carries work while it is healthy, and ends — because one side said goodbye, because
//! the peer stopped answering, or because something failed. Each of those is a different answer to "may I send this on
//! that link", and a kernel without the distinction has to guess.
//!
//! The guesses are what this exists to remove. A message sent on a link whose handshake has not finished is one the
//! peer will refuse; a session kept alive after the peer disconnected is one the user can choose from a list and then
//! watch fail; a reconnect that left the old session in place is one where the same device appears twice and half the
//! work goes to the dead half.
//!
//! # Why time is passed in rather than read
//!
//! Every method that decides something about time takes `now_ms`. A registry that called the wall clock would be one
//! whose tests had to sleep, and whose answer depended on how long the test took — so a test of "a peer that stopped
//! answering is noticed after the timeout" would be a test that passes on a fast machine and flakes on a slow one.
//!
//! The clock is the caller's, which is also what the design document asks for: the kernel's decisions are pure
//! functions over values a caller supplies, so the tests need neither a network nor a sleeping thread.
//!
//! # Why the heartbeat deadline is stored rather than computed at the check
//!
//! A deadline that is `last_seen + timeout` is recomputed on every check, so *changing* the timeout mid-session
//! silently changes when the session dies. Storing the deadline means a session keeps the timing it started with, and a
//! settings change applies to new sessions — which is what a user changing a timeout expects.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: the words a link's state is described in, the identifier a session is filed
//! under, the record of one session, and the registry that holds them all. The state machine was the part buried worst — in
//! one file it sat between a type alias and a collection, and it is the part worth reading on its own.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `state` | what a link's state is called, and how it may move |
//! | `identity` | the key a session is filed under |
//! | `record` | one session and the facts recorded about it |
//! | `registry` | every session, and what happens when one changes |

pub mod identity;
pub mod record;
pub mod registry;
pub mod state;

pub use identity::SessionKey;
pub use record::PeerSession;
pub use registry::{RegistryError, RegistryEvent, SessionRegistry};
pub use state::{ClosureReason, LinkState};

#[cfg(test)]
mod tests;
