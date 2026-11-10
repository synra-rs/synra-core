//! What the kernel has heard about, and how much of it to believe.
//!
//! # What discovery does and does not establish
//!
//! `synra-protocol`'s own module docs put it exactly: discovery answers *what addresses might a Synra device be at?* and
//! refuses to answer any other question. A UDP datagram's source address is trivially forged and its contents are
//! unauthenticated, so **anything a device claims about itself here is a hint to be checked, not a fact to be trusted**.
//!
//! That restraint is what this module is built around. A device found this way is a *candidate*, and it becomes a peer
//! only after a TCP connection has been made and a `Hello` exchanged over it. The trust level is tracked explicitly
//! rather than inferred, because the three levels have genuinely different consequences:
//!
//! | Level | What it took | What the user sees |
//! | --- | --- | --- |
//! | announced | a datagram arrived | the device, under "found on this network" |
//! | handshaked | a TCP connection completed a `Hello` | the device, as reachable |
//! | paired | the user approved it | the device, as usable |
//!
//! # Why the name is checked here
//!
//! It arrives from another device and it is **rendered**. A control character in it is how a device list row is
//! rewritten and a newline is how a log line is forged — the same reasoning `identity`'s validator follows, applied to
//! the same value arriving from the other direction. A name that fails is **not** a reason to drop the candidate: the
//! datagram told us a device exists and where, which is what discovery is for, and the name is only a display concern.
//! So it is replaced with a placeholder rather than the whole announcement being refused.
//!
//! # Why the trust level never goes down
//!
//! A datagram cannot demote a pairing: it is unauthenticated, so a peer that announced itself is not evidence that a
//! paired device stopped being paired. The level rises when the evidence rises and is lowered only by the kernel
//! forgetting the pairing, which is a different code path with a different reason.

mod model;
mod mutation;
mod table;
mod util;

pub use model::{Absorbed, Candidate};
pub use table::DiscoveryTable;
pub use util::announced_address;

use std::time::Duration;

/// How long an unpaired candidate stays current after its last announcement.
pub const CANDIDATE_TTL: Duration = Duration::from_secs(90);
/// The display name used when an announcement contains an unusable name.
pub const UNUSABLE_NAME: &str = "Unnamed device";

#[cfg(test)]
mod tests;
