//! Finding peers on the local network.
//!
//! Discovery answers one question — *what addresses might a Synra device be at?* — and deliberately
//! refuses to answer any other. In particular it never establishes identity. A UDP datagram's source
//! address is trivially forged, and its contents are unauthenticated, so anything a device claims
//! about itself here is a hint to be checked, not a fact to be trusted.
//!
//! That restraint is what makes the rest of the design simple: a device found this way is a
//! **candidate**, and only becomes a peer once a TCP connection has been made and a `Hello` exchanged
//! over it. The interface shows candidates under a separate heading for exactly that reason.
//!
//! # Two datagram kinds, one magic prefix each
//!
//! ```text
//! query    "SYNRA_DISCOVERY\n" + JSON { protocol, device_id, display_name, port }
//! response JSON { device_id, display_name, platform, app_version, protocol, features, port }
//! offline  "SYNRA_OFFLINE\n"   + JSON { device_id, timestamp }
//! ```
//!
//! A response has no magic prefix: it is a unicast reply to an address that just sent a query, so
//! there is nothing to disambiguate it from.
//!
//! # Unknown fields are ignored, and that is the opposite of the envelope rule
//!
//! [`crate::envelope::Envelope`] refuses unknown fields; these messages ignore them. The difference
//! is not inconsistency, it is what the two formats are for. An envelope is a contract: a peer that
//! sends an extra field is violating a protocol both sides agreed to, and accepting it would let two
//! implementations drift apart about what a valid message is.
//!
//! A discovery datagram is a broadcast rumour. Broadcast reaches every device on the network,
//! including ones running versions this build has never seen, and the cost of refusing an unfamiliar
//! field is that a device silently fails to be discoverable at all — a failure the user experiences
//! as "my phone can't see my laptop", with nothing in any log to explain it. So a datagram may say
//! more than we understand, and the extra is dropped.
//!
//! # Self-discovery is suppressed in exactly one place
//!
//! A device that answers its own broadcast appears in its own list. The check lives in
//! [`Discovery::admit`] and nowhere else. Spreading it over several layers produces the familiar
//! outcome: nobody can say which layer is doing the filtering, and a device discovers itself again
//! every time one is bypassed.

mod budget;
mod candidate;
mod datagram;
mod encode;

pub use budget::ScanBudget;
pub use candidate::{Candidate, Discovery, TrustLevel, offline_interval, offline_repeats};
pub use datagram::*;
pub use encode::*;

#[cfg(test)]
mod tests;
