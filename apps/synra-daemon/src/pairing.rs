//! The pairing record read, as this host reaches it.
//!
//! It is [`synra_core::inbound::pairing_state_for`] now: the listener that asks the question moved into the library, and a
//! listener that cannot answer "do I trust this peer" would have to take a closure no library can implement.

pub use synra_core::inbound::pairing_state_for as state_for;
