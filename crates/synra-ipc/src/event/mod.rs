//! What the kernel pushes to the interface, and how the interface notices it missed one.
//!
//! # Commands are requests; events are state changes
//!
//! The design document's second principle for this boundary is that the interface does not poll. It takes a
//! snapshot once and then consumes what changed — which means an event that never arrives is a screen that is
//! quietly wrong until something else happens to refresh it.
//!
//! So every event carries a **monotonic sequence number**, and the interface's job is to notice a gap. That is
//! what [`SequenceTracker`] is: the whole of the mechanism, with no runtime attached, so the arithmetic that
//! decides whether the interface's picture is still trustworthy is testable on its own.
//!
//! # Why the sequence is not the fix, it is the detector
//!
//! A gap cannot be repaired from the events themselves — the missing ones are gone. The only correct response is
//! to ask for a fresh snapshot, and the value of the sequence number is that it turns "the interface is subtly
//! wrong" into "the interface knows to re-read". A tracker that *ignored* a gap would be worse than none, because
//! the gap would still happen and nothing would notice.
//!
//! # Two ways to be out of order
//!
//! * **A gap** — `seq` jumped forward. Events were dropped, by the channel's own back-pressure or by the
//!   interface being busy. The snapshot is stale.
//! * **A repeat** — `seq` is not greater than the last one seen. The channel delivered something twice, which
//!   Tauri's event system can do across a reload. Applying it twice is how a list gets a duplicated row, so a
//!   repeat is *ignored* rather than applied.
//!
//! They need different responses, which is why the tracker distinguishes them rather than reporting "out of
//! order".
//!
//! # The events are the interface's, not the wire's
//!
//! These are not the protocol's `_synra.*` events. Those are between devices, and a plugin's `handles` refers to
//! them. These are the kernel telling *its own interface* what changed, so the set is chosen by what a screen
//! needs rather than by what a peer may send. The names overlap in meaning and not in mechanism: a
//! `_synra.device.changed` arriving from a peer and a [`KernelEvent::DeviceCardUpdated`] are the same fact at two
//! different distances from the user.

mod payload;
mod sequence;

pub use payload::{DebugWire, KernelEvent, KernelEventEnvelope};
pub use sequence::{EventVerdict, MAX_COUNTED_GAP, SequenceReport, SequenceTracker};

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
