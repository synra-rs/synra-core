//! Synra wire protocol.
//!
//! The complete description of what two Synra devices say to each other: frames, envelopes,
//! events, sessions, discovery. This crate is pure data and pure rules — **no I/O, no async, no
//! runtime**. That constraint is what lets the same definitions be used by the kernel, by the CLI,
//! by the plugin toolchain, and by tests that never open a socket.
//!
//! # Layout
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`ids`] | Typed identifiers. Passing a `TransferId` where a `RequestId` belongs should not compile. |
//! | [`limits`] | Every timing, size and capacity constant. Defined once, here. |
//! | [`error`] | The error model, with stable codes and a user-visibility verdict. |
//! | [`frame`] | The byte-level layer: length-prefixed frames, and the decoder that refuses to resynchronise. |
//! | [`envelope`] | The message layer: who sent what to whom, with a `RawValue` payload that is not parsed unless someone needs it. |
//! | [`event`] | Event names: the grammar, the built-in catalogue, and what a plugin may emit. |
//! | [`inbound`] | The semantic view of a received message, so callers match on variants instead of strings. |
//! | [`handshake`] | Link establishment, including the stale-pairing reconciliation rule. |
//! | [`session`] | Pairing, intent and transfer session payloads and their timeouts. |
//! | [`discovery`] | UDP broadcast query, response and offline announcement. |
//!
//! # Design rules
//!
//! These are enforced by review and by tests, and they are the reason several types look the way
//! they do.
//!
//! 1. **A structural problem closes the link.** The frame decoder never skips a bad frame; frame
//!    boundaries cannot be recovered once lost, and a decoder that pretends otherwise turns a
//!    single corrupt frame into a permanently broken connection.
//! 2. **Reliability does not depend on direction.** `ack_policy` is a function of the event, not of
//!    who dialled.
//! 3. **Unknown fields are rejected; unknown events are not.** An envelope with an extra field is a
//!    protocol violation (`deny_unknown_fields`). An event name nobody recognises is recorded and
//!    ignored — a newer peer may legitimately know more.
//! 4. **Hot paths do not allocate.** Frame decoding, envelope parsing, event routing and capability
//!    matching are asserted allocation-free in tests.
//! 5. **Payloads are transferred, not inspected.** The kernel routes a payload without understanding
//!    it, so `Envelope::payload` is a `RawValue`.
//! 6. **Every field has a producer and a consumer.** A field that appears in the type and never on
//!    the wire is worse than a missing one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules, and the exemption is deliberate rather than a
// convenience.
//
// The workspace denies `unwrap_used`, `expect_used` and `panic` because a running kernel must return
// a structured error instead of tearing down the process. In a test the opposite holds: a test that
// cannot proceed *should* fail loudly and immediately, and one that returned an error instead of
// panicking would be silent about the very failure it exists to catch. Writing every assertion as a
// `match` to satisfy the lint would also bury the assertions that matter in noise.
//
// Scoped to `cfg(test)`, so none of this relaxes the library itself.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod discovery;
pub mod envelope;
pub mod error;
pub mod event;
pub mod frame;
pub mod handshake;
pub mod ids;
pub mod inbound;
pub mod limits;
pub mod session;

pub use error::{ErrorCode, SynraError, UserVisibility};
pub use ids::{
    DeviceId, IntentId, PluginId, PluginSlug, RequestId, ScanId, SessionId, TraceId, TransferId,
};
