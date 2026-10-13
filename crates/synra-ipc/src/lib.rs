//! The host's interface boundary: commands, events, and the errors that cross it.
//!
//! # Why this is a crate rather than a module in the Tauri shell
//!
//! The shell is where the commands are *registered*; this is what they *are*. Splitting them means the contract
//! can be tested without a WebView, a window, or a Tauri runtime — and the two things most likely to be wrong
//! about an interface are the shape of what crosses it and the set of commands that exist.
//!
//! The design document's rule for this boundary is the one that shapes everything here:
//!
//! > command arguments and return values must be expressible as a `SynraError`; a panic may not cross.
//!
//! So every command has a *fallible* signature, and the error type carries a **message key** rather than a
//! sentence. That is the difference between an interface that can be translated and one that cannot: a `String`
//! baked into a Rust error is a string that arrives in the user's language as English.
//!
//! # Three things live here
//!
//! * [`command`] — the registry: which commands exist, what each takes and returns, and whether the plugin
//!   interface may call it. The registry is a value, so a test can assert that the interface's list and the
//!   shell's list are the same list.
//! * [`dto`] — the shapes that cross. Every one is a plain data type: no handles, no sockets, no plugin
//!   instances. The interface holds a picture of the kernel, not the kernel.
//! * [`event`] — what the kernel pushes. A sequence number, because an interface that missed an event has to be
//!   able to *tell* that it missed one, and to re-read rather than drift.
//!
//! # What does not live here
//!
//! No `tauri` dependency and no `#[tauri::command]` attributes. Those belong where the commands are wired to a
//! runtime, and a contract that depends on the runtime cannot be checked without one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
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

pub mod command;
pub mod dto;
pub mod error;
pub mod event;

pub use command::{
    CommandDescriptor, CommandRegistry, Domain, Interface, RegistryError, ReturnShape,
};
pub use dto::*;
pub use error::{IpcError, MessageKey};
pub use event::{
    EventVerdict, KernelEvent, KernelEventEnvelope, MAX_COUNTED_GAP, SequenceReport, SequenceTracker,
};
