//! Inbound dispatch: what happens to a message once it has been read off the wire.
//!
//! The frame layer is **structure**; this layer is **content**. The difference dictates the whole
//! design, and the two rules look contradictory until you separate them:
//!
//! * A structural problem closes the link. If a length field is wrong, every subsequent frame
//!   boundary is wrong, so continuing produces nonsense indefinitely.
//! * An unknown *event* is recorded and ignored. A newer peer may legitimately send something this
//!   build has never heard of, and the stream is still perfectly readable. Closing the link would
//!   make a version difference look like corruption.
//!
//! # What this module decides
//!
//! Given a validated envelope, classify it into one of four kinds, and produce the routing decision:
//!
//! | Kind | Delivered to plugins? | On an unrecognised name |
//! |---|---|---|
//! | [`Inbound::Transport`] | never | — (the frame layer owns these) |
//! | [`Inbound::Kernel`] | never | refused as a protocol violation |
//! | [`Inbound::Builtin`] | yes, to subscribers | — |
//! | [`Inbound::DataPlane`] | yes, to subscribers | refused: they drive a state machine |
//! | [`Inbound::Plugin`] | yes, to subscribers | recorded and ignored |
//!
//! # Why `handles` patterns are a separate grammar
//!
//! A [`HandlePattern`] may contain `*`, and an [`EventName`] may not. That separation is load-bearing:
//! `_plugin.@acme/chat.*` describes what a plugin wants to *receive* and can never be sent, so a routing
//! table built from names never has to ask whether one of its entries is a pattern. Two grammars,
//! two types, no ambiguity.
//!
//! # High-frequency events
//!
//! [`builtin::TRANSFER_PROGRESS`] and [`builtin::NETWORK_CHANGED`] are marked as coalescable. They
//! exist so a user interface can show progress, and a progress report superseded by the next one has
//! no value — delivering all of them spends a plugin invocation per frame to tell it something it
//! already knows. [`CoalesceBuffer`] keeps only the newest of each, so a slow consumer sees the
//! current state rather than a queue of history.
//!
//! Nothing else is coalescable, and the list is closed. Coalescing a business event would silently
//! drop it, which is a different thing from dropping a stale progress report.

#[path = "builtin/mod.rs"]
mod builtin_events;
mod classify;
mod coalesce;
mod handles;
mod pattern;

pub use builtin_events::{BuiltinEvent, BuiltinParseError, DeviceSnapshot, NetworkChangeKind, ShareItem};
pub use classify::{Inbound, UnknownReason};
pub use coalesce::{CoalesceBuffer, coalescable_names};
pub use handles::{HandleSet, HandleSetError, inbound_error_to_synra};
pub use pattern::{HandlePattern, PatternError, MAX_PATTERN_WILDCARDS, MAX_WILDCARD_RULES};

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
