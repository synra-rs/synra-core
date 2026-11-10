//! Event names: the grammar, the catalogue, and what a plugin is allowed to emit.
//!
//! # Two kinds of event, and why the line matters
//!
//! * **Built-in events** are the host's. Their names are defined here, their payload shapes are
//!   defined by the host, and they describe *capabilities* — "a device came online", "a transfer
//!   finished and its digest checked out", "a share arrived that no plugin claimed".
//! * **Plugin events** are an author's. They live under `_plugin.<full-plugin-id>.`, and the plugin declares
//!   their payload shape in its manifest.
//!
//! The host does not try to guess what a plugin's events mean. It cannot: the whole point of a
//! plugin is that it knows something the host does not. So the host reports what happened, and the
//! plugin decides what it means.
//!
//! # The namespace rule is enforced, not documented
//!
//! [`EventName::plugin`] preserves the complete identity it is given, and [`EventName::plugin_scope`] tells a
//! caller whether a name belongs to a plugin and which one. A plugin that could emit
//! `_plugin.@acme/someone-else.thing` could impersonate another plugin, so the check lives in the type
//! rather than in a convention someone has to remember.
//!
//! # Names are interned elsewhere
//!
//! Comparison here is by string, which is correct but not free. Routing does not use it: the host
//! resolves a name to a small integer once and looks that up thereafter, so the per-frame cost is an
//! array index rather than a string compare.
/// Prefix for host-defined events.
pub const SYSTEM_PREFIX: &str = "_synra.";

/// Prefix for plugin-defined events.
pub const PLUGIN_PREFIX: &str = "_plugin.";

/// Prefix reserved for events that never leave the process.
pub const INTERNAL_PREFIX: &str = "synra.internal.";

/// Event-name byte bound, leaving 16 bytes for the longest event capability prefix.
/// Full package identities remain within the shared 256-byte capability grammar limit.
pub const MAX_EVENT_NAME_LEN: usize = 240;

/// The largest gap a consumer is told the *size* of.
///
/// # Why a gap has a size at all, and why it is capped
///
/// When events are lost — a subscriber that fell behind, a link that reconnected — the consumer learns that it missed
/// some and, when it is worth saying, how many. The count is useful: one missed event is a hiccup, and ten thousand is
/// a subscriber that stopped keeping up and a bug worth reporting.
///
/// Beyond the cap the consumer is told only that there was a gap, which is the same instruction — re-read the snapshot
/// — without a number it would believe. A *reported* count of four billion says nothing.
pub const MAX_COUNTED_GAP: u32 = 1_000;

mod name;
mod catalog;

pub use catalog::*;
pub use name::*;

#[cfg(test)]
mod tests;
