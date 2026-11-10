//! The audit trail: what a plugin was allowed to do, and what it did.
//!
//! # Why this exists at all
//!
//! A capability prompt says "this plugin would like to read from GitHub". After that, the plugin runs, and
//! the user has no way to see whether it read from GitHub or from somewhere else. The audit trail is the
//! answer to that: every gated call, allowed or refused, in order, attributed.
//!
//! It is shown in the settings screen under the plugin's own name, because that is where a person looks
//! when they want to know what a plugin has been doing.
//!
//! # No payloads, ever
//!
//! An audit record says *that* `network:fetch` was called for `api.github.com`, and how long it took. It
//! does not say what was fetched. That is the whole reason the record is safe to keep for longer than a log
//! and safe to include in a diagnostic bundle: it is a list of destinations, not of contents.
//!
//! This is enforced by the type: [`AuditEntry`] has no field a payload could go in. A field added later
//! would have to be named, reviewed, and would fail the tests that assert the record contains no content.
//!
//! # Refusals are the interesting half
//!
//! An allowed call is bookkeeping. A refused one is the moment the capability system did its job, and the
//! user is the person who should know it happened — either because their plugin has a bug, or because it
//! was doing something they did not want. So a refusal is recorded with the same detail as an allowance, and
//! the interface does not hide it behind a filter.

mod activity;
mod entry;
mod retention;
mod ring;

pub use activity::PluginActivity;
pub use entry::{AuditEntry, AuditOutcome};
pub use retention::{DEFAULT_RETENTION_DAYS, Retention};
pub use ring::{AuditRing, MEMORY_CAPACITY};

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
