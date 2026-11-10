//! What a plugin asks the host to do, and what the host answers.
//!
//! # Why this is not the Wasmtime bindings
//!
//! Because the bindings are a *translation* and this is the *decision*. Every function in the WIT contract becomes, on
//! the host side, a check and an effect: may this plugin make this call, is it within its rate limit, what did it
//! actually ask for, and what is the answer. Those four questions are answerable over values — a capability set, a
//! clock, a table of devices — and the generated glue that turns a Wasm stack into those values adds nothing to whether
//! the answers are right. Writing the decisions first is also what makes them testable without an engine, and the
//! engine is the part that cannot be tested without a guest.
//!
//! # The one rule
//!
//! [`call`] refuses anything the generated import table does not list. Not "refuses anything gated and unheld" —
//! *anything not listed*, including a function name nothing has ever heard of. The table is produced by `synra-wit-codegen`
//! from the WIT file, so a function added to the contract without a gate is a build failure, and a function a plugin
//! asks for that is not in the contract is refused by the host rather than by a linker.
//!
//! # What the host is, for these calls
//!
//! [`Host`] is a **trait**, and the implementations are the point: the kernel implements it for real, and a test
//! implements it with a recording stub. A host that owned the kernel would make every rule below untestable without
//! one, and the rules — the gate, the rate limit, the audit record — are where the mistakes are.

use synra_capability::CapabilitySet;
use synra_observe::audit::AuditEntry;
use synra_protocol::ids::PluginId;

use crate::host_surface;
use crate::quota::{Budget, Health, RateKind};

pub(crate) mod event_scope;
pub(crate) mod log_scope;
pub mod network_scope;
pub(crate) mod target_scope;

mod arguments;
mod errors;
mod helpers;
mod host;
mod metrics;
mod platform;
mod platform_call;
mod policy;
mod run;
mod session;

pub use errors::{CallError, CallResult};
pub use host::Host;
pub use platform::PlatformAction;
#[cfg(test)]
pub(crate) use helpers::{json_array, json_string};

/// What one host call is checked against.
///
/// # Why the grants are here and not asked of the host
///
/// Because a host implementation that had to answer "may this plugin call this" would be one where every
/// implementation had to get the gate table right — and the gate table is generated from the contract precisely so
/// that it is written once. The host implements *effects*; this decides *permission*.
pub struct HostCalls<'a> {
    host: &'a dyn Host,
    plugin: PluginId,
    grants: &'a CapabilitySet,
    budget: &'a Budget,
    audit: &'a mut Vec<AuditEntry>,
    /// Whether the call now running may have side effects.
    ///
    /// ★ `share.can-handle` is a pure function by contract, and the contract is enforced here rather than trusted.
    ///
    /// It runs for **every** plugin the router asks, before a user has chosen anything — so a plugin that wrote a file,
    /// opened a browser or sent a message there would have done it for every share the user then cancelled. A plugin
    /// cannot be relied on to keep that promise, and it should not have to be: the host is what makes it true.
    ///
    /// See [`Work::allows_side_effects`](crate::Work::allows_side_effects), which answers the question and — until this
    /// field existed — was never asked.
    side_effects: bool,
    /// Where this call's place in the numbers goes, when the host keeps numbers at all.
    ///
    /// ★ Why the gate is where metrics start.
    ///
    /// Because it is the one place that already knows the answer to every question the design's `gate_*` metrics ask:
    /// whether the check passed, which plugin asked, which capability, and — when it did not pass — whether it was the
    /// capability set or the rate limiter that said no. A metric recorded anywhere else would be a second opinion about a
    /// decision made here.
    ///
    /// `None` is a real state: a unit test, or a host that keeps no numbers.
    metrics: Option<&'a synra_observe::metrics::RingRecorder>,
}

impl std::fmt::Debug for HostCalls<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCalls")
            .field("plugin", &self.plugin)
            .field("grants", &self.grants.len())
            .field("audited", &self.audit.len())
            .finish_non_exhaustive()
    }
}

/// Every function the host serves, as `(bare name, import name)`, sorted by the bare name.
///
/// # Why this exists
///
/// Because it is the one number that says whether the host and the contract are still the same surface. The generated
/// table is what the gate, the linker and this all read; a test compares the two, so a function added to the contract
/// and not handled by [`HostCalls::run`] fails rather than answering `unknownFunction` at run time — which a plugin
/// author would see as their own mistake.
///
/// # Why a slice and not a map
///
/// Because the container is not what a caller wants: a caller wants *the pairs*, and a `BTreeMap` in a public signature
/// is a promise about `std::collections` rather than about this crate. Sorted, so the answer is the same twice — which
/// is the one property the map was providing.
#[must_use]
pub fn implemented() -> Vec<(&'static str, &'static str)> {
    let mut pairs: Vec<(&'static str, &'static str)> = host_surface::provided()
        .into_iter()
        .map(|import| {
            let function = import.rsplit_once('#').map_or(import, |(_, name)| name);
            (function, import)
        })
        .collect();
    pairs.sort_unstable();
    pairs
}

#[cfg(test)]
#[path = "host_calls_tests.rs"]
mod tests;
