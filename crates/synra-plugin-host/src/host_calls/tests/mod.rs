//! The host calls, driven from both sides: what the contract says, and what a plugin gets for asking.
//!
//! The stub host records everything, so a test can assert both the answer and the *effect* — which is what makes the
//! gate rules testable: a refusal that still reached the host would be a refusal that did nothing.

use synra_capability::CapabilitySet;
use synra_observe::audit::AuditEntry;
use synra_protocol::ids::PluginId;

use super::{Budget, HostCalls};
use crate::host_surface::CAPABILITIES;
use crate::quota::Quota;
use crate::test_host::Stub;

mod audit;
mod contract;
mod events;
mod gate;
mod input;
mod log;
mod matching;
mod network;
mod rate;
mod responses;

/// A session with a generous budget and the given grants.
fn session<'a>(
    host: &'a Stub,
    grants: &'a CapabilitySet,
    budget: &'a Budget,
    audit: &'a mut Vec<AuditEntry>,
) -> HostCalls<'a> {
    HostCalls::new(host, plugin(), grants, budget, audit)
}

fn plugin() -> PluginId {
    PluginId::parse("@acme/chat").expect("a plugin id")
}

fn budget() -> Budget {
    Budget::new(Quota::default())
}

/// Every capability the contract mentions, so a test can grant exactly one and see what it reaches.
fn all_capabilities() -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for capability in CAPABILITIES {
        let _ = set.insert_str(capability);
    }
    set
}

fn granted(capabilities: &[&str]) -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for capability in capabilities {
        let _ = set.insert_str(capability);
    }
    set
}
