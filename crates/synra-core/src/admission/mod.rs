//! Intent admission: the eight checks a cross-device action has to pass before anything runs.
//!
//! # Why the order is part of the design
//!
//! The checks are a sequence, and each one is cheaper and more fundamental than the next. Running them in order means
//! a malformed request is refused before the kernel looks anything up, and a request from an unpaired device is
//! refused before the kernel consults the plugin registry — which is the difference between a stream of junk costing
//! a hash lookup each and a stream of junk costing a database query each.
//!
//! The order also decides *which* refusal a caller sees, and that matters because the refusals are acted on
//! differently:
//!
//! 1. **Envelope** — already checked by the time this runs; a violation closes the link.
//! 2. **Is the sender paired?** An unpaired source is not a plugin's problem, and the answer is not "denied" but
//!    "who are you".
//! 3. **Is the plugin installed and active?** If not, nothing else can be true.
//! 4. **Does the plugin declare this action?** A declared action is a promise; an undeclared one is a caller
//!    inventing an interface.
//! 5. **Does the grant cover what the action needs?** The plugin's own permissions.
//! 6. **Can this host do it at all?** Checked *before* step 8, so a plugin is not started to do something this
//!    machine cannot do — the design document's "so the plugin does not run for nothing".
//! 7. **Is this a duplicate?** Answered from the reply cache when it is, without running anything.
//! 8. **Run it.**
//!
//! # Why the capabilities are resolved rather than stored per action
//!
//! An action's declaration carries a JSON Schema for its arguments, not a capability list. The capability an action
//! needs is derived from what it *does* — `platform:open-url` for a handler that opens a URL, `device:send:<target>`
//! for one that sends to a target — and the derivation is the plugin author's declaration in the manifest plus the
//! arguments. So the caller supplies the required capabilities, having resolved them, and this module decides whether
//! the host and the plugin can meet them.

mod context;
mod decision;

pub use context::AdmissionContext;
pub use decision::{admit, check, host_requirement, AdmissionRefusal, AdmissionStep, PluginKey};

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
