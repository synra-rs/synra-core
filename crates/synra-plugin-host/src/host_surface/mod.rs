//! The host's surface, as the WIT contract declares it.
//!
//! # Why this is a module rather than a table written here
//!
//! Which functions the host offers and what each is gated on is a fact that **three** places need: the host, which
//! checks the gate before a call runs; the plugin CLI, which refuses an artifact importing a function the host does
//! not provide; and a reviewer, who wants to know that nothing is reachable without a capability.
//!
//! Written here by hand, the table drifts from `wit/synra-plugin.wit` silently and in the worst direction: a function
//! added to the contract and not to the table is one **any plugin can call**, and nothing in the kernel would be
//! wrong. So the table is generated from the contract, and `build.rs` regenerates it on every build — a contract
//! change that is not reflected in the generated file is a **compile error**, not a review comment.
//!
//! # What the table is for
//!
//! Three questions, and each has one answer here:
//!
//! * **May this function be called with the capabilities this plugin holds?** [`gate`] returns what the host must
//!   check; [`permits`] answers whether a granted set satisfies it.
//! * **Does the host provide this at all?** [`provides`] — the check the CLI makes against a compiled artifact's
//!   import section, and the reason an import name is matched in full rather than by a prefix.
//! * **Is anything ungated?** [`ungated`] — the list a reviewer reads, and the one that has to stay short.

/// The generated table.
///
/// Included rather than exported from a crate, because it is derived from a file this crate's build reads and there is
/// nothing to publish: the values are constants, and a second crate for six of them would be a crate whose only
/// purpose is to be a dependency.
mod generated {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/capability_table.rs"));

    /// The trait the host implements, one method per contract function.
    ///
    /// ★ Included rather than written, and the reason it matters is subtle: a hand-written trait is a trait somebody
    /// *noticed* was incomplete, whereas a generated one cannot be. A function the contract declares and the trait
    /// forgot is one the host silently does not implement, and the plugin that imports it fails to instantiate with a
    /// message about a missing export that names neither file.
    ///
    /// The trait's methods take no `&self`. A host's methods are the kernel's own logic, and whether they need state is
    /// the implementation's business: a trait that demanded `&self` would force every host to be an object, and one
    /// that demanded nothing lets a ZST implementation exist for a host that has no state.
    /// `pub(crate)` rather than `pub`: the trait is re-exported below, and an item a private module's `pub` cannot
    /// reach is what `unreachable_pub` warns about. The re-export is the public path, and it is the only one.
    pub(crate) mod host {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/host_trait.rs"));
    }
}

pub use generated::host::Host;

pub use generated::{CAPABILITIES, EXPORTED_INTERFACES, HOST_FUNCTIONS, HOST_INTERFACE, PACKAGE, PACKAGE_VERSION};

use synra_capability::{CapabilitySet, Domain};

/// What the host checks before a function runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostGate {
    /// Nothing: the call reads a fact about the environment.
    Ungated,
    /// The capability string, which the plugin must have been granted.
    Capability(&'static str),
}

impl HostGate {
    /// Whether anything is checked.
    #[must_use]
    pub const fn is_ungated(self) -> bool {
        matches!(self, Self::Ungated)
    }

    /// The capability, when there is one.
    #[must_use]
    pub const fn capability(self) -> Option<&'static str> {
        match self {
            Self::Ungated => None,
            Self::Capability(capability) => Some(capability),
        }
    }
}

/// What the host must check before calling a function, by its import name.
///
/// # The name is the full import, not the bare function
///
/// `synra:plugin/host#log` — what a compiled component's import section carries. A lookup on `log` alone would match a
/// function of that name in another interface, and the interface is part of what a component names.
///
/// # `None` means the host does not provide it
///
/// Distinct from [`HostGate::Ungated`], which means the host provides it and checks nothing. Collapsing the two would
/// make an unknown function — one a plugin built against a newer SDK called — look like an ungated one, which is the
/// answer that lets it through.
#[must_use]
pub fn gate(import_name: &str) -> Option<HostGate> {
    HOST_FUNCTIONS
        .iter()
        .find(|(name, _)| *name == import_name)
        .map(|(_, capability)| match capability {
            None => HostGate::Ungated,
            Some(capability) => HostGate::Capability(capability),
        })
}

/// Whether the host provides a function, by its import name.
#[must_use]
pub fn provides(import_name: &str) -> bool {
    gate(import_name).is_some()
}

/// Whether a granted set makes a function available for import.
///
/// Network availability requires a grant in the fetch family. Each call and redirect
/// must separately authorize its concrete destination and HTTP method. Logging similarly
/// requires a supported granted level, and checks the actual level on every call.
///
/// # `false` for a function the host does not provide
///
/// The two refusals are different — "you cannot" and "there is no such thing" — and this answers `false` for both
/// because the caller's next step is the same either way: do not make the call. A caller that needs to tell them apart
/// asks [`provides`] first, which is what the CLI's import check does.
#[must_use]
pub fn permits(import_name: &str, grants: &CapabilitySet) -> bool {
    match gate(import_name) {
        None => false,
        Some(HostGate::Ungated) => true,
        // Dynamic families need at least one usable concrete operation. The call checks its arguments again.
        Some(HostGate::Capability("event:emit:*")) => {
            crate::host_calls::event_scope::available(grants)
        }
        Some(HostGate::Capability("log:*")) => crate::host_calls::log_scope::available(grants),
        Some(HostGate::Capability(
            family @ ("device:send:*" | "action:invoke:*:*" | "action:declare:*"),
        )) => crate::host_calls::target_scope::available(grants, family),
        Some(HostGate::Capability("network:fetch:*")) => {
            crate::host_calls::network_scope::available(grants)
        }
        Some(HostGate::Capability(capability)) => {
            let Ok(needed) = synra_capability::Capability::parse(capability) else {
                // A capability in the table that does not parse is a bug in the contract, which `build.rs` regenerates.
                // Refusing rather than panicking: a host that crashed on a call would be worse than one that says no.
                return false;
            };
            grants.grants(&needed)
        }
    }
}

/// Every function the host provides, by import name, sorted.
#[must_use]
pub fn provided() -> Vec<&'static str> {
    HOST_FUNCTIONS.iter().map(|(name, _)| *name).collect()
}

/// The functions with no gate, sorted.
///
/// The list a reviewer reads first: each entry is a host call **any** plugin may make, so it has to stay short and
/// each one has to be a read rather than an action.
#[must_use]
pub fn ungated() -> Vec<&'static str> {
    HOST_FUNCTIONS
        .iter()
        .filter(|(_, capability)| capability.is_none())
        .map(|(name, _)| *name)
        .collect()
}

/// The gated functions and what each needs, sorted.
#[must_use]
pub fn gated() -> Vec<(&'static str, &'static str)> {
    HOST_FUNCTIONS
        .iter()
        .filter_map(|(name, capability)| capability.map(|capability| (*name, capability)))
        .collect()
}

/// Whether a capability string is one the contract mentions.
///
/// # Why this is not "is it well formed"
///
/// A manifest declaring `storag:local:read` has a typo that no parser catches: it is a well-formed capability string
/// that no host function needs. The plugin installs, the user grants it, and the plugin's calls fail because the
/// capability it holds is not the one being checked. Comparing against the contract turns that into an install-time
/// refusal naming the string.
#[must_use]
pub fn is_declared_capability(capability: &str) -> bool {
    let Ok(candidate) = synra_capability::Capability::parse(capability) else {
        return false;
    };
    // Event subscriptions are manifest policy rather than Wasm imports. The receiver's `handles`
    // declaration selects which events enter the runtime, while this grant is checked by the event
    // worker at delivery time. Keeping it here lets the consent and verification paths recognise
    // the same capability even though no guest calls an `event-subscribe` host function.
    if candidate.domain() == Domain::Event
        && candidate
            .prefixes()
            .first()
            .is_some_and(|prefix| prefix.as_str() == "subscribe")
        && candidate.qualifier().len() == 1
    {
        return true;
    }
    CAPABILITIES
        .iter()
        .filter_map(|family| synra_capability::Capability::parse(family).ok())
        .any(|family| family.matches(&candidate))
}

/// The capabilities a set of import names would need.
///
/// Used when a component's imports are read: what the plugin actually calls, rather than what its manifest claims.
/// The two are allowed to differ in the direction of the manifest asking for *more* — a plugin that declares what it
/// might use is one whose permission dialog is honest about the worst case — and never in the direction of the
/// component calling something the manifest did not declare, which an install refuses.
#[must_use]
pub fn required_capabilities(imports: &[String]) -> Vec<&'static str> {
    let mut needed: Vec<&'static str> = imports
        .iter()
        .filter_map(|import| gate(import).and_then(HostGate::capability))
        .collect();
    needed.sort_unstable();
    needed.dedup();
    needed
}

/// The imports a plugin could not use, given what its manifest declared.
///
/// Returns the import names, so a refusal can name the function rather than the capability: a plugin author who read
/// `capability denied` and a capability string has to work out which call needed it.
#[must_use]
pub fn undeclared_imports(imports: &[String], declared: &CapabilitySet) -> Vec<String> {
    imports
        .iter()
        .filter(|import| !permits(import, declared))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests;
