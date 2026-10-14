//! Whether the imports and the grants agree on a domain.

use crate::domain::Domain;

use super::imports::ImportSet;
use super::limits::CapabilitySet;
use crate::capability::Capability;
use super::imports::EffectiveCaps;
use super::limits::SetError;

/// Why effective capabilities could not be reconciled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// A capability string was malformed.
    #[error(transparent)]
    Set(#[from] SetError),

    /// The user's grant is not a subset of what the manifest asked for.
    #[error("the grant includes {capability}, which the manifest does not request")]
    GrantNotRequested {
        /// The unexpected capability.
        capability: String,
    },

    /// The module imports an interface no granted capability covers.
    #[error("the module imports {interface}, which no granted capability covers")]
    UncoveredImport {
        /// The uncovered interface.
        interface: String,
    },
}

/// The host interface each capability domain implies.
///
/// The mapping from a capability to the Wasm interface that provides it. A module importing
/// `host:network-fetch` needs a `network:fetch:*` capability; one importing it with no network grant
/// would be calling a host function it has no authorisation for.
#[must_use]
pub const fn interface_for_domain(domain: Domain) -> &'static str {
    match domain {
        Domain::Log => "host:log",
        Domain::Event => "host:event",
        Domain::Device => "host:device",
        Domain::Storage => "host:storage",
        Domain::Network => "host:network",
        Domain::Fs => "host:fs",
        Domain::File => "host:file",
        Domain::Platform => "host:platform",
        Domain::Action => "host:action",
        Domain::Ui => "host:ui",
    }
}

/// Reconciles the three declarations of what a plugin may do.
///
/// * `wanted` — the manifest's `capabilities`, what the plugin asks for.
/// * `granted` — what the user approved. Must be a subset of `wanted`, or the grant is for something
///   the user was never shown.
/// * `imports` — the interfaces the Wasm module imports, read from its type section. A module that
///   imports an interface with no grant behind it would fail at the gate on every call, so it is
///   refused at load instead.
///
/// # Errors
///
/// [`VerifyError`] for a malformed capability, a grant outside the manifest, or an uncovered import.
pub fn verify_effective_caps(
    wanted: &CapabilitySet,
    granted: &CapabilitySet,
    imports: &ImportSet,
) -> Result<EffectiveCaps, VerifyError> {
    // 1. Every granted capability must have been requested. Otherwise the user's consent was obtained
    //    for a different set than the one being used.
    for capability in granted.iter() {
        if !wanted.contains(capability) {
            return Err(VerifyError::GrantNotRequested {
                capability: capability.to_string(),
            });
        }
    }

    // 2. Every imported interface must be covered by a grant.
    for interface in imports.iter() {
        if !interface_is_covered(granted, interface) {
            return Err(VerifyError::UncoveredImport { interface: interface.to_owned() });
        }
    }

    // 3. The effective set is the intersection of what was asked for and what was granted. The
    //    imports have already been shown to be covered, so they do not narrow it further — they
    //    constrain *calls*, which the gate checks.
    let mut effective = CapabilitySet::new();
    for capability in granted.iter() {
        if wanted.contains(capability) {
            effective.insert(capability.clone()).map_err(VerifyError::Set)?;
        }
    }

    // What was granted but the module cannot use. A warning, not an error.
    let unused: Vec<Capability> = effective
        .iter()
        .filter(|capability| !interface_is_imported(imports, capability.domain()))
        .cloned()
        .collect();

    Ok(EffectiveCaps { granted: effective, unused, uncovered: Vec::new() })
}

/// Whether any granted capability is in the domain an interface provides.
fn interface_is_covered(granted: &CapabilitySet, interface: &str) -> bool {
    Domain::ALL.iter().any(|domain| {
        interface_for_domain(*domain) == interface && granted.domains().has(*domain)
    })
}

/// Whether a module imports the interface for a domain.
fn interface_is_imported(imports: &ImportSet, domain: Domain) -> bool {
    imports.contains(interface_for_domain(domain))
}
