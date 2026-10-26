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

use synra_capability::CapabilitySet;

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
        Some(HostGate::Capability("log:*")) => crate::host_calls::log_scope::available(grants),
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
    CAPABILITIES.contains(&capability)
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
mod tests {
    use super::*;

    fn grants(texts: &[&str]) -> CapabilitySet {
        let mut set = CapabilitySet::new();
        for text in texts {
            set.insert_str(text).expect("a valid capability");
        }
        set
    }

    // ── The table itself ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_table_is_not_empty_and_every_entry_is_named() {
        // A generated file that was truncated or overwritten would produce a host that answers no call — and every
        // other test here would pass vacuously against an empty table, so this one counts.
        assert!(HOST_FUNCTIONS.len() > 30, "only {} functions", HOST_FUNCTIONS.len());
        for (name, _) in HOST_FUNCTIONS {
            assert!(name.starts_with("synra:plugin/host#"), "{name}");
            assert!(name.len() > "synra:plugin/host#".len(), "{name}");
        }
    }

    #[test]
    fn the_table_is_sorted_so_a_lookup_and_a_diff_agree() {
        // The generator sorts it; this asserts the property, because a hand-edit of the generated file would be the one
        // way it could stop being sorted — and the file says not to edit it, which is not a check.
        let names: Vec<&str> = HOST_FUNCTIONS.iter().map(|(name, _)| *name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        // And a binary search would work, which is what the sort is for.
        assert!(names.windows(2).all(|pair| pair[0] != pair[1]), "a duplicate name");
    }

    #[test]
    fn the_package_is_what_the_contract_declares() {
        assert_eq!(PACKAGE, "synra:plugin");
        assert_eq!(PACKAGE_VERSION, "1.0.0");
        assert_eq!(HOST_INTERFACE, "host");
    }

    #[test]
    fn the_host_and_the_plugin_exports_are_different_interfaces() {
        // A name in both would make the import check answer for an entry point the plugin implements rather than the
        // host provides.
        for exported in EXPORTED_INTERFACES {
            assert_ne!(*exported, HOST_INTERFACE, "{exported} is both imported and exported");
        }
        for expected in ["lifecycle", "share", "actions"] {
            assert!(EXPORTED_INTERFACES.contains(&expected), "{expected} is not exported");
        }
    }

    // ── The lookup ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_gated_function_reports_its_capability() {
        assert_eq!(
            gate("synra:plugin/host#log"),
            Some(HostGate::Capability("log:*"))
        );
        assert!(provides("synra:plugin/host#log"));
        assert!(!permits("synra:plugin/host#log", &CapabilitySet::new()));
        assert!(permits("synra:plugin/host#log", &grants(&["log:*"])));
    }

    #[test]
    fn an_ungated_function_reports_nothing_to_check() {
        assert_eq!(gate("synra:plugin/host#env-sdk-version"), Some(HostGate::Ungated));
        // And it permits with nothing granted, which is the whole point of the exception.
        assert!(permits("synra:plugin/host#env-sdk-version", &CapabilitySet::new()));
    }

    #[test]
    fn an_unknown_function_is_not_a_function() {
        // ★ `None` and `Ungated` are different answers: collapsing them would make a function this host does not
        // provide look like one it provides without checking anything — the answer that lets a call through.
        assert_eq!(gate("synra:plugin/host#teleport"), None);
        assert!(!provides("synra:plugin/host#teleport"));
        assert!(!permits("synra:plugin/host#teleport", &grants(&["log:*"])));
    }

    #[test]
    fn a_bare_function_name_is_not_an_import() {
        // The name is the full import, because the interface is part of what a component names. A lookup on `log`
        // alone would match a function of that name in another interface.
        assert_eq!(gate("log"), None);
        assert!(!provides("log"));
    }

    #[test]
    fn a_prefix_is_not_a_match() {
        // The bug the plugin CLI had with `synra:host/exec` and `execute`, in the same shape: a name that is a prefix of
        // a provided one must not resolve.
        // `log` *is* a function and its import is the full name. What must not resolve is a *shorter* name that happens
        // to be a prefix of a real import, because the lookup is an equality rather than a prefix test.
        assert!(provides("synra:plugin/host#log"));
        assert!(!provides("synra:plugin/host#logg"));
        assert!(!provides("synra:plugin/host"));
        assert!(!provides("synra:plugin"));
        assert!(!provides("synra:plugin/host#"));
    }

    // ── The lists ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_ungated_list_is_short_and_every_entry_is_a_read() {
        // ★ The list a reviewer reads first. Each entry is a host call any plugin may make, so the assertions are that
        // it is short and that nothing on it is an action.
        let ungated = ungated();
        assert!(!ungated.is_empty(), "nothing is ungated, which the contract does not intend");
        assert!(ungated.len() <= 10, "{} ungated functions: {ungated:?}", ungated.len());
        for name in &ungated {
            let short = name.rsplit('#').next().unwrap_or(name);
            assert!(
                short.starts_with("env-") || short == "platform-capabilities" || short == "plugin-id",
                "{name} is ungated and is not a read-only fact"
            );
        }
    }

    #[test]
    fn nothing_dangerous_is_ungated() {
        // Named individually, because "the list is short" is not the same statement as "these are not on it".
        let ungated = ungated();
        for dangerous in [
            "synra:plugin/host#platform-simulate-keys",
            "synra:plugin/host#platform-read-clipboard",
            "synra:plugin/host#platform-write-clipboard",
            "synra:plugin/host#storage-set",
            "synra:plugin/host#secret-get",
            "synra:plugin/host#network-fetch",
            "synra:plugin/host#action-invoke",
        ] {
            assert!(!ungated.contains(&dangerous), "{dangerous} is ungated");
        }
    }

    #[test]
    fn the_gated_and_ungated_lists_partition_the_table() {
        // No function is both and none is neither, which is what makes the two lists the whole surface.
        let gated = gated();
        let ungated = ungated();
        assert_eq!(gated.len() + ungated.len(), HOST_FUNCTIONS.len());
        for (name, _) in &gated {
            assert!(!ungated.contains(name), "{name} is on both lists");
        }
    }

    #[test]
    fn every_capability_in_the_table_is_in_the_capability_list() {
        // The list a manifest is validated against. A capability the table needs and the list lacks would be one no
        // manifest could declare — a function reachable by nobody.
        for (name, capability) in gated() {
            assert!(
                is_declared_capability(capability),
                "{name} needs {capability}, which CAPABILITIES does not list"
            );
        }
    }

    #[test]
    fn the_dangerous_capabilities_are_each_their_own() {
        // A plugin that notifies has no business simulating keystrokes, and one capability for both would make the
        // permission dialog ask for both.
        for capability in [
            "platform:notify",
            "platform:simulate-keys",
            "platform:read-clipboard",
            "platform:write-clipboard",
            "storage:local:read",
            "storage:local:write",
            "storage:secure:read",
            "storage:secure:write",
        ] {
            assert!(is_declared_capability(capability), "{capability} is not declared");
        }
    }

    #[test]
    fn a_typo_in_a_capability_is_not_a_capability() {
        // ★ The failure this check exists for: a well-formed string that no host function needs. The plugin installs,
        // the user grants it, and every call fails because the capability held is not the one checked.
        assert!(is_declared_capability("log:*"));
        assert!(!is_declared_capability("storag:local:read"));
        assert!(!is_declared_capability("log"));
        assert!(!is_declared_capability(""));
        // And case matters: a capability is a string the kernel compares.
        assert!(!is_declared_capability("LOG:*"));
    }

    // ── What a set of imports needs ───────────────────────────────────────────────────────────────

    #[test]
    fn the_required_capabilities_are_derived_from_the_imports() {
        let needed = required_capabilities(&[
            "synra:plugin/host#log".to_owned(),
            "synra:plugin/host#storage-get".to_owned(),
            "synra:plugin/host#env-sdk-version".to_owned(),
        ]);
        assert_eq!(needed, vec!["log:*", "storage:local:read"]);
        // Ungated and unknown imports need nothing: the first is permitted without a grant and the second is refused
        // by `provides`, not by a capability.
        assert!(required_capabilities(&["synra:plugin/host#teleport".to_owned()]).is_empty());
    }

    #[test]
    fn the_required_capabilities_are_sorted_and_deduplicated() {
        // Two functions may share a capability, and a caller building a manifest from this must not declare it twice.
        let needed = required_capabilities(&[
            "synra:plugin/host#storage-get".to_owned(),
            "synra:plugin/host#storage-keys".to_owned(),
            "synra:plugin/host#log".to_owned(),
        ]);
        assert_eq!(needed, vec!["log:*", "storage:local:read"]);
    }

    #[test]
    fn an_undeclared_import_is_named_rather_than_its_capability() {
        // A plugin author who read `capability denied` and a capability string has to work out which call needed it.
        let undeclared = undeclared_imports(
            &[
                "synra:plugin/host#log".to_owned(),
                "synra:plugin/host#storage-set".to_owned(),
                "synra:plugin/host#teleport".to_owned(),
            ],
            &grants(&["log:*"]),
        );
        assert_eq!(
            undeclared,
            vec!["synra:plugin/host#storage-set", "synra:plugin/host#teleport"]
        );
    }

    #[test]
    fn nothing_is_undeclared_when_everything_is_granted() {
        // The positive case, so the check is not one that refuses everything.
        let all: Vec<String> = gated().iter().map(|(name, _)| (*name).to_owned()).collect();
        let mut granted = CapabilitySet::new();
        for capability in CAPABILITIES {
            granted.insert_str(capability).expect("a valid capability");
        }
        assert!(undeclared_imports(&all, &granted).is_empty());
    }

    #[test]
    fn a_wildcard_grant_satisfies_the_functions_it_covers() {
        // `log:*` is a pattern, not a literal, and the manifest's own validation is what decides whether a plugin may
        // ask for one. Here what matters is that a granted wildcard permits every function it covers.
        let log_functions: Vec<String> = gated()
            .iter()
            .filter(|(_, capability)| *capability == "log:*")
            .map(|(name, _)| (*name).to_owned())
            .collect();
        assert!(!log_functions.is_empty());
        assert!(undeclared_imports(&log_functions, &grants(&["log:*"])).is_empty());
    }
}
