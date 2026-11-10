use synra_capability::CapabilitySet;
use super::{
    CAPABILITIES, EXPORTED_INTERFACES, HOST_FUNCTIONS, HOST_INTERFACE, HostGate, PACKAGE,
    PACKAGE_VERSION, gate, gated, is_declared_capability, permits, provides, required_capabilities,
    undeclared_imports, ungated,
};

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
    assert!(is_declared_capability("log:info"));
    assert!(is_declared_capability("action:declare:debug"));
    assert!(is_declared_capability("network:fetch:example.com"));
    assert!(is_declared_capability(
        "event:subscribe:_plugin.@acme/chat.*"
    ));
    assert!(!is_declared_capability("action:unknown:debug"));
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
