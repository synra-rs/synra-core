use super::*;

// ── The registry ──────────────────────────────────────────────────────────────────────────────

#[test]
fn the_registry_is_internally_consistent() {
    // Prefixes, duplicates and spelling, all at once: a registry that is wrong is a build failure rather than
    // something a user discovers.
    assert_eq!(CommandRegistry::verify(), Ok(()));
}

#[test]
fn every_command_the_design_document_lists_exists() {
    // ★ What this test does and does not check.
    //
    // The comment here used to read: "A command in the document and not here is one the front end calls and the shell
    // does not have." That is the failure worth catching, and this test cannot see it. Both lists below and in the
    // registry are maintained by hand **in this file**, so the assertion is a hand-written list against a table
    // written from it — it compares two copies of the same decision, not the decision against the shell.
    //
    // The gap it cannot see is real and larger: of the names below, only twelve are registered with Tauri in
    // `synra-rust-app/src-tauri/src/main.rs`. A front end calling `pairing_request` reaches a command the shell does
    // not have, which is exactly the sentence above.
    //
    // What this test *is* good for is the other direction, and it is worth keeping for that: a name removed from the
    // registry while the contract still lists it fails here, and the counts must agree. The half about the shell is
    // checked where the shell is — `synra-rust-app/src/ipc/registration.test.ts` — because a test in this crate
    // cannot read that file without reaching out of the workspace.
    let documented = [
        // identity
        "identity_get",
        "identity_set_display_name",
        // devices
        "devices_snapshot",
        "devices_scan_start",
        "devices_scan_cancel",
        "devices_forget",
        "devices_pair",
        "devices_pairing_respond",
        "devices_pairing_cancel",
        "devices_pairing_snapshot",
        "devices_input_snapshot",
        "devices_input_respond",
        "devices_input_stop",
        // pairing
        // intent
        "intent_dispatch",
        "intent_list",
        "intent_snapshot",
        "intent_decide",
        "intent_cancel",
        // transfer
        "transfer_send_file",
        "transfer_send_text",
        "transfer_cancel",
        "transfer_respond",
        "transfer_list",
        "transfer_received",
        "transfer_open",
        "transfer_reveal",
        "transfer_discard",
        // plugins
        "plugins_list",
        "plugins_catalog_search",
        "plugins_preview",
        "plugins_install",
        "plugins_uninstall",
        "plugins_enable",
        "plugins_disable",
        "plugins_consent_respond",
        "plugins_updates",
        "plugins_check_update",
        "plugins_update",
        "plugins_reload",
        "plugins_sync_plan",
        "plugins_sync_run",
        "plugins_publishers",
        "plugins_publisher_decide",
        "plugins_audit",
        "plugins_audit_clear",
        "plugins_request_registry_search",
        // plugin ui
        "plugin_ui_rpc",
        "plugin_ui_ready",
        "plugin_ui_open",
        // config
        "config_get",
        "config_set",
        // diagnostics
        "diag_export",
        "diag_probes",
        "diag_metrics",
        "diag_logs_tail",
        "diag_crash_dismiss",
        "diag_crashes",
    ];

    for name in documented {
        assert!(
            CommandRegistry::find(name).is_some(),
            "{name} is documented and missing"
        );
    }
    assert_eq!(
        documented.len(),
        CommandRegistry::len(),
        "the registry has commands the document does not"
    );
}

#[test]
fn a_command_can_be_found_by_name() {
    let command = CommandRegistry::find("devices_snapshot").expect("exists");
    assert_eq!(command.domain, Domain::Devices);
    assert_eq!(command.interface, Interface::Host);
    assert_eq!(command.returns, ReturnShape::One);
    assert!(!command.mutates);
}

#[test]
fn an_unknown_command_is_not_found_rather_than_guessed() {
    // The shell refuses a name it does not have; it does not fall back to something similar.
    assert!(CommandRegistry::find("devices_snapshot_").is_none());
    assert!(CommandRegistry::find("Devices_Snapshot").is_none());
    assert!(CommandRegistry::find("").is_none());
    assert!(CommandRegistry::find("device_snapshot").is_none());
}

#[test]
fn every_command_belongs_to_a_domain_that_exists() {
    // A command filed under no domain is one whose prefix check passes vacuously.
    for command in COMMANDS {
        assert!(Domain::ALL.contains(&command.domain), "{}", command.name);
    }
    let total: usize = Domain::ALL
        .iter()
        .map(|domain| CommandRegistry::in_domain(*domain).len())
        .sum();
    assert_eq!(
        total,
        CommandRegistry::len(),
        "some command is in no domain"
    );
}

#[test]
fn every_domain_has_a_command() {
    // An empty domain is a group the front end has a module for and nothing to put in it.
    for domain in Domain::ALL {
        assert!(
            !CommandRegistry::in_domain(*domain).is_empty(),
            "{domain:?} has no commands"
        );
    }
}

// ── Reporting ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_interface_can_be_listed() {
    let host = CommandRegistry::for_interface(Interface::Host);
    let plugin = CommandRegistry::for_interface(Interface::Plugin);
    assert_eq!(host.len() + plugin.len(), CommandRegistry::len());
    assert_eq!(plugin.len(), 2);
    for command in &host {
        assert_eq!(command.interface, Interface::Host);
    }
}

#[test]
fn a_domain_can_be_listed() {
    let devices = CommandRegistry::in_domain(Domain::Devices);
    assert_eq!(devices.len(), 11);
    for command in devices {
        assert_eq!(command.domain, Domain::Devices);
        assert!(command.name.starts_with("devices_"));
    }
}

#[test]
fn an_interface_has_a_name_for_a_log_line() {
    assert_eq!(Interface::Host.as_str(), "host");
    assert_eq!(Interface::Plugin.as_str(), "plugin");
}

#[test]
fn registry_errors_explain_themselves() {
    let errors = [
        RegistryError::PrefixMismatch {
            name: "device_snapshot".to_owned(),
            domain: "devices",
            prefix: "devices_",
        },
        RegistryError::Duplicate {
            name: "devices_snapshot".to_owned(),
        },
        RegistryError::BadName {
            name: "DevicesSnapshot".to_owned(),
        },
        RegistryError::MutatingInPluginInterface {
            name: "plugins_uninstall".to_owned(),
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn the_registry_is_the_default_value_it_claims_to_be() {
    assert_eq!(CommandRegistry::len(), COMMANDS.len());
    assert!(CommandRegistry::len() > 30);
}
