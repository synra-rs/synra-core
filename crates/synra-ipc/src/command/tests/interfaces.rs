use super::*;

// ── The interface separation ──────────────────────────────────────────────────────────────────

#[test]
fn the_plugin_interface_cannot_reach_a_host_command() {
    // The design document's requirement, as an executable statement. A plugin's page runs in the same WebView
    // as the host's screens, so without this a plugin could call `plugins_uninstall`.
    for command in COMMANDS {
        if command.interface == Interface::Host {
            assert!(
                !command.callable_by(Interface::Plugin),
                "{} is reachable from a plugin",
                command.name
            );
        }
    }
}

#[test]
fn the_host_interface_cannot_reach_a_plugin_command() {
    // The other direction, and it matters for a different reason: the host's screens go through the Tauri
    // bridge, and a command that expects a plugin's session token would fail in a way that reads as a bug.
    for command in COMMANDS {
        if command.interface == Interface::Plugin {
            assert!(
                !command.callable_by(Interface::Host),
                "{} is reachable from the host bridge",
                command.name
            );
        }
    }
}

#[test]
fn an_interface_always_allows_itself() {
    assert!(Interface::Host.allows(Interface::Host));
    assert!(Interface::Plugin.allows(Interface::Plugin));
}

#[test]
fn the_plugin_allow_list_is_small_and_explicit() {
    // The smallness is the design: a plugin's page reaches the kernel through a token and these verbs, and
    // everything else goes through `rpc`, whose allow-list is the plugin's capabilities rather than a name.
    let allowed = CommandRegistry::plugin_allow_list();
    assert_eq!(allowed.len(), 2, "{allowed:?}");
    assert!(allowed.contains(&"plugin_ui_rpc"));
    assert!(allowed.contains(&"plugin_ui_ready"));
}

#[test]
fn no_destructive_command_is_in_the_plugin_allow_list() {
    // An explicit assertion over the dangerous ones rather than a general rule, because the list is short and
    // a reader should be able to see which names are deliberately excluded.
    let dangerous = [
        "plugins_uninstall",
        "plugins_install",
        "identity_set_display_name",
        "devices_forget",
        "devices_pair",
        "devices_pairing_respond",
        "devices_pairing_cancel",
        "devices_pairing_snapshot",
        "config_set",
        "diag_export",
    ];
    let allowed = CommandRegistry::plugin_allow_list();
    for name in dangerous {
        assert!(
            !allowed.contains(&name),
            "{name} is reachable from a plugin page"
        );
    }
}

#[test]
fn the_registry_verifies_the_mutating_commands_are_host_only() {
    // `RegistryError::MutatingInPluginInterface` exists as a variant so the rule can be stated; the registry
    // verifies it by construction rather than by the variant being returned, and this asserts the property
    // the variant names.
    let mutating: Vec<&str> = COMMANDS
        .iter()
        .filter(|command| command.mutates && command.interface == Interface::Plugin)
        .map(|command| command.name)
        .collect();
    // The two plugin commands are marked as mutating — `rpc` performs whatever the plugin asked for and
    // `ready` records a state — and that is deliberate: the *token* is what limits them, not the verb.
    assert_eq!(mutating, vec!["plugin_ui_rpc", "plugin_ui_ready"]);

    // So the variant is reachable in principle but not from this table, which is worth knowing: a caller that
    // saw it come out of `verify` would be looking at a different table.
    assert!(!matches!(
        CommandRegistry::verify(),
        Err(RegistryError::MutatingInPluginInterface { .. })
    ));
}
