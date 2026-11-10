use super::{CommandDescriptor, Domain, Interface, ReturnShape};

/// The macro that keeps the table and the names in step.
///
/// A command is declared once, with its name as a string literal, and the `name` field is built from the same
/// literal. Writing the name twice — once as a Rust identifier and once as a string — is how the two drift, and a
/// drifted name is a command the front end calls and the shell does not have.
macro_rules! commands {
    ($( $name:literal => $domain:ident, $interface:ident, $returns:ident, $mutates:literal );* $(;)?) => {
        /// Every command the shell registers.
        pub const COMMANDS: &[CommandDescriptor] = &[
            $(
                CommandDescriptor {
                    name: $name,
                    domain: Domain::$domain,
                    interface: Interface::$interface,
                    returns: ReturnShape::$returns,
                    mutates: $mutates,
                },
            )*
        ];
    };
}

commands! {
    // ── identity ──
    "identity_get" => Identity, Host, One, false;
    "identity_set_display_name" => Identity, Host, Unit, true;

    // ── devices ──
    "devices_snapshot" => Devices, Host, One, false;
    "devices_scan_start" => Devices, Host, One, true;
    "devices_scan_cancel" => Devices, Host, Unit, true;
    "devices_forget" => Devices, Host, Unit, true;
    "devices_pair" => Devices, Host, One, true;
    "devices_pairing_respond" => Devices, Host, One, true;
    "devices_pairing_cancel" => Devices, Host, One, true;
    "devices_pairing_snapshot" => Devices, Host, One, true;
    "devices_input_snapshot" => Devices, Host, One, false;
    "devices_input_respond" => Devices, Host, Unit, true;
    "devices_input_stop" => Devices, Host, Unit, true;


    // ── intent ──
    "intent_dispatch" => Intent, Host, One, true;
    // ★ The listing read, which the interface asked for before the contract had it.
    //
    // `HomePage.vue`'s "received" panel wanted the intents in flight, and there was no command that answers them — so the
    // page called `intent_snapshot` with no identifier (refused by the bridge, since the wrapper requires one) and read
    // `answer.value.intents`, a field no DTO has. The capability was never missing: `Board::all()` has existed since the
    // board was written, for persistence. What was missing was the name.
    "intent_list" => Intent, Host, Many, false;
    "intent_snapshot" => Intent, Host, One, false;
    "intent_decide" => Intent, Host, Unit, true;
    "intent_cancel" => Intent, Host, Unit, true;

    // ── transfer ──
    "transfer_send_file" => Transfer, Host, One, true;
    "transfer_send_text" => Transfer, Host, One, true;
    "transfer_cancel" => Transfer, Host, Unit, true;
    "transfer_respond" => Transfer, Host, Unit, true;
    "transfer_list" => Transfer, Host, Many, false;
    // ★ The files that already landed. `transfer_list` is the in-flight registry and a finished transfer leaves it; the
    // inbox is what remains, and it is read rather than remembered.
    "transfer_received" => Transfer, Host, Many, false;
    // ★ Opening a received file. It changes nothing in the kernel; the path is checked against the inbox before the
    // platform is asked to launch anything.
    "transfer_open" => Transfer, Host, Unit, false;
    // ★ Showing where a received file is. Like opening it, the path is checked against the inbox before the platform
    // is asked to reveal anything.
    "transfer_reveal" => Transfer, Host, Unit, false;
    // ★ Removing a received file from the inbox. Destructive, so the interface asks first; the shell still checks the
    // path is inside the inbox before it deletes anything.
    "transfer_discard" => Transfer, Host, Unit, true;

    // ── plugins ──
    "plugins_list" => Plugins, Host, Many, false;
    "plugins_catalog_search" => Plugins, Host, Many, false;
    "plugins_preview" => Plugins, Host, One, false;
    "plugins_install" => Plugins, Host, One, true;
    "plugins_uninstall" => Plugins, Host, One, true;
    "plugins_enable" => Plugins, Host, Unit, true;
    "plugins_disable" => Plugins, Host, Unit, true;
    "plugins_consent_respond" => Plugins, Host, Unit, true;
    // ★ What the background pass last found, so the page can show the update buttons without asking the registry again
    // on open. A read of a cached answer: no network, and empty means "nothing known", not "checked and none".
    "plugins_updates" => Plugins, Host, Many, false;
    "plugins_check_update" => Plugins, Host, Maybe, false;
    "plugins_update" => Plugins, Host, One, true;
    // ★ Retry a load without changing a flag. A faulted plugin is enabled and trusted; what failed was starting it,
    // so switching it off and on again was the only way to ask again. This asks directly and answers with the card.
    "plugins_reload" => Plugins, Host, One, true;
    "plugins_sync_plan" => Plugins, Host, One, false;
    "plugins_sync_run" => Plugins, Host, One, true;
    "plugins_publishers" => Plugins, Host, Many, false;
    "plugins_publisher_decide" => Plugins, Host, Unit, true;
    "plugins_audit" => Plugins, Host, Many, false;
    // ★ The user's half of the audit: reading it was implemented first, and 18 §5.2 has always asked for "clear this
    // plugin's history" beside it. `Many` and `false` on the read, `Unit` and `true` here — clearing is the one audit verb
    // that changes anything.
    "plugins_audit_clear" => Plugins, Host, Unit, true;
    "plugins_request_registry_search" => Plugins, Host, Many, true;

    // ── the plugin interface ──
    //
    // Two commands, and the smallness is the design. A plugin's page reaches the kernel through a session token
    // and *these* verbs; everything else it wants goes through `rpc`, whose allow-list is the plugin's granted
    // capabilities rather than a command name.
    "plugin_ui_rpc" => PluginUi, Plugin, One, true;
    "plugin_ui_ready" => PluginUi, Plugin, Unit, true;
    // ★ `Host`, and that is the whole point of the row: opening a page is the **host's** act. A plugin page that could ask
    // for another page would be a plugin that can spawn windows, which is not a capability this model grants.
    "plugin_ui_open" => PluginUi, Host, Unit, true;

    // ── config ──
    "config_get" => Config, Host, One, false;
    "config_set" => Config, Host, Unit, true;

    // ── diagnostics ──
    "diag_export" => Diag, Host, One, true;
    // ★ The probes the CLI runs before a first start, answered to the window too: a user whose app cannot bind or find
    // its data directory should be able to see the reason without a terminal. Reads the machine, changes nothing.
    "diag_probes" => Diag, Host, One, false;
    "diag_metrics" => Diag, Host, One, false;
    "diag_logs_tail" => Diag, Host, Many, false;
    // ★ The user's "ignore" for the crash prompt: the reports that make the next start enter safe mode are deleted,
    // so a fixed installation starts normally instead of waiting five minutes for them to age out.
    "diag_crash_dismiss" => Diag, Host, Unit, true;
    // ★ "查看详情" for the same prompt: the reports the dismiss deletes, newest first.
    "diag_crashes" => Diag, Host, Many, false;
}
