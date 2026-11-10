use super::super::{Command, PluginAction};
use super::{parse, parsed};

#[test]
fn plugin_list_defaults_to_enabled_plugins() {
    let Command::Plugin(args) = parsed(&["synra", "plugin", "list"]).command else {
        panic!("expected plugin");
    };
    let PluginAction::List { all } = args.action else {
        panic!("expected list");
    };
    assert!(
        !all,
        "a disabled plugin is not one the user is looking for by default"
    );
}

#[test]
fn plugin_install_takes_a_path_or_a_registry_name() {
    let Command::Plugin(args) = parsed(&["synra", "plugin", "install", "./chat.synra"]).command
    else {
        panic!("expected plugin");
    };
    let PluginAction::Install { source, version } = args.action else {
        panic!("expected install");
    };
    assert_eq!(source, "./chat.synra");
    assert_eq!(version, None);

    let Command::Plugin(args) = parsed(&[
        "synra",
        "plugin",
        "install",
        "@synra-plugin/chat",
        "--version",
        "1.0.0",
    ])
    .command
    else {
        panic!("expected plugin");
    };
    let PluginAction::Install { version, .. } = args.action else {
        panic!("expected install");
    };
    assert_eq!(version.as_deref(), Some("1.0.0"));
}

#[test]
fn plugin_reinstall_names_the_container() {
    // The container is the source of the list and of the origins inside it; naming it is the whole input.
    let Command::Plugin(args) =
        parsed(&["synra", "plugin", "reinstall", "device.synrabackup"]).command
    else {
        panic!("expected plugin");
    };
    let PluginAction::Reinstall { from } = args.action else {
        panic!("expected reinstall");
    };
    assert_eq!(from, std::path::PathBuf::from("device.synrabackup"));
}

#[test]
fn plugin_remove_keeps_the_data_unless_asked() {
    // Removing a plugin the user may reinstall should keep its settings; one they do not trust is what the flag is
    // for.
    let Command::Plugin(args) =
        parsed(&["synra", "plugin", "remove", "@synra-plugin/chat"]).command
    else {
        panic!("expected plugin");
    };
    let PluginAction::Remove { data, .. } = args.action else {
        panic!("expected remove");
    };
    assert!(!data);

    let Command::Plugin(args) =
        parsed(&["synra", "plugin", "remove", "@synra-plugin/chat", "--data"]).command
    else {
        panic!("expected plugin");
    };
    let PluginAction::Remove { data, .. } = args.action else {
        panic!("expected remove");
    };
    assert!(data);
}

#[test]
fn a_plugin_action_needs_its_plugin() {
    assert!(parse(&["synra", "plugin", "enable"]).is_err());
    assert!(parse(&["synra", "plugin", "remove"]).is_err());
    assert!(parse(&["synra", "plugin", "install"]).is_err());
}

// ── Logs ──────────────────────────────────────────────────────────────────────────────────────
