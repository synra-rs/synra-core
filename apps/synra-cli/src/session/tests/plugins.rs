use clap::Parser as _;
use synra_control::Request;

use crate::args::{Cli, Command};

use super::super::commands::plugin_request;

#[test]
fn publisher_decisions_require_a_fingerprint_and_reach_the_daemon() {
    for (args, expected) in [
        (vec!["publisher", "list"], Request::PluginPublishers),
        (
            vec!["publisher", "decide", "@acme", "trusted", "--fingerprint", "AB12 CD34 EF56 7890"],
            Request::PluginPublisherDecide {
                publisher_id: "@acme".to_owned(),
                fingerprint: "AB12 CD34 EF56 7890".to_owned(),
                trust: "trusted".to_owned(),
            },
        ),
    ] {
        let cli = Cli::try_parse_from(["synra", "plugin"].into_iter().chain(args)).expect("parse");
        let question = crate::question_for(&cli.command, cli.output, || {
            plugin_request(&cli.command)
        }).expect("question");
        assert_eq!(question.request, expected);
    }
    assert!(Cli::try_parse_from([
        "synra", "plugin", "publisher", "decide", "@acme", "trusted"
    ]).is_err());
    assert!(Cli::try_parse_from([
        "synra", "plugin", "publisher", "decide", "@acme", "maybe",
        "--fingerprint", "AB12 CD34 EF56 7890"
    ]).is_err());
}

#[test]
fn plugin_update_commands_parse_and_reach_the_control_request() {
    for (args, expected) in [
        (vec!["registry"], Request::PluginRegistry { urls: None }),
        (
            vec!["registry", "https://registry.example", "static:https://cdn.example/plugins"],
            Request::PluginRegistry {
                urls: Some(vec![
                    "https://registry.example".to_owned(),
                    "static:https://cdn.example/plugins".to_owned(),
                ]),
            },
        ),
        (
            vec!["registry", "--clear"],
            Request::PluginRegistry { urls: Some(Vec::new()) },
        ),
        (
            vec!["policy", "auto-all"],
            Request::PluginUpdatePolicy { policy: Some("auto-all".to_owned()) },
        ),
        (vec!["check"], Request::PluginCheckUpdates { plugin_id: None }),
        (
            vec!["check", "@acme/hello"],
            Request::PluginCheckUpdates { plugin_id: Some("@acme/hello".to_owned()) },
        ),
        (
            vec!["update", "@acme/hello", "--version", "^1.1"],
            Request::PluginUpdate {
                plugin_id: "@acme/hello".to_owned(),
                version: Some("^1.1".to_owned()),
            },
        ),
    ] {
        let cli = Cli::try_parse_from(["synra", "plugin"].into_iter().chain(args)).expect("parse");
        assert!(matches!(cli.command, Command::Plugin(_)));
        let question = crate::question_for(&cli.command, cli.output, || {
            plugin_request(&cli.command)
        }).expect("question");
        assert_eq!(question.request, expected);
    }
    assert!(Cli::try_parse_from(["synra", "plugin", "policy", "yes"]).is_err());
    assert!(Cli::try_parse_from(["synra", "plugin", "registry", "--clear", "https://example.com"]).is_err());
}

#[test]
fn enabling_and_disabling_a_plugin_ask_the_kernel() {
    // ★ The commands that did nothing and blamed the kernel.
    //
    // Every plugin action but `list` answered `None` from `plugin_request`, and a `None` there makes the CLI report
    // "this command needs a running kernel, and none is reachable" — a false sentence about a kernel that is running,
    // which sends the user to check the wrong thing. Both actions are in the documented command list.
    let request = |action: crate::args::PluginAction| {
        plugin_request(&Command::Plugin(crate::args::PluginArgs { action }))
    };

    assert!(matches!(
        request(crate::args::PluginAction::Enable { plugin_id: "@acme/x".to_owned() }),
        Some(Request::PluginSetEnabled { enabled: true, .. })
    ));
    assert!(matches!(
        request(crate::args::PluginAction::Disable { plugin_id: "@acme/x".to_owned() }),
        Some(Request::PluginSetEnabled { enabled: false, .. })
    ));
    // The identifier survives, because a request that enabled the wrong plugin would be worse than one that enabled
    // none at all.
    let Some(Request::PluginSetEnabled { plugin_id, .. }) =
        request(crate::args::PluginAction::Enable { plugin_id: "@acme/x".to_owned() })
    else {
        panic!("expected a plugin request");
    };
    assert_eq!(plugin_id, "@acme/x");

    // ★ And installing asks the kernel, with the path the user typed. It used to ask nothing on the grounds that
    // there was no install layer — and there was not, which made a command in the documented list answer "you need a
    // running kernel" while one was running.
    //
    // ★ A name with no path separators now goes to the registry. It used to be sent as a path and refused by the
    // installer with "not a directory", which made the command's documented "or a `@scope/name` for a registry" a lie.
    let Some(Request::PluginInstallPackage { package, version }) =
        request(crate::args::PluginAction::Install {
            source: "@acme/x".to_owned(),
            version: Some("1.0.0".to_owned()),
        })
    else {
        panic!("expected a registry install request");
    };
    assert_eq!(package, "@acme/x");
    assert_eq!(version.as_deref(), Some("1.0.0"));
    let Some(Request::PluginInstall { path }) = request(crate::args::PluginAction::Install {
        source: "./build".to_owned(),
        version: None,
    }) else {
        panic!("expected an install request");
    };
    assert_eq!(path, "./build");

    // And consent carries the capabilities the user named, because a request that dropped them would record a
    // decision nobody made — every capability denied.
    let Some(Request::PluginConsent { plugin_id, granted }) =
        request(crate::args::PluginAction::Consent {
            plugin_id: "@acme/x".to_owned(),
            allow: vec!["log:*".to_owned(), "platform:open-url".to_owned()],
        })
    else {
        panic!("expected a consent request");
    };
    assert_eq!(plugin_id, "@acme/x");
    assert_eq!(granted, ["log:*", "platform:open-url"]);

    // Removing asks the kernel now, and carries the data decision with it: the flag is the only difference between
    // "remove" and "remove and delete", and a request that could not express it would make `--data` a promise with
    // nothing behind it.
    let Some(Request::PluginRemove { plugin_id, remove_data }) = request(crate::args::PluginAction::Remove {
        plugin_id: "@acme/x".to_owned(),
        data: true,
    })
    else {
        panic!("expected a remove request");
    };
    assert_eq!(plugin_id, "@acme/x");
    assert!(remove_data, "the flag reaches the kernel");
}
