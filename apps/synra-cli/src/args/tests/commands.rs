use clap::CommandFactory as _;
use super::super::{Cli, OutputFormat};
use super::{parse, parsed};

#[test]
fn the_parser_is_internally_consistent() {
    // `clap`'s own check for a command tree it cannot describe: two flags with one long name, a subcommand with a
    // required argument that has no help, and so on. It is a build failure rather than something a user finds.
    Cli::command().debug_assert();
}

#[test]
fn every_documented_command_exists() {
    // The design document's list, as an executable statement. A command in the document and not here is one a
    // user types and gets an error for.
    for args in [
        vec!["synra", "devices"],
        vec!["synra", "status"],
        vec!["synra", "send", "--to", "dev_a", "--text", "hi"],
        vec!["synra", "send", "--to", "dev_a", "--file", "a.txt"],
        vec!["synra", "plugin", "list"],
        vec!["synra", "plugin", "install", "@synra-plugin/chat"],
        vec!["synra", "plugin", "enable", "@synra-plugin/chat"],
        vec!["synra", "plugin", "disable", "@synra-plugin/chat"],
        vec!["synra", "plugin", "remove", "@synra-plugin/chat"],
        vec!["synra", "logs"],
        vec!["synra", "doctor"],
        vec!["synra", "db", "dump"],
        vec!["synra", "share", "https://example.com"],
        vec![
            "synra",
            "intent",
            "show",
            "01a140ce-0000-7000-8000-000000000000",
        ],
    ] {
        assert!(parse(&args).is_ok(), "{args:?} should parse");
    }
}

#[test]
fn an_unknown_command_is_refused() {
    assert!(parse(&["synra", "devices_"]).is_err());
    assert!(
        parse(&["synra"]).is_err(),
        "a bare invocation needs a subcommand"
    );
}

#[test]
fn the_help_subcommand_is_disabled() {
    // `clap` adds a `help` subcommand by default, and it collides with a future command of that name while
    // shadowing the flag. The flag is what a user already reaches for.
    let command = Cli::command();
    let names: Vec<&str> = command
        .get_subcommands()
        .map(|sub| sub.get_name())
        .collect();
    assert!(!names.contains(&"help"), "{names:?}");
    assert!(
        parse(&["synra", "--help"]).is_err(),
        "`--help` exits rather than parsing"
    );
}

// ── Output format ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_output_format_is_global_and_defaults_to_prose() {
    // Global so it can go before or after the subcommand: a user who types it in the wrong place should not have
    // to be told where it goes.
    assert!(parsed(&["synra", "status"]).output.is_none());
    assert_eq!(
        parsed(&["synra", "--output", "json", "status"]).output,
        Some(OutputFormat::Json)
    );
    assert_eq!(
        parsed(&["synra", "status", "--output", "json"]).output,
        Some(OutputFormat::Json)
    );
    assert_eq!(
        parsed(&["synra", "--output", "text", "status"]).output,
        Some(OutputFormat::Text)
    );
}

#[test]
fn an_unknown_output_format_is_refused() {
    // A typo that silently fell back to prose would make a script parse the wrong thing.
    assert!(parse(&["synra", "--output", "yaml", "status"]).is_err());
}

// ── Devices ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_parser_lives_in_the_library_rather_than_in_main() {
    // The design document requires `main.rs` to be at most sixty lines with the logic here, and a CI guard checks
    // the count. This asserts the half that can be asserted from inside: that the whole command surface is
    // reachable without `main`.
    assert!(Cli::command().get_name() == "synra");
    // Counted rather than named, so adding a command without adding it here is a failure — and the count is what
    // makes the list above (`every_documented_command_exists`) meaningful: a command that parses but is not on the
    // command surface would be one clap never dispatches to.
    assert_eq!(Cli::command().get_subcommands().count(), 9);
}
