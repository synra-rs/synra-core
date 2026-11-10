//! The command surface: what a user types, and what it means.
//!
//! # Why the parser is a value
//!
//! The command line is a contract with a person, and the failures it produces are the ones a person reads: a missing
//! flag, an unknown subcommand, two flags that contradict each other. Every one of those is decidable from the
//! arguments alone, so putting them in a type worth testing means the failures are tested rather than discovered by
//! whoever types the command wrong.
//!
//! It is also what keeps `main.rs` short. The design document requires it to be at most sixty lines with the logic in
//! this crate's library, because a `main` that grew would be a `main` that holds the one part of a CLI nobody writes
//! tests for.
//!
//! # Flags that contradict each other are refused
//!
//! `send --text "hi" --file a.txt` is not "one of them wins". It is a user who meant one thing and typed two, and
//! guessing produces a message that goes somewhere they did not intend. `clap`'s `conflicts_with` makes it an error
//! with both flags in the message.
//!
//! # The subcommands mirror the kernel's aggregates
//!
//! `devices`, `status`, `send`, `plugin`, `logs`, `doctor`, `db`. Not one command per Tauri command — the interface
//! has forty because it drives every screen, and a person on a terminal wants seven. The mapping is the aggregate,
//! which is why a new kernel feature tends to land inside an existing group rather than adding a command.

mod common;
mod misc;
mod plugins;

pub use common::*;
pub use misc::*;
pub use plugins::*;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn parsed(args: &[&str]) -> Cli {
        parse(args).expect("parses")
    }

    // ── The command surface ───────────────────────────────────────────────────────────────────────

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
    fn devices_defaults_to_paired_only_and_no_scan() {
        // A paired device is one the user has decided about, and a list mixing in everything heard on the network is
        // one where the interesting entries are hard to find.
        let cli = parsed(&["synra", "devices"]);
        let Command::Devices(args) = cli.command else {
            panic!("expected devices");
        };
        assert!(!args.all);
        assert!(!args.cached);
        assert_eq!(args.scan_ms, None);
    }

    #[test]
    fn devices_accepts_a_scan_and_a_cache_read_but_not_both() {
        // Scanning and reading the cache are opposite requests. Accepting both would mean one of them silently losing.
        let Command::Devices(scan) = parsed(&["synra", "devices", "--scan-ms", "2500"]).command
        else {
            panic!("expected devices");
        };
        assert_eq!(scan.scan_ms, Some(2_500));

        let Command::Devices(cached) = parsed(&["synra", "devices", "--cached"]).command else {
            panic!("expected devices");
        };
        assert!(cached.cached);

        assert!(parse(&["synra", "devices", "--scan-ms", "2500", "--cached"]).is_err());
    }

    // ── Send ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn send_requires_a_target_and_a_payload() {
        // Both are required, and they are required in different places: the target by `clap`, because "which device"
        // is a flag a user plainly has to give, and the payload by `SendArgs::payload`, because "one of two flags"
        // with a sentence naming both is a better message than a usage line.
        assert!(
            parse(&["synra", "send", "--text", "hi"]).is_err(),
            "no target"
        );
        assert!(
            parse(&["synra", "send", "--to", "dev_a"]).is_ok(),
            "the parser accepts it, and `payload` is what refuses it"
        );
        let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a"]).command else {
            panic!("expected send");
        };
        assert_eq!(args.payload(), Err(PayloadError::NothingToSend));
    }

    #[test]
    fn send_refuses_both_payloads_at_the_parser() {
        // Not "one of them wins": a user who typed both meant one thing, and guessing produces a message that goes
        // somewhere they did not intend.
        let error = parse(&[
            "synra", "send", "--to", "dev_a", "--text", "hi", "--file", "a.txt",
        ])
        .expect_err("should be refused");
        let text = error.to_string();
        assert!(text.contains("text"), "{text}");
        assert!(text.contains("file"), "{text}");
    }

    #[test]
    fn send_carries_text() {
        let Command::Send(args) =
            parsed(&["synra", "send", "--to", "dev_a", "--text", "hi"]).command
        else {
            panic!("expected send");
        };
        assert_eq!(args.to, "dev_a");
        assert_eq!(args.payload(), Ok(Payload::Text("hi")));
    }

    #[test]
    fn send_carries_a_file() {
        let Command::Send(args) =
            parsed(&["synra", "send", "--to", "dev_a", "--file", "a.txt"]).command
        else {
            panic!("expected send");
        };
        assert_eq!(args.payload(), Ok(Payload::File("a.txt")));
    }

    #[test]
    fn a_payload_built_in_code_is_checked_too() {
        // `clap` cannot be reached by a caller building the arguments directly, and the two shapes it refuses are the
        // two that would otherwise be decided by whichever field a caller read first.
        let neither = SendArgs {
            to: "dev_a".to_owned(),
            text: None,
            file: None,
            context: None,
        };
        assert_eq!(neither.payload(), Err(PayloadError::NothingToSend));

        let both = SendArgs {
            to: "dev_a".to_owned(),
            text: Some("hi".to_owned()),
            file: Some("a.txt".to_owned()),
            context: None,
        };
        assert_eq!(both.payload(), Err(PayloadError::Both));
    }

    #[test]
    fn send_accepts_a_context() {
        let Command::Send(args) = parsed(&[
            "synra",
            "send",
            "--to",
            "dev_a",
            "--text",
            "hi",
            "--context",
            "c1",
        ])
        .command
        else {
            panic!("expected send");
        };
        assert_eq!(args.context.as_deref(), Some("c1"));
    }

    #[test]
    fn an_empty_payload_is_text_rather_than_nothing() {
        // `--text ""` is a user sending an empty message, which is a thing people do. Treating it as "no payload"
        // would refuse a valid invocation.
        let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a", "--text", ""]).command
        else {
            panic!("expected send");
        };
        assert_eq!(args.payload(), Ok(Payload::Text("")));
    }

    // ── Plugins ───────────────────────────────────────────────────────────────────────────────────

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

    #[test]
    fn logs_defaults_to_a_hundred_lines_and_no_follow() {
        let Command::Logs(args) = parsed(&["synra", "logs"]).command else {
            panic!("expected logs");
        };
        assert_eq!(args.lines, 100);
        assert!(!args.follow);
        assert!(!args.verbose);
        assert_eq!(args.trace, None);
    }

    #[test]
    fn logs_follows_and_filters() {
        let Command::Logs(args) = parsed(&[
            "synra",
            "logs",
            "--follow",
            "--trace",
            "t1",
            "--lines",
            "10",
            "--verbose",
        ])
        .command
        else {
            panic!("expected logs");
        };
        assert!(args.follow);
        assert!(args.verbose);
        assert_eq!(args.trace.as_deref(), Some("t1"));
        assert_eq!(args.lines, 10);
    }

    #[test]
    fn logs_follow_has_a_short_form() {
        // Because it is the flag a user types most, and typing `--follow` while watching a log is friction.
        let Command::Logs(args) = parsed(&["synra", "logs", "-f"]).command else {
            panic!("expected logs");
        };
        assert!(args.follow);
    }

    #[test]
    fn a_line_count_that_is_not_a_number_is_refused() {
        assert!(parse(&["synra", "logs", "--lines", "many"]).is_err());
        assert!(parse(&["synra", "logs", "--lines", "-1"]).is_err());
    }

    // ── Doctor and db ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn doctor_reports_everything_by_default() {
        // A user running `doctor` wants the whole picture; `--failures-only` is for a script.
        let Command::Doctor(args) = parsed(&["synra", "doctor"]).command else {
            panic!("expected doctor");
        };
        assert!(!args.failures_only);
        assert_eq!(args.bundle, None);
    }

    #[test]
    fn doctor_can_write_a_bundle_and_be_quiet() {
        let Command::Doctor(args) = parsed(&[
            "synra",
            "doctor",
            "--failures-only",
            "--bundle",
            "/tmp/d.json",
        ])
        .command
        else {
            panic!("expected doctor");
        };
        assert!(args.failures_only);
        assert_eq!(args.bundle.as_deref(), Some("/tmp/d.json"));
    }

    #[test]
    fn db_dump_takes_an_optional_table() {
        let Command::Db(args) = parsed(&["synra", "db", "dump"]).command else {
            panic!("expected db");
        };
        let DbAction::Dump { table } = args.action else {
            panic!("expected dump");
        };
        assert_eq!(table, None);

        let Command::Db(args) = parsed(&["synra", "db", "dump", "--table", "plugins"]).command
        else {
            panic!("expected db");
        };
        let DbAction::Dump { table } = args.action else {
            panic!("expected dump");
        };
        assert_eq!(table.as_deref(), Some("plugins"));
    }

    #[test]
    fn db_integrity_needs_nothing() {
        let Command::Db(args) = parsed(&["synra", "db", "integrity"]).command else {
            panic!("expected db");
        };
        assert!(matches!(args.action, DbAction::Integrity));
    }

    #[test]
    fn db_restore_names_the_backup_to_restore_from() {
        let Command::Db(args) = parsed(&["synra", "db", "restore", "old.db"]).command else {
            panic!("expected db");
        };
        let DbAction::Restore { path } = args.action else {
            panic!("expected restore");
        };
        assert_eq!(path, std::path::PathBuf::from("old.db"));
    }

    #[test]
    fn payload_errors_explain_themselves() {
        for error in [PayloadError::NothingToSend, PayloadError::Both] {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn share_asks_the_kernel_to_route_rather_than_to_send() {
        // ★ The two are opposites and the difference is the whole feature: `send` names a device and delivers to it,
        // `share` names nothing and asks every plugin which one can handle it. A `share` that quietly became a `send`
        // would look identical from the command line and do something else entirely.
        let Command::Share(args) = parsed(&["synra", "share", "https://example.com"]).command
        else {
            panic!("share is a command");
        };
        assert_eq!(args.text, "https://example.com");
        // The default is `text/plain`, which is what a bare argument is. A link is `text/uri-list`, and the caller says
        // so rather than the kernel guessing from the contents.
        assert_eq!(args.mime, "text/plain");

        let Command::Share(args) = parsed(&[
            "synra",
            "share",
            "--mime",
            "text/uri-list",
            "https://example.com",
        ])
        .command
        else {
            panic!("share is a command");
        };
        assert_eq!(args.mime, "text/uri-list");
    }

    #[test]
    fn the_three_answers_to_a_prompt_each_parse() {
        // ★ `share` prints an identifier and these are the commands that spend it. Before them, routing could be
        // started from the command line and never finished there — the identifier was a value with no second command.
        let Command::Intent(args) = parsed(&[
            "synra",
            "intent",
            "show",
            "01a140ce-0000-7000-8000-000000000000",
        ])
        .command
        else {
            panic!("intent is a command");
        };
        assert!(matches!(args.action, IntentAction::Show { .. }));

        let Command::Intent(args) = parsed(&["synra", "intent", "decide", "abc"]).command else {
            panic!("intent is a command");
        };
        // Both optional: omitting them is the ordinary case — one plugin claimed the share and named where to run it.
        assert!(matches!(
            args.action,
            IntentAction::Decide {
                plugin: None,
                target: None,
                ..
            }
        ));

        // And naming them is how a user answers a share that left either open.
        let Command::Intent(args) = parsed(&[
            "synra",
            "intent",
            "decide",
            "abc",
            "--plugin",
            "@acme/opener",
            "--target",
            "0e5a1c34-0000-4000-8000-000000000001",
        ])
        .command
        else {
            panic!("intent is a command");
        };
        match args.action {
            IntentAction::Decide { plugin, target, .. } => {
                assert_eq!(plugin.as_deref(), Some("@acme/opener"));
                assert_eq!(
                    target.as_deref(),
                    Some("0e5a1c34-0000-4000-8000-000000000001")
                );
            }
            other => panic!("expected decide, got {other:?}"),
        }

        let Command::Intent(args) = parsed(&["synra", "intent", "cancel", "abc"]).command else {
            panic!("intent is a command");
        };
        assert!(matches!(args.action, IntentAction::Cancel { .. }));
    }

    // ── The main.rs bound ─────────────────────────────────────────────────────────────────────────

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
}

