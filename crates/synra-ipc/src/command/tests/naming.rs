use super::super::registry::is_snake_case_with_one_separator;

use super::*;

// ── Naming ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_command_starts_with_its_domains_prefix() {
    // The prefixes are what the front end organises its modules by, and a command whose prefix disagrees with
    // its group ends up in the wrong file.
    for command in COMMANDS {
        assert!(
            command.prefix_matches(),
            "{} vs {:?}",
            command.name,
            command.domain
        );
    }
}

#[test]
fn every_command_name_is_snake_case() {
    for command in COMMANDS {
        assert!(
            is_snake_case_with_one_separator(command.name),
            "{} is not domain_verb in snake_case",
            command.name
        );
    }
}

#[test]
fn a_name_that_is_not_the_convention_is_refused() {
    // The check has to actually reject the shapes that would break the front end's grouping.
    for bad in [
        "",
        "get",
        "Get_thing",
        "get__thing",
        "get-Thing",
        "get thing",
        "_x",
        "x_",
    ] {
        assert!(
            !is_snake_case_with_one_separator(bad),
            "{bad:?} was accepted"
        );
    }
    for good in ["devices_snapshot", "plugin_ui_rpc", "diag_logs_tail", "a_b"] {
        assert!(
            is_snake_case_with_one_separator(good),
            "{good:?} was refused"
        );
    }
}

#[test]
fn the_domain_prefixes_are_distinct() {
    // `plugin_ui_` and `plugins_` are close, and a front end matching on a prefix would group wrongly if one
    // were a prefix of the other. `plugin_ui_` is not: `plugins_` starts with `plugin` and then `s`, so
    // neither is a prefix of the other.
    for (index, first) in Domain::ALL.iter().enumerate() {
        for second in &Domain::ALL[index + 1..] {
            assert_ne!(first.prefix(), second.prefix(), "{first:?} and {second:?}");
            assert!(
                !first.prefix().starts_with(second.prefix())
                    && !second.prefix().starts_with(first.prefix()),
                "{first:?} and {second:?} are prefixes of each other"
            );
        }
    }
}
