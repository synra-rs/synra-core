use super::*;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

proptest! {
    // Keep using the regression seeds saved before this suite moved into a directory.
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/command.txt"
        )))),
        ..ProptestConfig::default()
    })]

    /// Whatever interface a command belongs to, only that interface may call it. The property is the
    /// separation the design document requires, stated over the whole table rather than over the names a
    /// reader happens to check.
    #[test]
    fn only_a_commands_own_interface_may_call_it(index in 0usize..COMMANDS.len()) {
        let command = COMMANDS[index];
        for caller in [Interface::Host, Interface::Plugin] {
            prop_assert_eq!(command.callable_by(caller), command.interface == caller);
        }
    }

    /// The plugin allow-list never contains a command filed under the host interface, whatever the table
    /// holds. A leak here is a plugin reaching the host's screens' commands with a stolen token.
    #[test]
    fn the_allow_list_never_leaks_a_host_command(index in 0usize..COMMANDS.len()) {
        let allowed = CommandRegistry::plugin_allow_list();
        let command = COMMANDS[index];
        if allowed.contains(&command.name) {
            prop_assert_eq!(command.interface, Interface::Plugin, "{} leaked", command.name);
        }
    }

    /// Lookup is exact. A suffix may form another registered command, but must never loosely match its prefix.
    #[test]
    fn lookup_agrees_with_the_table(index in 0usize..COMMANDS.len(), suffix in "[a-zA-Z_]{1,4}") {
        let command = COMMANDS[index];
        prop_assert_eq!(CommandRegistry::find(command.name).map(|found| found.name), Some(command.name));

        let altered = format!("{}{}", command.name, suffix);
        if let Some(found) = CommandRegistry::find(&altered) {
            prop_assert_eq!(found.name, altered.as_str(), "lookup must not match a prefix");
        }
    }

    /// Any command the registry lists is one an interface may call, so the table has no entry that is
    /// unreachable. An unreachable command is dead code the front end may still try to call.
    #[test]
    fn every_command_is_reachable_from_some_interface(index in 0usize..COMMANDS.len()) {
        let command = COMMANDS[index];
        prop_assert!(command.callable_by(command.interface));
        prop_assert!(Domain::ALL.contains(&command.domain));
        prop_assert!(command.prefix_matches());
    }
}
