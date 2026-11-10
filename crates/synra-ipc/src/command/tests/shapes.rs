use super::*;

// ── Return shapes ─────────────────────────────────────────────────────────────────────────────

#[test]
fn absent_tasks_and_updates_return_optional_values() {
    // `plugins_check_update`: "no update" is not an error, and a command that returned one would make the
    // interface handle a failure on the common path.
    let optional: Vec<&str> = COMMANDS
        .iter()
        .filter(|command| command.returns == ReturnShape::Maybe)
        .map(|command| command.name)
        .collect();
    assert_eq!(optional, vec!["plugins_check_update"]);
}

#[test]
fn a_list_returning_command_is_marked_as_such() {
    // The front end types a list differently from a single value, so the distinction has to be in the
    // descriptor rather than inferred.
    for name in [
        "transfer_list",
        "plugins_list",
        "plugins_audit",
        "diag_logs_tail",
    ] {
        assert_eq!(
            CommandRegistry::find(name).expect("exists").returns,
            ReturnShape::Many,
            "{name}"
        );
    }
}

#[test]
fn a_command_that_changes_nothing_is_marked_as_such() {
    // The interface uses this to decide whether to refresh a snapshot afterwards, and refreshing after a read
    // is a round trip that shows nothing new.
    for name in [
        "identity_get",
        "devices_snapshot",
        "intent_snapshot",
        "transfer_list",
        "plugins_list",
        "config_get",
        "diag_metrics",
    ] {
        assert!(
            !CommandRegistry::find(name).expect("exists").mutates,
            "{name}"
        );
    }
}

#[test]
fn a_scan_is_marked_as_mutating() {
    // It changes kernel state even though it returns a value, and the interface has to know that so it does
    // not treat the answer as a pure read.
    let start = CommandRegistry::find("devices_scan_start").expect("exists");
    assert!(start.mutates);
    assert_eq!(start.returns, ReturnShape::One);
}
