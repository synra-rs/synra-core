use super::super::{Health, PERSISTENT_REFUSALS, in_window};
use super::budget;

#[test]
fn a_plugin_that_keeps_trapping_is_degraded() {
    // """ + S + """ The path that was missing: the ladder listened only to rate-limit refusals.
    //
    // A trap is not a rate, so a plugin that trapped on every call produced no refusals, nothing counted, `bad_windows` never
    // moved, and a plugin that could not run kept being asked. The same fixture as the refusal ladder, with misbehaviour
    // instead of refusal, so the two are visibly one mechanism.
    let budget = budget();
    assert_eq!(budget.health(), Health::Good);

    for window in 0..12u64 {
        for _ in 0..PERSISTENT_REFUSALS {
            budget.record_misbehaviour(in_window(window));
        }
        if budget.health() != Health::Good {
            break;
        }
    }

    assert_ne!(budget.health(), Health::Good, "twelve bad windows should have moved the ladder");
}

#[test]
fn one_misbehaviour_does_not_change_health() {
    // And the control, so the test above cannot pass by degrading on anything: the ladder moves on **persistently** bad
    // windows, and a single trap is an ordinary failure a plugin is allowed to have.
    let budget = budget();

    budget.record_misbehaviour(in_window(0));

    assert_eq!(budget.health(), Health::Good);
}
