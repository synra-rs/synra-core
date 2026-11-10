use core::time::Duration;
use crate::limits;
use super::super::ScanBudget;

#[test]
fn the_default_scan_budget_is_self_consistent() {
    assert_eq!(ScanBudget::default().validate(), Ok(()));
}

#[test]
fn the_default_scan_budget_reads_its_numbers_from_the_limits() {
    // One source per number. A per-platform timeout is how "the same code behaves differently on
    // each device" starts.
    let budget = ScanBudget::default();
    assert_eq!(budget.total, limits::SCAN_TOTAL);
    assert_eq!(budget.passive, limits::SCAN_PASSIVE);
    assert_eq!(budget.probe_timeout, limits::SCAN_PROBE_TIMEOUT);
    assert_eq!(budget.probe_concurrency, limits::SCAN_PROBE_CONCURRENCY);
    assert_eq!(budget.query_interval(), limits::DISCOVERY_QUERY_INTERVAL);
    assert_eq!(budget.query_repeats(), limits::DISCOVERY_QUERY_REPEATS);
}

#[test]
fn a_degenerate_scan_budget_is_refused() {
    for budget in [
        ScanBudget {
            total: Duration::ZERO,
            ..ScanBudget::default()
        },
        ScanBudget {
            passive: Duration::ZERO,
            ..ScanBudget::default()
        },
        ScanBudget {
            probe_timeout: Duration::ZERO,
            ..ScanBudget::default()
        },
        ScanBudget {
            probe_concurrency: 0,
            ..ScanBudget::default()
        },
    ] {
        assert!(budget.validate().is_err());
    }

    // A passive window longer than the whole budget means the probe phase never runs, so
    // candidates are found and never checked.
    let passive_too_long = ScanBudget {
        passive: Duration::from_secs(60),
        total: Duration::from_secs(10),
        ..ScanBudget::default()
    };
    assert!(passive_too_long.validate().is_err());
}

#[test]
fn repeated_queries_must_fit_inside_the_passive_window() {
    // Otherwise a query is still going out after replies stopped being collected, and its answer
    // arrives with nobody listening.
    let too_short = ScanBudget {
        passive: Duration::from_millis(10),
        total: Duration::from_secs(10),
        ..ScanBudget::default()
    };
    assert!(too_short.validate().is_err());

    let default = ScanBudget::default();
    assert!(
        default.query_window() <= default.passive,
        "the default must satisfy its own rule"
    );
}

#[test]
fn the_probe_window_is_what_is_left_after_listening() {
    let budget = ScanBudget::default();
    assert_eq!(budget.probe_window(), budget.total - budget.passive);
}

#[test]
fn a_budget_can_say_whether_it_can_finish_a_probe_set() {
    let budget = ScanBudget {
        total: Duration::from_secs(2),
        passive: Duration::from_millis(500),
        probe_timeout: Duration::from_millis(200),
        probe_concurrency: 10,
    };
    // 1500ms of probe window, 200ms per batch of 10.
    assert!(budget.can_probe(0));
    assert!(budget.can_probe(10));
    assert!(budget.can_probe(70), "7 batches is 1400ms");
    assert!(
        !budget.can_probe(80),
        "8 batches is 1600ms, past the window"
    );
}
