use super::super::{Budget, Quota, RateKind};
use super::budget;

#[test]
fn a_burst_within_the_allowance_is_admitted() {
    let budget = budget();
    // The host-call burst is a thousand, so a hundred calls at the same instant are fine.
    for _ in 0..100 {
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    }
    assert_eq!(budget.admitted(), 100);
    assert_eq!(budget.refused(), 0);
}

#[test]
fn exceeding_the_burst_is_refused_and_recorded() {
    let budget = Budget::new(Quota { host_calls_burst: 2, host_calls_per_sec: 1, ..Quota::default() });
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));

    match budget.consume(RateKind::HostCalls, 1, 0) {
        Err(refusal) => assert_eq!(refusal.kind, Some(RateKind::HostCalls)),
        Ok(()) => panic!("the bucket should be empty"),
    }
    assert_eq!(budget.refused(), 1);
}

#[test]
fn each_kind_has_its_own_bucket() {
    // A plugin that emits a thousand events should not thereby be unable to read a file.
    let budget = Budget::new(Quota { events_per_sec: 1, fs_ops_per_sec: 100, ..Quota::default() });
    assert_eq!(budget.consume(RateKind::Events, 1, 0), Ok(()));
    assert!(budget.consume(RateKind::Events, 1, 0).is_err());
    // The filesystem bucket is untouched.
    assert_eq!(budget.consume(RateKind::FsOps, 1, 0), Ok(()));
}

#[test]
fn every_rate_kind_has_a_quota_field() {
    // A kind with no field would have a zero rate and refuse everything, which reads as a broken plugin rather
    // than a missing limit.
    let quota = Quota::default();
    for kind in RateKind::ALL {
        let (rate, burst) = quota.rate_for(*kind);
        assert!(rate > 0, "{kind:?} has no rate");
        assert!(burst > 0, "{kind:?} has no burst");
        assert!(!kind.as_str().is_empty(), "{kind:?}");
    }
    // And the list covers every kind, so a new variant cannot be forgotten here.
    assert_eq!(RateKind::ALL.len(), 5);

    // The index is the position in `ALL`, which is what the refusal counts are keyed by. A mismatch would file one
    // kind's refusals under another.
    for (position, kind) in RateKind::ALL.iter().enumerate() {
        assert_eq!(kind.index(), position, "{kind:?}");
    }
}
