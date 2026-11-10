use super::super::{Quota, StaticRefusal};
use super::budget;

#[test]
fn static_limits_are_checked_against_the_defaults() {
    let budget = budget();
    assert_eq!(budget.check_memory(32 * 1024 * 1024), Ok(()));
    assert_eq!(budget.check_instances(4), Ok(()));
    assert_eq!(budget.check_storage(1024), Ok(()));
    assert_eq!(budget.check_transfers(4), Ok(()));
}

#[test]
fn exceeding_a_static_limit_names_it_and_the_amount() {
    let budget = budget();
    match budget.check_memory(u64::MAX) {
        Err(StaticRefusal::Memory { limit, .. }) => assert_eq!(limit, Quota::default().max_memory_bytes),
        other => panic!("expected a memory refusal, got {other:?}"),
    }
    match budget.check_instances(100) {
        Err(StaticRefusal::Instances { wanted, limit }) => {
            assert_eq!(wanted, 100);
            assert_eq!(limit, 4);
        }
        other => panic!("expected an instance refusal, got {other:?}"),
    }
    assert!(matches!(budget.check_storage(u64::MAX), Err(StaticRefusal::Storage { .. })));
    assert!(matches!(budget.check_transfers(99), Err(StaticRefusal::Transfers { .. })));
}

#[test]
fn a_static_refusal_is_never_retryable() {
    // A static limit is a decision about how much a plugin may hold, so retrying against it is retrying against
    // the host's own configuration.
    let refusals = [
        StaticRefusal::Memory { wanted: 2, limit: 1 },
        StaticRefusal::Instances { wanted: 2, limit: 1 },
        StaticRefusal::Storage { wanted: 2, limit: 1 },
        StaticRefusal::Transfers { wanted: 2, limit: 1 },
    ];
    for refusal in refusals {
        assert!(!refusal.is_retryable(), "{refusal:?}");
        assert!(!refusal.to_string().is_empty(), "{refusal:?}");
    }
}
