use synra_capability::CapabilitySet;
use synra_observe::audit::AuditOutcome;
use super::super::{CallError, HostCalls};
use crate::quota::RateKind;
use crate::test_host::Stub;
use super::{budget, granted, session};

#[test]
fn calling_faster_than_the_limit_allows_is_refused_and_counted() {
    // The limit is per kind rather than per function, and this drives it until it refuses: the refusal is a value a
    // plugin handles, not a trap.
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();

    // ★ The property, and it is about a *refused* call rather than about the next one: the count of calls that reached
    // the host must equal the count that were admitted. A refusal that still performed the call is the bug this rules
    // out, and it is checkable without knowing when the bucket will refuse next — which the second version of this test
    // tried to assume, and which is not knowable: a refilled token makes the call after a refusal succeed, and that is
    // the rate limiter working rather than failing.
    let mut admitted = 0u64;
    let mut refusals = 0u64;
    let mut refused_after_a_refusal = false;
    let mut last_was_refused = false;
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for _ in 0..10_000 {
            match calls.call("synra:plugin/host#log", r#"{"level":"info","message":"x"}"#) {
                Ok(_) => {
                    admitted += 1;
                    last_was_refused = false;
                }
                Err(error) => {
                    assert_eq!(error.code, CallError::RATE_LIMITED);
                    refusals += 1;
                    refused_after_a_refusal |= last_was_refused;
                    last_was_refused = true;
                    // ★ The count of calls that reached the host is the count that were admitted, at every refusal —
                    // which is the assertion that a refusal does not perform the call.
                    assert_eq!(
                        host.called().len() as u64,
                        admitted,
                        "a refused call reached the host"
                    );
                }
            }
        }
    }
    assert!(refusals > 0, "the budget never refused");
    assert!(refused_after_a_refusal, "the limit refused once and then stopped");
    assert!(audit.iter().any(|entry| entry.outcome == AuditOutcome::RateLimited));
}

#[test]
fn the_ungated_calls_are_not_rate_limited() {
    // A plugin that needs an environment fact to decide what to ask for must be able to ask, however often.
    let host = Stub::default();
    let grants = CapabilitySet::new();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    for _ in 0..5_000 {
        assert_eq!(calls.call("synra:plugin/host#plugin-id", ""), Ok("@acme/chat".to_owned()));
    }
}

#[test]
fn the_rate_kind_is_chosen_by_what_the_call_costs() {
    // A storage write and a storage read are the same kind of thing to the host, and a network call is not.
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#storage-set"), RateKind::HostCalls);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#storage-get"), RateKind::HostCalls);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#network-fetch"), RateKind::NetworkRequests);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#device-send"), RateKind::DeviceSends);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#event-emit"), RateKind::Events);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#transfer-send"), RateKind::FsOps);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#platform-notify"), RateKind::HostCalls);
}
