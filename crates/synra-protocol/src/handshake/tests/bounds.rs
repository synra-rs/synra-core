use core::time::Duration;

use crate::limits;

use super::super::{HandshakeBudget, SequenceGuard, SessionNonce};

#[test]
fn a_sequence_guard_accepts_only_newer_values() {
    let mut guard = SequenceGuard::new();
    assert_eq!(guard.accept(1), Ok(()));
    assert_eq!(guard.highest(), 1);

    assert_eq!(guard.accept(2), Ok(()));
    assert!(guard.accept(2).is_err(), "the same value again is a replay");
    assert!(guard.accept(1).is_err(), "an older value is a replay");

    assert_eq!(guard.accept(100), Ok(()));
    assert_eq!(guard.highest(), 100);
}

#[test]
fn a_sequence_guard_resumes_from_a_persisted_value() {
    // After a restart the guard must not accept what it accepted before, or every attempt
    // recorded during the previous run becomes replayable.
    let mut guard = SequenceGuard::resume(500);
    assert!(guard.accept(500).is_err());
    assert!(guard.accept(499).is_err());
    assert_eq!(guard.accept(501), Ok(()));
}

#[test]
fn replay_errors_name_both_values() {
    let mut guard = SequenceGuard::resume(10);
    let error = guard.accept(3).expect_err("a replay");
    assert_eq!(error.sequence, 3);
    assert_eq!(error.seen, 10);
    assert!(error.to_string().contains("replay"));
}

#[test]
fn handshake_budgets_must_bound_every_phase() {
    assert_eq!(HandshakeBudget::default().validate(), Ok(()));

    for budget in [
        HandshakeBudget { await_hello: Duration::ZERO, ..HandshakeBudget::default() },
        HandshakeBudget { await_ack: Duration::ZERO, ..HandshakeBudget::default() },
        HandshakeBudget { await_pairing: Duration::ZERO, ..HandshakeBudget::default() },
    ] {
        assert!(budget.validate().is_err());
    }
}

#[test]
fn the_default_hello_timeout_matches_the_protocol_limit() {
    // Two sources for the same number is how they drift apart.
    assert_eq!(HandshakeBudget::default().await_hello, limits::HELLO_TIMEOUT);
    assert_eq!(HandshakeBudget::default().await_ack, limits::HELLO_TIMEOUT);
}

#[test]
fn session_nonces_are_never_zero() {
    for _ in 0..64 {
        assert!(!SessionNonce::random().is_zero());
    }
    assert!(SessionNonce(0).is_zero());
    assert_eq!(SessionNonce(0xFF).to_hex().len(), 32);
}
