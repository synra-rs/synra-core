use crate::ids::RequestId;
use super::super::{OutstandingRequests, SessionState};

#[test]
fn session_states_know_which_are_terminal() {
    assert!(!SessionState::Open.is_terminal());
    for state in [
        SessionState::Succeeded,
        SessionState::Failed,
        SessionState::Expired,
        SessionState::Cancelled,
    ] {
        assert!(state.is_terminal(), "{state:?}");
    }
}

#[test]
fn outstanding_requests_forget_what_has_expired() {
    let mut outstanding = OutstandingRequests::new(4, 1_000);
    let first = RequestId::new();
    outstanding.insert(first, 0);
    assert!(outstanding.contains(&first));

    outstanding.expire(999);
    assert!(outstanding.contains(&first));

    outstanding.expire(1_001);
    assert!(!outstanding.contains(&first));
    assert!(outstanding.is_empty());
}

#[test]
fn outstanding_requests_stay_bounded() {
    // A record that grows without limit is a memory leak with a slow fuse.
    let mut outstanding = OutstandingRequests::new(2, 1_000_000);
    let ids: Vec<_> = (0..5).map(|_| RequestId::new()).collect();
    for (at, id) in ids.iter().enumerate() {
        outstanding.insert(*id, at as i64);
    }
    assert_eq!(outstanding.len(), 2);
    // The oldest are dropped: the newest requests are the ones whose replies have not yet had
    // time to arrive.
    assert!(!outstanding.contains(&ids[0]));
    assert!(outstanding.contains(&ids[4]));
}

#[test]
fn a_answered_request_stops_being_outstanding() {
    let mut outstanding = OutstandingRequests::new(4, 1_000_000);
    let id = RequestId::new();
    outstanding.insert(id, 0);
    assert!(outstanding.contains(&id));

    outstanding.remove(&id);
    assert!(!outstanding.contains(&id));
    assert!(outstanding.is_empty());
}
