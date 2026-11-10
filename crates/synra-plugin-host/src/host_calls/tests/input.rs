use synra_capability::CapabilitySet;
use crate::test_host::Stub;
use super::{budget, granted, session};

#[test]
fn input_frames_keep_gates_and_metrics_without_a_persistent_row_per_sample() {
    let host = Stub::default();
    let grants = granted(&["device:input"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        calls.call("synra:plugin/host#input-session", r#"{"op":"open"}"#).unwrap();
        calls.call("synra:plugin/host#input-session", r#"{"op":"frame"}"#).unwrap();
        calls.call("synra:plugin/host#input-session", r#"{"op":"status"}"#).unwrap();
        calls.call("synra:plugin/host#input-session", r#"{"op":"close"}"#).unwrap();
    }
    assert_eq!(host.called().len(), 4);
    assert_eq!(audit.len(), 2, "open and close remain audited");
    let denied = CapabilitySet::new();
    let mut calls = session(&host, &denied, &budget, &mut audit);
    assert!(calls.call("synra:plugin/host#input-session", r#"{"op":"frame"}"#).is_err());
    drop(calls);
    assert_eq!(audit.len(), 3, "a denied frame is still audited");
    assert_eq!(host.called().len(), 4, "denial never reaches the host");
}
