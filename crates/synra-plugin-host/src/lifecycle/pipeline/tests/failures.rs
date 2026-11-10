use super::super::{FailStage, WEAR_OUT_AFTER, PluginSlot, Move, MoveError};
use super::{NOW, registry_source};

#[test]
fn a_failure_records_its_stage_and_whether_a_retry_could_work() {
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot
        .apply(
            Move::Fail {
                stage: FailStage::Download,
                detail: "the connection dropped".to_owned(),
                retryable: None,
            },
            1_500,
        )
        .expect("failed");

    let PluginSlot::Failed(failed) = &slot else {
        panic!("expected a failure");
    };
    assert_eq!(failed.stage, FailStage::Download);
    assert!(failed.retryable, "a download can be tried again");
    assert_eq!(failed.attempts, 1);
    assert_eq!(failed.failed_at_ms, 1_500);
    assert!(slot.can_retry());
}

#[test]
fn a_verification_failure_is_not_offered_as_a_retry() {
    // ★ The same bytes hash the same way. A retry button here is a button that cannot work.
    assert!(!FailStage::Verify.is_retryable(), "the stage's own answer");
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot
        .apply(
            Move::Fail {
                stage: FailStage::Verify,
                detail: "the digest does not match".to_owned(),
                retryable: None,
            },
            NOW,
        )
        .expect("failed");

    assert!(!slot.can_retry());
    assert!(matches!(slot.apply(Move::Retry, NOW), Err(MoveError::WrongState { .. })));
}

#[test]
fn a_caller_that_knows_better_can_mark_a_retryable_stage_as_hopeless() {
    // A registry that answered 404 failed at `Resolve`, and no amount of trying will make the package exist.
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot
        .apply(
            Move::Fail {
                stage: FailStage::Resolve,
                detail: "no such package".to_owned(),
                retryable: Some(false),
            },
            NOW,
        )
        .expect("failed");

    assert!(!slot.can_retry(), "the caller's answer wins over the stage's");
}

#[test]
fn retrying_counts_the_attempts_and_starts_over_from_resolving() {
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot
        .apply(Move::Fail { stage: FailStage::Download, detail: "dropped".to_owned(), retryable: None }, NOW)
        .expect("failed");
    let _ = slot.apply(Move::Fail { stage: FailStage::Download, detail: "dropped again".to_owned(), retryable: None }, NOW);

    let PluginSlot::Failed(failed) = &slot else {
        panic!("expected a failure");
    };
    assert_eq!(failed.attempts, 2, "a second failure increments rather than replaces");

    let _ = slot.apply(Move::Retry, NOW + 10).expect("retry");
    assert_eq!(slot.as_str(), "resolving", "a retry starts where the source is known again");
}

#[test]
fn a_failure_that_keeps_happening_stops_offering_a_button() {
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    for attempt in 0..WEAR_OUT_AFTER {
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Install,
                    detail: format!("attempt {attempt}"),
                    retryable: None,
                },
                NOW,
            )
            .expect("failed");
    }

    let PluginSlot::Failed(failed) = &slot else {
        panic!("expected a failure");
    };
    assert_eq!(failed.attempts, WEAR_OUT_AFTER);
    assert!(failed.is_worn_out());
    assert!(!slot.can_retry(), "the fourth offer of the same button is not useful");
    assert!(slot.describe().contains("attempts"), "{}", slot.describe());
}

#[test]
fn abandoning_a_failure_returns_the_slot_to_available() {
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot
        .apply(Move::Fail { stage: FailStage::Download, detail: "dropped".to_owned(), retryable: None }, NOW)
        .expect("failed");
    let _ = slot.apply(Move::Abandon, NOW).expect("abandon");

    assert_eq!(slot, PluginSlot::Available);
    assert!(slot.source().is_none());
}
