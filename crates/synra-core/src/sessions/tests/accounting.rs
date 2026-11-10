use super::super::registry::SessionRegistry;
use super::opened;

#[test]
fn frames_are_counted_in_both_directions() {
    // The numbers a diagnostic report wants, and the only evidence of a link that is up but not carrying anything —
    // frames out and none in is a peer that is not listening.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 0);
    for _ in 0..3 {
        registry.record_frame_out(key).expect("out");
    }
    registry.record_frame_in(key, 100).expect("in");

    let session = registry.get(key).expect("key");
    assert_eq!(session.frames_out(), 3);
    assert_eq!(session.frames_in(), 1);
}

#[test]
fn the_age_and_the_silence_are_measured_from_different_moments() {
    // ★ Two different questions. A session that has been open for an hour and heard from its peer a second ago is
    // healthy; one open for an hour and silent for an hour is not. Deriving one from the other would report the
    // wrong one for exactly the long-lived sessions that matter.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.record_frame_in(key, 3_600_000).expect("frame");

    let session = registry.get(key).expect("key");
    assert_eq!(session.age_ms(3_600_000), 3_599_000);
    assert_eq!(session.silent_for_ms(3_600_000), 0);
    assert!(!session.is_overdue(3_600_000));
}

#[test]
fn a_clock_that_went_backwards_does_not_report_a_negative_silence() {
    // A caller with a clock that moved backwards is a caller with a problem, and a negative duration is not one this
    // module can represent. Saturating is the answer that keeps the arithmetic total.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 5_000);
    let session = registry.get(key).expect("key");
    assert_eq!(session.silent_for_ms(1_000), 0);
    assert_eq!(session.age_ms(1_000), 0);
}
