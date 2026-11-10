use super::super::{StopRecord, UNSTABLE_THRESHOLD};

#[test]
fn a_version_that_has_not_stopped_is_stable() {
    let record = StopRecord::new("1.0.0");
    assert!(!record.is_unstable());
    assert_eq!(record.unexpected_stops, 0);
    assert_eq!(record.last_reason, None);
}

#[test]
fn three_unexpected_stops_make_a_version_unstable() {
    // A plugin that has crashed three times in a row is not going to work on the fourth.
    let mut record = StopRecord::new("1.0.0");
    for _ in 0..UNSTABLE_THRESHOLD - 1 {
        record.record_unexpected_stop("trapped");
        assert!(!record.is_unstable());
    }
    record.record_unexpected_stop("trapped");
    assert!(record.is_unstable());
    assert_eq!(record.last_reason.as_deref(), Some("trapped"));
}

#[test]
fn the_stop_count_saturates_rather_than_wrapping() {
    // A wrapping count would make a plugin that crashed four billion times look like one that never crashed.
    let mut record = StopRecord::new("1.0.0");
    record.unexpected_stops = u32::MAX;
    record.record_unexpected_stop("again");
    assert_eq!(record.unexpected_stops, u32::MAX);
    assert!(record.is_unstable());
}

#[test]
fn a_stop_record_survives_a_round_trip() {
    let mut record = StopRecord::new("1.0.0");
    record.record_unexpected_stop("trapped");
    let json = serde_json::to_string(&record).expect("serialises");
    assert!(json.contains("unexpectedStops"), "{json}");
    let back: StopRecord = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, record);
}
