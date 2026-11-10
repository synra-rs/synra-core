use super::super::TraceId;

#[test]
fn trace_id_hex_is_32_digits() {
    let trace = TraceId::new();
    let hex = trace.to_hex();
    assert_eq!(hex.len(), 32);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(trace.to_string(), hex);
}

#[test]
fn trace_id_never_zero() {
    for _ in 0..64 {
        assert!(!TraceId::new().is_zero());
    }
}

#[test]
fn trace_id_round_trips_through_hex() {
    let trace = TraceId::new();
    let parsed: TraceId = trace.to_hex().parse().expect("round trips");
    assert_eq!(parsed, trace);
}

#[test]
fn trace_id_rejects_wrong_length_and_zero() {
    assert!("abc".parse::<TraceId>().is_err());
    assert!("0".repeat(32).parse::<TraceId>().is_err());
    assert!("z".repeat(32).parse::<TraceId>().is_err());
}
