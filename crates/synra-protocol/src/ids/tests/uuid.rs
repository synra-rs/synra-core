use super::super::{DeviceId, IdError, RequestId, TraceId, TransferId};

#[test]
fn device_ids_are_time_ordered() {
    let first = DeviceId::new();
    // UUIDv7 puts a millisecond timestamp in the high bits, so successive ids ascend. This is
    // the property the module docs rely on for log ordering.
    let second = DeviceId::new();
    assert!(first <= second, "{first} should not exceed {second}");
}

#[test]
fn ids_round_trip_through_text() {
    let id = RequestId::new();
    let parsed: RequestId = id.to_string().parse().expect("round trips");
    assert_eq!(parsed, id);
}

#[test]
fn ids_round_trip_through_json_as_bare_strings() {
    // `serde(transparent)` matters: a peer expects `"0193…"`, not `{"0": …}`.
    let id = DeviceId::new();
    let json = serde_json::to_string(&id).expect("serialises");
    assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
    let back: DeviceId = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, id);
}

#[test]
fn parsing_rejects_non_uuids() {
    assert_eq!("not-a-uuid".parse::<DeviceId>(), Err(IdError::NotUuid));
    assert_eq!("".parse::<DeviceId>(), Err(IdError::NotUuid));
    // A valid-looking but truncated uuid.
    assert_eq!("0193abcd-0000-7000".parse::<DeviceId>(), Err(IdError::NotUuid));
}

#[test]
fn parsing_rejects_the_nil_uuid() {
    let nil = "00000000-0000-0000-0000-000000000000";
    assert_eq!(nil.parse::<DeviceId>(), Err(IdError::Nil));
    assert_eq!(nil.parse::<TraceId>(), Err(IdError::NotUuid));
}

#[test]
fn different_id_types_are_not_interchangeable() {
    // Compile-time in practice; this test documents the intent. If `RequestId` and `TransferId`
    // were both plain `Uuid`, the two locals below would be assignable to each other.
    let request = RequestId::new();
    let transfer = TransferId::new();
    assert_ne!(request.as_uuid(), transfer.as_uuid());
}
