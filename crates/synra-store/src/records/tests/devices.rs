use super::super::{DeviceNumbers, DeviceRow, DeviceText, RowError, SeenDeviceRow};

/// Builds a device row from the seven columns, with the address left out.
///
/// A helper rather than a literal at each call site: the address is not what most of these tests are about, and a
/// signature that grows should not turn every assertion about a name into a second edit.
fn device_row(
    device_id: Option<&str>,
    display_name: Option<&str>,
    platform: Option<&str>,
    features: Option<&str>,
    paired_at_ms: Option<i64>,
    last_seen_ms: Option<i64>,
    blocked: Option<i64>,
) -> Result<DeviceRow, RowError> {
    DeviceRow::from_columns(
        DeviceText { device_id, display_name, platform, features, address: None },
        DeviceNumbers { paired_at_ms, last_seen_ms, blocked },
    )
}

#[test]
fn a_device_row_is_built_from_the_columns_in_order() {
    let row = DeviceRow::from_columns(
        DeviceText {
            device_id: Some("dev_a"),
            display_name: Some("Laptop"),
            platform: Some("windows"),
            features: Some(r#"["eventStream"]"#),
            address: Some("10.0.0.4:51000"),
        },
        DeviceNumbers { paired_at_ms: Some(1_000), last_seen_ms: Some(2_000), blocked: Some(0) },
    )
    .expect("a row");
    assert_eq!(row.device_id, "dev_a");
    assert_eq!(row.display_name, "Laptop");
    assert_eq!(row.platform, "windows");
    assert_eq!(row.features, vec!["eventStream"]);
    assert_eq!(row.paired_at_ms, 1_000);
    assert_eq!(row.last_seen_ms, 2_000);
    assert_eq!(row.address.as_deref(), Some("10.0.0.4:51000"));
    assert!(!row.blocked);
    assert!(row.is_usable());
}

#[test]
fn an_address_of_nothing_is_absent_rather_than_empty() {
    // A device paired over something other than a socket, or a row written before the column existed. The distinction
    // is what keeps a blank line out of a device list.
    for value in [None, Some("")] {
        let row = DeviceRow::from_columns(
            DeviceText {
                device_id: Some("dev_a"),
                display_name: Some("Laptop"),
                platform: Some("windows"),
                features: Some("[]"),
                address: value,
            },
            DeviceNumbers { paired_at_ms: Some(1_000), last_seen_ms: Some(2_000), blocked: Some(0) },
        )
        .expect("a row");
        assert_eq!(row.address, None, "{value:?}");
    }
}

#[test]
fn a_blocked_device_is_not_usable() {
    // ★ The question the kernel actually asks. Written as a method rather than as a condition at each call site,
    // because the call sites are where it gets left out.
    let row = device_row(Some("d"), Some("n"), Some("p"), Some("[]"), Some(0), Some(0), Some(1))
        .expect("a row");
    assert!(row.blocked);
    assert!(!row.is_usable());
}

#[test]
fn a_missing_not_null_column_is_refused_and_named() {
    // ★ The failure a positional read produces when a `SELECT` omits a column: without the name, the message is
    // "index out of range" and the user has no idea which query is wrong.
    for (index, column) in [
        (0, "device_id"),
        (1, "display_name"),
        (2, "platform"),
        (3, "features"),
        (4, "paired_at_ms"),
        (5, "last_seen_ms"),
        (6, "blocked"),
    ] {
        let mut args: Vec<Option<&str>> = vec![Some("x"), Some("x"), Some("x"), Some("[]")];
        let mut numbers: Vec<Option<i64>> = vec![Some(0), Some(0), Some(0)];
        if index < 4 {
            args[index] = None;
        }
        else {
            // The address is the eighth column and is allowed to be absent — that is what `None` means for it — so
            // the loop only walks the three integers the row requires.
            numbers[index - 4] = None;
        }
        match device_row(args[0], args[1], args[2], args[3], numbers[0], numbers[1], numbers[2]) {
            Err(RowError::Missing { column: reported }) => {
                assert_eq!(reported, column, "index {index}");
            }
            other => panic!("expected a missing column at index {index}, got {other:?}"),
        }
    }
}

#[test]
fn a_features_column_that_is_not_a_list_of_strings_is_refused_rather_than_emptied() {
    // ★ A fallback to "no features" would produce a device that pairs and then fails every transfer with a message
    // about a missing feature — pointing at the peer rather than at the row that is wrong.
    for text in ["[1, 2]", "{}", "not json", r#""a string""#] {
        match device_row(Some("d"), Some("n"), Some("p"), Some(text), Some(0), Some(0), Some(0)) {
            Err(RowError::WrongType { column, .. }) => assert_eq!(column, "features", "{text}"),
            other => panic!("`{text}` was accepted: {other:?}"),
        }
    }
}

#[test]
fn an_empty_features_list_is_the_ordinary_case() {
    // The schema's own default is `'[]'`, so it is the value most rows have.
    let row = device_row(Some("d"), Some("n"), Some("p"), Some("[]"), Some(0), Some(0), Some(0))
        .expect("a row");
    assert!(row.features.is_empty());
}

#[test]
fn a_boolean_column_holding_something_else_is_refused() {
    // ★ The schema's `CHECK (x IN (0, 1))` makes this two-valued, and a reader that accepted any non-zero integer
    // would treat a `2` — which the schema forbids and a corrupt file can contain — as `true`. The point of checking
    // is that a value the schema does not allow is reported rather than interpreted.
    for value in [2_i64, -1, 99] {
        match device_row(Some("d"), Some("n"), Some("p"), Some("[]"), Some(0), Some(0), Some(value)) {
            Err(RowError::NotABoolean { column, found }) => {
                assert_eq!(column, "blocked");
                assert!(found.contains(&value.to_string()), "{found}");
            }
            other => panic!("`{value}` was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_seen_device_row_is_built_from_its_columns() {
    let row = SeenDeviceRow::from_columns(
        Some("dev_b"),
        Some("Phone"),
        Some("android"),
        Some(10),
        Some(20),
        Some("mdns"),
    )
    .expect("a row");
    assert_eq!(row.device_id, "dev_b");
    assert_eq!(row.source, "mdns");
    assert_eq!(row.first_seen_ms, 10);
}

#[test]
fn the_rows_are_serialisable_which_is_what_the_dump_needs() {
    // `synra db dump` prints these as JSON, and a type that could not be serialised would make the command's own
    // output impossible.
    let row = device_row(Some("d"), Some("n"), Some("p"), Some(r#"["a"]"#), Some(1), Some(2), Some(0))
        .expect("a row");
    let json = serde_json::to_string(&row).expect("serialises");
    assert!(json.contains("\"device_id\":\"d\""), "{json}");
    assert!(json.contains("\"address\":null"), "an absent address is null rather than an empty string: {json}");
    let back: DeviceRow = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, row);
}
