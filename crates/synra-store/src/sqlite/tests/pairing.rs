use super::migrated;

/// A pairing record, which is what the write takes.
///
/// A helper rather than a literal at each call site, because what most of these tests are about is the token and the
/// address rather than the platform and the features.
fn paired(
    device_id: &str,
    display_name: &str,
    address: Option<&str>,
    now_ms: i64,
) -> crate::sqlite::Paired {
    crate::sqlite::Paired {
        device_id: device_id.to_owned(),
        display_name: display_name.to_owned(),
        platform: "windows".to_owned(),
        features: "[]".to_owned(),
        address: address.map(str::to_owned),
        paired_at_ms: now_ms,
    }
}


#[test]
fn pairing_without_an_address_stores_none() {
    // An empty address is "this side has none", not "the address is the empty string": a caller that pairs a device it
    // reached over something other than a socket — or a test — must not leave a value behind that a device list would
    // then render as a blank line where an address belongs.
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", None, 1_000)).expect("pairs");

    assert_eq!(db.paired_devices().expect("lists")[0].address, None);
}


#[test]
fn pairing_again_clears_a_block() {
    // A device the user blocked and then deliberately paired again is a decision the user has reversed. Leaving the
    // block in place would make the second pairing appear to succeed and then refuse every link.
    //
    // The block is set with SQL rather than through a method because no method exists: nothing in the kernel blocks a
    // device yet, so a `set_device_blocked` would be unused public API written only to make this test read nicely.
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", None, 1_000)).expect("pairs");
    db.connection
        .execute("UPDATE paired_devices SET blocked = 1 WHERE device_id = 'dev-1'", [])
        .expect("blocks");
    assert!(!db.is_paired_with("dev-1").expect("queries"), "a blocked device is not usable");

    db.pair_device(&paired("dev-1", "Laptop", None, 2_000)).expect("pairs again");
    assert!(db.is_paired_with("dev-1").expect("queries"));
}
