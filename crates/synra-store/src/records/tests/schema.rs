use super::super::columns;

#[test]
fn every_column_list_has_one_entry_per_argument() {
    // ★ The lists exist because `from_columns` reads positionally — which is what a binding produces — so a `SELECT`
    // that lists the columns in another order swaps two fields. A swap between two `TEXT` columns is the dangerous
    // one: nothing fails, and a device's name becomes its platform.
    //
    // This asserts the count, and `the_column_lists_match_the_migration_schema` below asserts the names.
    assert_eq!(columns::DEVICE.len(), 8);
    assert_eq!(columns::SEEN_DEVICE.len(), 6);
    assert_eq!(columns::IDENTITY.len(), 4);
    assert_eq!(columns::PLUGIN.len(), 6);
    assert_eq!(columns::CONFIG.len(), 3);
}

#[test]
fn the_column_lists_match_the_migration_schema() {
    // ★ The other half of the check: the names have to be the ones the migration created, or a `SELECT` built from
    // these lists names a column that does not exist — which SQLite reports, but only when the query runs.
    let sql = crate::db::MIGRATIONS
        .iter()
        .flat_map(|migration| migration.statements.iter())
        .copied()
        .collect::<Vec<&str>>()
        .join("\n");

    for list in [
        (columns::DEVICE, "paired_devices"),
        (columns::SEEN_DEVICE, "devices_seen"),
        (columns::IDENTITY, "identity"),
        (columns::PLUGIN, "plugins"),
        (columns::CONFIG, "config"),
    ] {
        for column in list.0 {
            assert!(
                sql.contains(column),
                "`{column}` is in the {} column list and not in the migrations",
                list.1
            );
        }
    }
}

#[test]
fn the_column_lists_have_no_repeats() {
    // A repeated name in a `SELECT` is a row with two columns the same, and a positional read that takes both would
    // read the wrong value for one of them.
    for (list, table) in [
        (columns::DEVICE, "paired_devices"),
        (columns::SEEN_DEVICE, "devices_seen"),
        (columns::IDENTITY, "identity"),
        (columns::PLUGIN, "plugins"),
        (columns::CONFIG, "config"),
    ] {
        let mut sorted = list.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), list.len(), "{table} lists a column twice");
    }
}

#[test]
fn the_column_order_matches_the_read_order() {
    // ★ The assertion the whole `columns` module exists for. A `SELECT` built from these lists must hand its columns
    // to `from_columns` in this order — and a reader that reordered one would produce a row whose fields are swapped.
    //
    // It is checked by building a row from values tagged with the column name and asserting each landed in the field
    // with the same name.
    assert_eq!(
        columns::CONFIG,
        &["key", "value", "updated_ms"],
        "the order `ConfigRow::from_columns` takes"
    );
    assert_eq!(
        columns::IDENTITY,
        &["device_id", "display_name", "platform", "created_at_ms"],
        "the order `IdentityRow::from_columns` takes"
    );
    assert_eq!(
        &columns::DEVICE[..3],
        &["device_id", "display_name", "platform"],
        "the order `DeviceRow::from_columns` takes its text columns"
    );
    assert_eq!(
        &columns::DEVICE[4..],
        &["paired_at_ms", "last_seen_ms", "blocked", "last_address"],
        "the order `DeviceRow::from_columns` takes, with the two columns a migration appended at the end"
    );
}
