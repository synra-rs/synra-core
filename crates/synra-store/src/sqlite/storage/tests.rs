//! What a plugin keeps, and the ways it can be got wrong.

use super::SynraDb;

const PLUGIN: &str = "@acme/notes";
const OTHER: &str = "@acme/chat";

fn db() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    // The table cascades from `plugins`, so a row is needed before anything can be stored against it.
    db.insert_plugin(PLUGIN, true, true, "healthy", 1, 1).expect("a plugin row");
    db.insert_plugin(OTHER, true, true, "healthy", 1, 1).expect("another plugin row");
    db
}

#[test]
fn a_value_comes_back_exactly_as_it_went_in() {
    // The whole contract. A plugin's value is its own format, and anything this layer did to it — trimming, parsing,
    // re-encoding — would be a change the plugin could not see coming.
    let db = db();
    let awkward = "  {\"a\": 1}\n\u{1F600}\ttrailing  ";

    db.storage_set(PLUGIN, "settings", awkward, 1_000).expect("stores");
    let back = db.storage_get(PLUGIN, "settings").expect("reads");

    assert_eq!(back.as_deref(), Some(awkward), "byte for byte");
}

#[test]
fn a_key_that_was_never_set_is_absent_rather_than_empty() {
    // ★ "It stored nothing" and "it never stored anything" are different answers, and a plugin that could not tell them
    // apart would treat a missing setting as an empty one.
    let db = db();

    assert_eq!(db.storage_get(PLUGIN, "never-set").expect("reads"), None);

    // And an empty string is a value, not an absence: a plugin that deliberately cleared a setting must read back what it
    // wrote rather than `None`.
    db.storage_set(PLUGIN, "cleared", "", 1_000).expect("stores");
    assert_eq!(db.storage_get(PLUGIN, "cleared").expect("reads").as_deref(), Some(""));
}

#[test]
fn setting_a_key_twice_replaces_it_rather_than_failing() {
    // An upsert, because a plugin saving its settings a second time has not made a mistake.
    let db = db();

    db.storage_set(PLUGIN, "settings", "first", 1_000).expect("stores");
    db.storage_set(PLUGIN, "settings", "second", 2_000).expect("stores again");

    assert_eq!(db.storage_get(PLUGIN, "settings").expect("reads").as_deref(), Some("second"));
    assert_eq!(db.storage_keys(PLUGIN, None).expect("keys").len(), 1, "one key, not two");
}

#[test]
fn two_plugins_do_not_share_a_key_space() {
    // ★ The isolation that makes the pair the primary key. A shared space would let installing an unrelated plugin change
    // what another one reads — and both are called `settings`, which is exactly what a plugin would call it.
    let db = db();

    db.storage_set(PLUGIN, "settings", "notes", 1_000).expect("stores");
    db.storage_set(OTHER, "settings", "chat", 1_000).expect("stores");

    assert_eq!(db.storage_get(PLUGIN, "settings").expect("reads").as_deref(), Some("notes"));
    assert_eq!(db.storage_get(OTHER, "settings").expect("reads").as_deref(), Some("chat"));

    db.storage_delete(PLUGIN, "settings").expect("deletes");
    assert_eq!(
        db.storage_get(OTHER, "settings").expect("reads").as_deref(),
        Some("chat"),
        "removing one plugin's key leaves the other's alone"
    );
}

#[test]
fn deleting_reports_whether_there_was_anything_to_delete() {
    // Not an error either way — a plugin deleting twice has not made a mistake — but the two answers differ, and a caller
    // that could not tell them apart could not report "it was already gone".
    let db = db();
    db.storage_set(PLUGIN, "k", "v", 1_000).expect("stores");

    assert!(db.storage_delete(PLUGIN, "k").expect("deletes"), "there was one");
    assert!(!db.storage_delete(PLUGIN, "k").expect("deletes again"), "and now there is not");
}

#[test]
fn keys_come_back_ordered_and_by_prefix() {
    let db = db();
    for key in ["b", "a", "c", "ab"] {
        db.storage_set(PLUGIN, key, "v", 1_000).expect("stores");
    }
    db.storage_set(OTHER, "a", "v", 1_000).expect("stores");

    assert_eq!(db.storage_keys(PLUGIN, None).expect("keys"), ["a", "ab", "b", "c"], "ordered, and only this plugin's");
    assert_eq!(db.storage_keys(PLUGIN, Some("a")).expect("keys"), ["a", "ab"]);
    assert!(db.storage_keys(PLUGIN, Some("z")).expect("keys").is_empty());
}

#[test]
fn a_prefix_containing_a_wildcard_is_a_prefix_rather_than_a_pattern() {
    // ★ `LIKE` reads `%` and `_` as wildcards, and a plugin's keys may contain either. A caller naming characters must get
    // the keys that begin with those characters — not every key, which is what an unescaped `%` would return.
    let db = db();
    db.storage_set(PLUGIN, "%secret", "v", 1_000).expect("stores");
    db.storage_set(PLUGIN, "anything", "v", 1_000).expect("stores");
    db.storage_set(PLUGIN, "a_b", "v", 1_000).expect("stores");
    db.storage_set(PLUGIN, "axb", "v", 1_000).expect("stores");

    assert_eq!(db.storage_keys(PLUGIN, Some("%")).expect("keys"), ["%secret"], "not every key");
    assert_eq!(db.storage_keys(PLUGIN, Some("a_")).expect("keys"), ["a_b"], "not axb");
}

#[test]
fn the_bytes_counted_are_the_values() {
    // A quota is a limit on what a plugin keeps. Counting keys, rows or pages would make the number depend on SQLite's
    // layout, and a plugin would fail its quota after a storage upgrade for reasons it cannot see.
    let db = db();
    assert_eq!(db.storage_used_bytes(PLUGIN).expect("counts"), 0, "nothing stored");

    db.storage_set(PLUGIN, "a-key-longer-than-the-value", "12345", 1_000).expect("stores");
    assert_eq!(db.storage_used_bytes(PLUGIN).expect("counts"), 5);

    db.storage_set(PLUGIN, "b", "1234567890", 1_000).expect("stores");
    assert_eq!(db.storage_used_bytes(PLUGIN).expect("counts"), 15, "summed, not per row");
}

#[test]
fn a_multibyte_value_is_counted_in_bytes_rather_than_characters() {
    // ★ Five characters, sixteen bytes: four at three bytes each and one at four. A limit measured in characters would
    // let a plugin store three times what it was allowed, and the plugin would have no way to know why it was refused.
    let db = db();
    db.storage_set(PLUGIN, "k", "\u{4e16}\u{754c}\u{4f60}\u{597d}\u{1F600}", 1_000).expect("stores");

    assert_eq!(
        db.storage_used_bytes(PLUGIN).expect("counts"),
        16,
        "the string is five characters and sixteen bytes"
    );
}

#[test]
fn clearing_removes_one_plugins_storage_and_no_other() {
    // What an uninstall needs: a reinstall that remembers nothing, while the row itself may stay for the audit trail.
    let db = db();
    db.storage_set(PLUGIN, "a", "1", 1_000).expect("stores");
    db.storage_set(PLUGIN, "b", "2", 1_000).expect("stores");
    db.storage_set(OTHER, "a", "1", 1_000).expect("stores");

    assert_eq!(db.storage_clear(PLUGIN).expect("clears"), 2);

    assert!(db.storage_keys(PLUGIN, None).expect("keys").is_empty());
    assert_eq!(db.storage_used_bytes(PLUGIN).expect("counts"), 0);
    assert_eq!(db.storage_keys(OTHER, None).expect("keys").len(), 1, "the other plugin is untouched");
}

#[test]
fn removing_the_plugin_row_takes_its_storage_with_it() {
    // The cascade, asserted rather than assumed. Without it a removed plugin's values stay in the table for ever, and
    // once the row above is gone no query could attribute them to anything.
    //
    // ★ The `DELETE` is written here rather than called, because **the store has no method that removes a plugin** — no
    // `remove_plugin`, no uninstall path. So this is the schema's promise checked at the level the schema is written in;
    // when an uninstall exists, it should be the thing this test calls.
    let db = db();
    db.storage_set(PLUGIN, "settings", "kept", 1_000).expect("stores");

    db.connection
        .execute("DELETE FROM plugins WHERE plugin_id = ?1", rusqlite::params![PLUGIN])
        .expect("removes the plugin row");

    // Read directly, because `storage_get` would answer `None` for a plugin whose row is gone whether the rows are still
    // there or not — and that is the assertion that would pass for the wrong reason.
    let left: i64 = db
        .connection
        .query_row(
            "SELECT COUNT(*) FROM plugin_storage WHERE plugin_id = ?1",
            rusqlite::params![PLUGIN],
            |row| row.get(0),
        )
        .expect("counts");
    assert_eq!(left, 0, "the cascade removed them");
}
