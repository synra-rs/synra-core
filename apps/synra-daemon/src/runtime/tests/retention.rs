use super::*;

#[test]
fn the_sweep_takes_only_what_it_is_for() {
    // ★ `11` asks for this and it did not exist: *"GC 的测试断言‘用户数据目录未被触碰’"*.
    //
    // The sweep is the only thing in this kernel that **deletes rows**. A `DELETE` with a missing `WHERE`, or a new
    // collection target written against the wrong table, is not a slow failure or a wrong answer — it is a user's paired
    // devices, plugin consents or settings gone, discovered later and unrecoverable. So the assertion is not "the sweep
    // removed something"; it is that **everything it is not for is exactly as it was**.
    //
    // The instrument is `counts()`, which is what `status` reports: every table, from the schema's own list. Using the
    // product's own mechanism means the test cannot pass by looking at a list somebody kept up to date by hand.
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("the schema");

    // Everything with a public writer, so every table the sweep must not touch has a row to lose.
    db.insert_plugin("@acme/notes", true, true, "enabled", 1_000, 1_000)
        .expect("a plugin");
    db.record_grants(
        "@acme/notes",
        &[("device:list".to_owned(), true)],
        1_000,
        "digest",
    )
    .expect("grants");
    db.pair_device(&Paired {
        device_id: "01a139a9-8f3c-72ce-9c96-2b2c81f14551".to_owned(),
        display_name: "Laptop".to_owned(),
        platform: "windows".to_owned(),
        features: "[]".to_owned(),
        address: None,
        paired_at_ms: 1_000,
    })
    .expect("a pairing");
    db.set_config("theme", &serde_json::json!("dark"), 1_000)
        .expect("a setting");

    // And one row in each table the sweep **is** for, all old enough to be collectable.
    db.record_seen_device(&Seen {
        device_id: "01b139a9-8f3c-72ce-9c96-2b2c81f14552".to_owned(),
        display_name: "Phone".to_owned(),
        platform: "android".to_owned(),
        seen_at_ms: 1,
        source: "udp".to_owned(),
    })
    .expect("a seen device");
    db.record_audit(&AuditRecord {
        plugin_id: "@acme/notes".to_owned(),
        capability: "device:list".to_owned(),
        outcome: "allowed".to_owned(),
        at_ms: 1,
        elapsed_ms: Some(1),
        trace_id: None,
    })
    .expect("an audit record");
    db.save_intent(&IntentRecord {
        intent_id: "01c139a9-8f3c-72ce-9c96-2b2c81f14553".to_owned(),
        state: "succeeded".to_owned(),
        created_ms: 1,
        updated_ms: 1,
        origin_device: None,
        request_id: None,
        document: "{}".to_owned(),
    })
    .expect("an intent");

    let before: std::collections::BTreeMap<String, i64> = db
        .counts()
        .expect("counts")
        .into_iter()
        .filter_map(|(table, count)| count.map(|count| (table, count)))
        .collect();

    // Aggressive on purpose: a retention of zero makes every finished intent and every audit record collectable, so the
    // sweep has the maximum opportunity to take something it should not.
    let collected = crate::runtime::intents::sweep(
        &db,
        crate::runtime::intents::Retention {
            intents_ms: 0,
            audit_ms: 0,
        },
    );

    let after: std::collections::BTreeMap<String, i64> = db
        .counts()
        .expect("counts")
        .into_iter()
        .filter_map(|(table, count)| count.map(|count| (table, count)))
        .collect();

    // ★ And nothing else moved. Listed as the tables that must be **unchanged**, so a future collection target fails this
    // test by adding itself to the difference rather than by not being mentioned.
    let untouched = [
        "identity",
        "paired_devices",
        "plugins",
        "plugin_versions",
        "plugin_grants",
        "plugin_actions",
        "plugin_deps",
        "sync_records",
        "transfer_sessions",
        "config",
    ];
    for table in untouched {
        assert_eq!(
            before.get(table),
            after.get(table),
            "the sweep changed `{table}`, which it is not for"
        );
    }
    // And the three it is for each have a name in the list, so this cannot pass by the sweep targeting a table nobody
    // mentioned.
    for table in ["intents", "devices_seen", "plugin_audit"] {
        assert!(
            before.contains_key(table) && after.contains_key(table),
            "`{table}` is a collection target and should appear in the counts"
        );
    }

    // ★ **The "it did collect" assertions come last, and that ordering is deliberate.**
    //
    // They were first, and two controls showed why that was wrong: pointing a collection target at `paired_devices` — the
    // exact failure the list above exists for — tripped *"the audit record was collectable"* instead, because the statement
    // errored and the sweep reported zero. The test still failed, so it looked like a working control; what it never reached
    // was the assertion that would have named the table it damaged. A guard the failure never reaches is a guard that is not
    // being tested, and putting the specific assertion before the general one is what fixes it.
    assert_ne!(collected.intents, 0, "the finished intent was collectable");
    assert_ne!(collected.audit, 0, "the audit record was collectable");
}

// ── Forgetting what is finished ───────────────────────────────────────────────────────────────────

/// A stored intent, ready for the sweep.
fn stored(id: &str, state: &str, at_ms: i64) -> IntentRecord {
    IntentRecord {
        intent_id: id.to_owned(),
        state: state.to_owned(),
        created_ms: at_ms,
        updated_ms: at_ms,
        origin_device: None,
        request_id: None,
        document: "{}".to_owned(),
    }
}

#[test]
fn the_sweep_forgets_a_finished_intent_that_is_old_enough() {
    // ★ The rule the design gives intents: twenty-four hours after they finish. Before this ran nowhere, so a device
    // raising intents for months carried every one of them.
    let dir = TempDir::new("gc-old");
    let (runtime, db) = runtime_shared(dir.path());
    let long_ago = store_time() - (48 * 60 * 60 * 1_000);
    db.lock()
        .save_intent(&stored("finished", "succeeded", long_ago))
        .expect("stored");

    let removed = runtime.collect_intents(24 * 60 * 60 * 1_000);

    assert_eq!(removed, 1);
    assert_eq!(db.lock().intent_count().expect("counted"), 0);
}

#[test]
fn the_sweep_keeps_work_that_is_still_running() {
    // ★ The half that matters more. An intent that has been running for two days is not old data — it is something a user
    // asked for, and a sweep that collected it would lose it without telling anyone.
    let dir = TempDir::new("gc-running");
    let (runtime, db) = runtime_shared(dir.path());
    let long_ago = store_time() - (48 * 60 * 60 * 1_000);
    db.lock()
        .save_intent(&stored("running", "dispatching", long_ago))
        .expect("stored");

    assert_eq!(runtime.collect_intents(24 * 60 * 60 * 1_000), 0);
    assert_eq!(
        runtime.board.lock().len(),
        0,
        "and it was never on the board either"
    );
    assert_eq!(
        db.lock().intent_count().expect("counted"),
        1,
        "still there, still running"
    );
}

#[test]
fn the_sweep_keeps_an_intent_that_finished_recently() {
    // Twenty-four hours is a retention, not a "collect anything finished" rule: a result the user may still be reading must
    // survive the sweep.
    let dir = TempDir::new("gc-recent");
    let (runtime, db) = runtime_shared(dir.path());
    let an_hour_ago = store_time() - (60 * 60 * 1_000);
    db.lock()
        .save_intent(&stored("recent", "succeeded", an_hour_ago))
        .expect("stored");

    assert_eq!(runtime.collect_intents(24 * 60 * 60 * 1_000), 0);
    assert_eq!(db.lock().intent_count().expect("counted"), 1);
}

#[test]
fn the_sweep_does_not_touch_what_a_plugin_stored() {
    // ★ The design's first requirement for GC: user data is never deleted. `plugin_storage` is where a plugin's own values
    // live, and a sweep that reached it would destroy work the user cannot get back.
    let dir = TempDir::new("gc-storage");
    let (runtime, db) = runtime_shared(dir.path());
    db.lock()
        .insert_plugin("@acme/notes", true, true, "healthy", 1, 1)
        .expect("a plugin row");
    db.lock()
        .storage_set("@acme/notes", "draft", "the user's words", 1_000)
        .expect("stored");
    let long_ago = store_time() - (48 * 60 * 60 * 1_000);
    db.lock()
        .save_intent(&stored("finished", "succeeded", long_ago))
        .expect("stored");

    assert_eq!(
        runtime.collect_intents(24 * 60 * 60 * 1_000),
        1,
        "the intent went"
    );

    assert_eq!(
        db.lock()
            .storage_get("@acme/notes", "draft")
            .expect("read")
            .as_deref(),
        Some("the user's words"),
        "and the plugin's data stayed"
    );
}

/// The wall clock, as the store spells it.
///
/// The daemon reads a `u64` and every column in the store is an `i64`, so a test that wants "an hour ago" has to convert —
/// and the conversion is the part that matters: `now_ms` is what the *daemon* answers, not what a row holds.
fn store_time() -> i64 {
    i64::try_from(now_ms()).unwrap_or(i64::MAX)
}

#[test]
fn a_sweep_that_cannot_finish_says_so_rather_than_reporting_zero() {
    // """ + S + """ The failure this report exists for, and it is the shape that hides longest.
    //
    // Every collection target used to swallow its error: a delete that failed logged and returned **zero**, so a sweep that
    // could not do its job produced exactly the same answer as a sweep with nothing to do — and the daemon's loop printed
    // nothing at all, because every count was zero. A database that cannot be collected from would stay that way quietly.
    //
    // """ + S + """ The fixture is a database that was never migrated, which is how round 82 found the same class of bug.
    //
    // `open_in_memory` creates an empty file and runs no schema, so all three targets fail for the same honest reason: the
    // tables are not there. That is a real failure rather than a contrived one, and it needs no seam to inject.
    let db = synra_store::SynraDb::open_in_memory().expect("a database");

    let report = crate::runtime::intents::sweep(
        &db,
        crate::runtime::intents::Retention {
            intents_ms: 0,
            audit_ms: 0,
        },
    );

    assert_eq!(
        report.removed(),
        0,
        "nothing could have been removed: {report:?}"
    );
    // ★ All three are named, so a reader knows which tables to look at — and three rather than one, which is what makes
    // this a report about the sweep rather than about the first thing that went wrong.
    assert_eq!(report.failures.len(), 3, "{report:?}");
    for (failure, table) in report.failures.iter().zip(["intents", "devices", "call"]) {
        assert!(failure.contains(table), "{failure} should name {table}");
    }
}
