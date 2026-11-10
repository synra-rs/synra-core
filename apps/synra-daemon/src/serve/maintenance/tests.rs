use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::retention::{collect_loop, fast_gc_task};
use super::sleep_until_shutdown;

/// A migrated database, and a supervisor that is not shutting down.
fn world() -> (
    Arc<Mutex<synra_store::SynraDb>>,
    Arc<synra_core::supervisor::Supervisor>,
) {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    (
        Arc::new(Mutex::new(db)),
        Arc::new(synra_core::supervisor::Supervisor::new(1_000)),
    )
}

fn stored(id: &str, state: &str, at_ms: i64) -> synra_store::records::IntentRecord {
    synra_store::records::IntentRecord {
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
fn the_sweep_runs_on_its_schedule() {
    // ★ The schedule is the whole of what this function is, so it is what the test drives — with milliseconds rather
    // than the hour the daemon uses. A loop that never ran would leave the table growing for ever, and nothing else in
    // the daemon would notice.
    let (db, supervisor) = world();
    // ★ The epoch, which is older than any retention window. The first version of this used a large *positive* number
    // hoping it read as "long ago" — it is 2.1e12, which is **after** now, so the intent was in the future and the
    // sweep was right to keep it.
    db.lock()
        .save_intent(&stored("finished", "succeeded", 0))
        .expect("stored");

    let running = {
        let db = Arc::clone(&db);
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || {
            collect_loop(&db, &supervisor, fast_gc_task());
        })
    };

    // Give it long enough for the first delay and at least one interval.
    std::thread::sleep(Duration::from_millis(120));
    assert_eq!(
        db.lock().intent_count().expect("counted"),
        0,
        "the old one went"
    );

    let _ = supervisor.begin_shutdown();
    assert!(running.join().is_ok(), "and the loop returned");
}

#[test]
fn a_daemon_asked_to_stop_does_not_wait_out_its_schedule() {
    // ★ Why the first wait is sliced. The daemon's first sweep is a minute away, and a stop request during that minute
    // must not take the whole minute to be noticed — the shutdown report would be missing a task that was still asleep.
    let (_, supervisor) = world();
    let shutdown = {
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let _ = supervisor.begin_shutdown();
        })
    };

    let started = std::time::Instant::now();
    let waited = sleep_until_shutdown(&supervisor, Duration::from_secs(30));
    let elapsed = started.elapsed();

    assert!(!waited, "the wait was cut short");
    assert!(
        elapsed < Duration::from_secs(5),
        "and it did not wait out the thirty seconds: {elapsed:?}"
    );
    assert!(shutdown.join().is_ok());
}

#[test]
fn the_schedule_forgets_devices_beyond_the_ceiling_too() {
    // ★ The other half of the sweep, and the one table in the design's GC section that genuinely fills up: the discovery
    // thread writes it, and a kernel on a shared network hears a new device every few minutes.
    let (db, supervisor) = world();
    for index in 0..(crate::runtime::intents::SEEN_DEVICE_CEILING + 3) {
        let sighting = synra_store::Seen {
            device_id: format!("{index:08}-0000-4000-8000-000000000000"),
            display_name: format!("device {index}"),
            platform: "linux".to_owned(),
            seen_at_ms: 1_000 + i64::try_from(index).unwrap_or(0),
            source: "broadcast".to_owned(),
        };
        db.lock().record_seen_device(&sighting).expect("heard");
    }
    assert_eq!(db.lock().seen_devices().expect("listed").len(), 503);

    let running = {
        let db = Arc::clone(&db);
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || {
            collect_loop(&db, &supervisor, fast_gc_task());
        })
    };

    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        db.lock().seen_devices().expect("listed").len(),
        crate::runtime::intents::SEEN_DEVICE_CEILING,
        "the ceiling held"
    );

    let _ = supervisor.begin_shutdown();
    assert!(running.join().is_ok());
}

#[test]
fn a_sweep_with_nothing_to_collect_removes_nothing() {
    // The ordinary case, and the one that runs every hour: a daemon whose intents are all recent logs nothing and
    // changes nothing.
    let (db, supervisor) = world();
    // `now_ms` is already an `i64`, which the first version of this did not notice.
    let recent = synra_store::sqlite::now_ms();
    db.lock()
        .save_intent(&stored("recent", "succeeded", recent))
        .expect("stored");

    let running = {
        let db = Arc::clone(&db);
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || {
            collect_loop(&db, &supervisor, fast_gc_task());
        })
    };

    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        db.lock().intent_count().expect("counted"),
        1,
        "nothing was old enough"
    );

    let _ = supervisor.begin_shutdown();
    assert!(running.join().is_ok());
}
