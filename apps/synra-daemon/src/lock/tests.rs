use super::{Claim, HEARTBEAT_INTERVAL_MS, HEARTBEAT_STALE_AFTER_MS, LOCK_FORMAT_VERSION, LockError, LockFile, LockOwner, decide};

fn owner(heartbeat_ms: u64) -> LockOwner {
    LockOwner {
        pid: 4_242,
        version: "0.1.0".to_owned(),
        claimed_at_ms: 0,
        heartbeat_ms,
        clean: false,
    }
}

fn file(heartbeat_ms: u64) -> LockFile {
    LockFile { version: LOCK_FORMAT_VERSION, owner: owner(heartbeat_ms) }
}

// ── A fresh directory ─────────────────────────────────────────────────────────────────────────

#[test]
fn an_absent_lock_means_the_directory_is_free() {
    // Nothing owns it, so the instance takes it. This is the ordinary first start.
    assert_eq!(decide(None, 1_000, "/lock").expect("decides"), Claim::Taken);
    assert!(decide(None, 0, "/lock").expect("decides").may_run());
}

#[test]
fn taking_a_fresh_claim_lets_the_instance_run() {
    assert!(Claim::Taken.may_run());
    assert_eq!(Claim::Taken.refusal(), None);
}

// ── A live owner ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_recent_heartbeat_holds_the_directory() {
    // The case the module exists for: two daemons over one data directory, each holding half the truth about which
    // devices are paired and which plugins are active.
    let claim = decide(Some(&file(1_000)), 2_000, "/lock").expect("decides");
    match &claim {
        Claim::Held { owner, age_ms } => {
            assert_eq!(owner.pid, 4_242);
            assert_eq!(*age_ms, 1_000);
        }
        other => panic!("expected a live owner, got {other:?}"),
    }
    assert!(!claim.may_run());
    let refusal = claim.refusal().expect("a refusal");
    assert!(refusal.contains("4242"), "{refusal}");
    assert!(refusal.contains("0.1.0"), "{refusal}");
}

#[test]
fn a_heartbeat_exactly_at_the_threshold_is_stale() {
    // The threshold is the point at which the owner has missed every beat it was supposed to send, so a heartbeat
    // exactly there is not evidence of life. `<=` here would leave a daemon unable to start after a clean crash
    // until the next millisecond ticked over.
    let at_threshold = file(0);
    assert!(
        !at_threshold.owner.is_live(HEARTBEAT_STALE_AFTER_MS),
        "a heartbeat at the threshold was believed"
    );
    assert!(at_threshold.owner.is_live(HEARTBEAT_STALE_AFTER_MS - 1));
}

#[test]
fn the_refusal_says_how_long_ago_in_seconds() {
    // So a user can tell "something is running" from "something died a moment ago and I should try again" — and
    // the number is in seconds because milliseconds is not a unit a person reads.
    let claim = decide(Some(&file(0)), 45_000, "/lock").expect("decides");
    let refusal = claim.refusal().expect("a refusal");
    assert!(refusal.contains("45s ago"), "{refusal}");
}

// ── A dead owner ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_stale_heartbeat_is_reclaimed() {
    // ★ The ordinary case rather than the exception: a machine loses power, a user kills the process, a debugger
    // stops it. A lock that treated every existing file as a live owner would leave the daemon unable to start
    // ever again.
    let claim = decide(Some(&file(0)), HEARTBEAT_STALE_AFTER_MS + 1, "/lock").expect("decides");
    match &claim {
        Claim::Reclaimed { previous, age_ms } => {
            assert_eq!(previous.pid, 4_242);
            assert_eq!(*age_ms, HEARTBEAT_STALE_AFTER_MS + 1);
        }
        other => panic!("expected a reclaim, got {other:?}"),
    }
    assert!(claim.may_run());
    assert_eq!(claim.refusal(), None, "a reclaim is not something to refuse");
}

#[test]
fn a_reclaim_is_distinct_from_taking_a_free_directory() {
    // The two are not the same event for a user: taking a claim from a dead daemon means the last session ended
    // badly, and the log should say so.
    let free = decide(None, 1_000, "/lock").expect("decides");
    let stale = decide(Some(&file(0)), HEARTBEAT_STALE_AFTER_MS + 1, "/lock").expect("decides");
    assert_ne!(free, stale);
    assert!(free.may_run() && stale.may_run());
}

// ── Clock oddities ────────────────────────────────────────────────────────────────────────────

#[test]
fn a_heartbeat_from_the_future_is_live_rather_than_infinitely_old() {
    // A reading *before* the heartbeat it is checking is a clock that moved, and the saturating subtraction gives
    // zero — which is the safe direction. A wrapping subtraction would give an enormous age and take a live
    // owner's claim away, which produces the two instances this module exists to prevent.
    let from_the_future = file(u64::MAX);
    assert_eq!(from_the_future.owner.heartbeat_age_ms(0), 0);
    assert!(from_the_future.owner.is_live(0));
    assert!(!decide(Some(&from_the_future), 0, "/lock").expect("decides").may_run());
}

#[test]
fn a_clock_that_has_not_moved_still_leaves_a_heartbeat_live() {
    // A daemon that has just written its heartbeat and the second that reads it are the same millisecond on a
    // coarse clock, and that is a live owner.
    assert!(file(1_000).owner.is_live(1_000));
}

// ── Versions ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_lock_from_a_newer_build_is_refused_rather_than_ignored() {
    // A newer daemon may have changed what a claim means, and deciding from fields this build may be misreading is
    // the shape that produces two instances.
    let newer = LockFile { version: LOCK_FORMAT_VERSION + 1, owner: owner(0) };
    match decide(Some(&newer), 0, "/lock") {
        Err(LockError::FromTheFuture { found, expected, .. }) => {
            assert_eq!(found, LOCK_FORMAT_VERSION + 1);
            assert_eq!(expected, LOCK_FORMAT_VERSION);
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
}

#[test]
fn a_lock_from_an_older_build_is_read() {
    // The shape has not changed, so an older claim is decidable — and refusing it would mean a user upgrading
    // could not start until they deleted a file.
    let older = LockFile { version: 0, owner: owner(0) };
    assert!(decide(Some(&older), HEARTBEAT_STALE_AFTER_MS + 1, "/lock").is_ok());
}

#[test]
fn a_written_claim_carries_a_heartbeat_from_the_moment_it_was_taken() {
    // A claim whose heartbeat started at zero would look stale immediately, and the first thing the next start
    // would do is reclaim a claim that is live.
    let lock = LockFile::claim(1, "0.1.0", 5_000);
    assert_eq!(lock.owner.heartbeat_ms, 5_000);
    assert_eq!(lock.owner.claimed_at_ms, 5_000);
    assert_eq!(lock.version, LOCK_FORMAT_VERSION);
    assert!(lock.is_readable());
    assert!(lock.owner.is_live(5_000));
}

#[test]
fn the_heartbeat_is_written_far_more_often_than_it_expires() {
    // The two numbers have to be read together: an interval that drifted toward the threshold would make a live
    // daemon look dead under load, which is the failure that produces two instances. Ten missed beats is the floor
    // a reviewer should accept.
    let missed = HEARTBEAT_STALE_AFTER_MS / HEARTBEAT_INTERVAL_MS;
    assert!(missed >= 10, "only {missed} beats are missed before a live owner looks dead");
}

// ── Serialisation ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_lock_round_trips_so_a_reader_gets_what_the_writer_meant() {
    let lock = LockFile::claim(7, "0.1.0", 1_000);
    let json = serde_json::to_string(&lock).expect("serialises");
    let back: LockFile = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, lock);
    // And camelCase on the wire, matching every other file this kernel writes.
    assert!(json.contains("heartbeatMs"), "{json}");
    assert!(json.contains("claimedAtMs"), "{json}");
}

#[test]
fn lock_errors_explain_themselves() {
    let errors = [
        LockError::Unreadable { path: "/lock".to_owned(), reason: "permission denied".to_owned() },
        LockError::FromTheFuture { path: "/lock".to_owned(), found: 2, expected: 1 },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 30, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
