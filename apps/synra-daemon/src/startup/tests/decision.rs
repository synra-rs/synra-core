use crate::args::Parsed;
use crate::lock::HEARTBEAT_STALE_AFTER_MS;
use super::super::startup;
use super::{Cleanup, args};

#[test]
fn a_free_directory_is_claimed_and_the_daemon_runs() {
    let dir = Cleanup::new("free");
    let startup = startup(&args(&dir.data(), &[]), 0);
    assert!(startup.may_run(), "{startup:?}");
    assert_eq!(startup.exit_code(), 0);
    assert!(startup.failure().is_none());
    assert!(startup.lines().iter().any(|line| line.contains("claimed")), "{:?}", startup.lines());
}

#[test]
fn the_lines_name_the_installation_being_started() {
    // A user with two profiles needs to see which one this is.
    let dir = Cleanup::new("lines");
    let startup = startup(&args(&dir.data(), &[]), 0);
    let lines = startup.lines();
    assert!(lines[0].contains("synra-daemon"), "{lines:?}");
    assert!(lines.iter().any(|line| line.contains("transport port")), "{lines:?}");
    // The heartbeat interval, because it is the number that decides how long a dead daemon blocks the next start.
    assert!(lines.iter().any(|line| line.contains("heartbeat every")), "{lines:?}");
}

// ── A live owner ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_live_owner_stops_a_second_start() {
    // ★ Two daemons over one database: both open the same SQLite file, both believe they are the only one, and
    // each holds half the truth about which devices are paired.
    let dir = Cleanup::new("held");
    dir.write_claim(1_000, 4_242);

    let startup = startup(&args(&dir.data(), &[]), 2_000);
    let a = args(&dir.data(), &[]);
    let from_args = Parsed::resolve(&a).expect("resolves").plan.lock_path();
    let expected = dir.lock_path();
    assert_eq!(
        from_args, expected,
        "the daemon looks at {} and the fixture wrote {}",
        from_args.display(),
        expected.display()
    );
    assert!(!startup.may_run(), "{startup:?}");
    assert_eq!(startup.exit_code(), 1);
    let reason = startup.failure().expect("a reason");
    assert!(reason.contains("4242"), "{reason}");
    assert!(reason.contains("already"), "{reason}");
}

#[test]
fn a_refusal_still_shows_which_installation_is_in_use() {
    // The first thing a user needs to know, and the thing a bare "already running" would not tell them.
    let dir = Cleanup::new("held-lines");
    dir.write_claim(1_000, 4_242);
    let startup = startup(&args(&dir.data(), &[]), 2_000);
    let lines = startup.lines();
    assert!(lines.iter().any(|line| line.contains("data")), "{lines:?}");
    assert!(lines.iter().any(|line| line.contains("4242")), "{lines:?}");
}

// ── A dead owner ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_dead_owner_is_reclaimed_and_the_reclaim_is_reported() {
    // ★ A machine loses power, a user kills the process, a debugger stops it. A lock that treated every existing
    // file as a live owner would leave the daemon unable to start ever again — and a reclaim that was silent would
    // leave a user with an unexplained gap in the record.
    let dir = Cleanup::new("reclaim");
    dir.write_claim(0, 9_999);

    let startup = startup(&args(&dir.data(), &[]), HEARTBEAT_STALE_AFTER_MS + 1);
    assert!(startup.may_run(), "{startup:?}");
    let lines = startup.lines();
    let reclaim = lines
        .iter()
        .find(|line| line.contains("reclaimed"))
        .unwrap_or_else(|| panic!("no reclaim line in {lines:?}"));
    assert!(reclaim.contains("9999"), "{reclaim}");
    assert!(reclaim.contains("ended without shutting down"), "{reclaim}");
}

#[test]
fn a_reclaim_is_reported_differently_from_taking_a_free_directory() {
    // The same event for the claim and different events for a user.
    let free = Cleanup::new("free-vs-reclaim");
    let stale = Cleanup::new("stale-vs-free");
    stale.write_claim(0, 1);

    let free_lines = startup(&args(&free.data(), &[]), 0).lines();
    let stale_lines = startup(&args(&stale.data(), &[]), HEARTBEAT_STALE_AFTER_MS + 1).lines();

    assert!(!free_lines.iter().any(|line| line.contains("reclaimed")), "{free_lines:?}");
    assert!(stale_lines.iter().any(|line| line.contains("reclaimed")), "{stale_lines:?}");
}

// ── A claim that cannot be read ───────────────────────────────────────────────────────────────

#[test]
fn a_claim_file_that_cannot_be_read_stops_the_start() {
    // It might be a live owner's. Treating it as absent is how a second daemon starts over a running one — the
    // failure the lock exists to prevent, arriving through the door the policy does not guard.
    let dir = Cleanup::new("garbage");
    std::fs::write(dir.lock_path(), "not a claim").expect("writes");

    let startup = startup(&args(&dir.data(), &[]), 0);
    assert!(!startup.may_run(), "{startup:?}");
    assert_eq!(startup.exit_code(), 1);
    assert!(startup.failure().is_some());
}

#[test]
fn an_empty_claim_file_is_recovered_from() {
    // What a process killed between creating and writing leaves behind. Refusing would leave a daemon unable to
    // start after exactly the crash the lock exists to recover from.
    let dir = Cleanup::new("empty-recover");
    std::fs::write(dir.lock_path(), "").expect("writes");
    assert!(startup(&args(&dir.data(), &[]), 0).may_run());
}
