use crate::args::ClaimFile;
use super::super::{begin, release};
use super::{Cleanup, args};

#[test]
fn starting_writes_the_claim_it_decided_about() {
    // ★ A daemon that only *decided* it owned the directory reported "claimed the data directory" while leaving no
    // file behind, so a second instance decided the same thing and both believed they were alone. The exclusive
    // claim was decorative.
    let dir = Cleanup::new("writes-claim");
    let decision = begin(&args(&dir.data(), &[]), 4_242, 1_000);
    assert!(decision.may_run(), "{decision:?}");

    let path = dir.lock_path();
    let written = ClaimFile::read(&path).expect("reads");
    let lock = written.as_lock().expect("a claim was written");
    assert_eq!(lock.owner.pid, 4_242);
    assert_eq!(lock.owner.heartbeat_ms, 1_000);
    assert_eq!(lock.owner.claimed_at_ms, 1_000);
}

#[test]
fn a_second_start_after_the_first_is_refused() {
    // The end-to-end property, through the file system rather than through the policy: the first start leaves a
    // claim, and the second sees it and refuses. This is the case that was broken.
    let dir = Cleanup::new("second-start");
    let first = begin(&args(&dir.data(), &[]), 1_111, 1_000);
    assert!(first.may_run(), "{first:?}");

    // One second later, so the heartbeat is fresh.
    let second = begin(&args(&dir.data(), &[]), 2_222, 2_000);
    assert!(!second.may_run(), "{second:?}");
    assert_eq!(second.exit_code(), 1);
    assert!(second.failure().expect("a reason").contains("1111"));
}

#[test]
fn a_start_after_a_clean_shutdown_is_a_free_directory() {
    // A clean shutdown takes its own claim away, so the next start is an ordinary first start rather than a
    // reclaim that writes "the previous session ended without shutting down" into the log about a session that
    // ended perfectly well.
    let dir = Cleanup::new("clean-shutdown");
    let first = begin(&args(&dir.data(), &[]), 1_111, 1_000);
    assert!(first.may_run(), "{first:?}");
    release(&first).expect("releases");
    // ★ The claim is *kept* and marked, not deleted: a deleted file is indistinguishable from a daemon killed
    // before it wrote one, and that difference is what the next start wants to know.
    assert!(dir.lock_path().exists(), "a clean shutdown deleted its claim");
    let kept = ClaimFile::read(&dir.lock_path()).expect("reads");
    assert!(kept.as_lock().expect("a claim").owner.clean, "the claim was not marked clean");

    let second = begin(&args(&dir.data(), &[]), 2_222, 2_000);
    assert!(second.may_run(), "{second:?}");
    assert!(
        !second.lines().iter().any(|line| line.contains("reclaimed")),
        "a clean restart reported a crash: {:?}",
        second.lines()
    );
}

#[test]
fn a_diagnostic_run_writes_no_claim() {
    // Writing one would make a run that promised not to touch the directory the one that held it.
    let dir = Cleanup::new("diagnostic-no-write");
    let decision = begin(&args(&dir.data(), &["--diagnostic"]), 4_242, 1_000);
    assert!(decision.may_run(), "{decision:?}");
    assert!(!dir.lock_path().exists(), "a diagnostic run took a claim");
}

#[test]
fn a_dry_run_writes_no_claim() {
    let dir = Cleanup::new("dry-no-write");
    let decision = begin(&args(&dir.data(), &["--dry-run"]), 4_242, 1_000);
    assert_eq!(decision.exit_code(), 0);
    assert!(decision.plan().is_none(), "a dry run has no claim to release");
    assert!(!dir.lock_path().exists());
}

#[test]
fn a_refreshed_heartbeat_keeps_the_claim_identity() {
    // The claimed-at reading and the pid are the identity: a user reading the file wants to know when the session
    // started and which process it is. Overwriting them on every beat would make `claimedAtMs` mean "the last
    // beat", which is the one thing a reader is trying to tell apart from the heartbeat.
    let dir = Cleanup::new("heartbeat");
    let decision = begin(&args(&dir.data(), &[]), 4_242, 1_000);
    assert!(decision.may_run(), "{decision:?}");
    let path = dir.lock_path();
    let lock = ClaimFile::read(&path)
        .expect("reads")
        .as_lock()
        .expect("a claim")
        .clone();

    let refreshed = crate::args::refresh_claim(&path, &lock, 4_000).expect("refreshes");
    assert_eq!(refreshed.owner.heartbeat_ms, 4_000);
    assert_eq!(refreshed.owner.claimed_at_ms, 1_000, "the identity moved");
    assert_eq!(refreshed.owner.pid, 4_242);

    // And it is still one claim, readable, with the new beat — so a live daemon does not look dead.
    let reread = ClaimFile::read(&path).expect("reads");
    assert_eq!(reread.as_lock().expect("a claim").owner.heartbeat_ms, 4_000);
}

#[test]
fn removing_a_claim_that_is_gone_is_not_an_error() {
    // A shutdown that failed because it had already cleaned up would report a problem where there is none.
    let dir = Cleanup::new("remove-twice");
    let path = dir.lock_path();
    assert!(crate::args::remove_claim(&path).is_ok(), "a missing file is not a failure");
    let decision = begin(&args(&dir.data(), &[]), 1, 0);
    assert!(decision.may_run(), "{decision:?}");
    assert!(crate::args::remove_claim(&path).is_ok());
    assert!(crate::args::remove_claim(&path).is_ok());
}
