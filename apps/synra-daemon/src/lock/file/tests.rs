use std::path::Path;
use super::super::{Claim, HEARTBEAT_STALE_AFTER_MS, LockError, LockFile};
use super::{ClaimFile, encode_claim};

#[test]
fn a_missing_claim_file_is_a_free_directory() {
    // The ordinary first start.
    let dir = tempfile::Builder::new().prefix("missing").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    let claim = ClaimFile::read(&path).expect("reads");
    assert_eq!(claim, ClaimFile::Absent);
    assert!(claim.decide(0, &path).expect("decides").may_run());
}

#[test]
fn an_empty_claim_file_is_absent_rather_than_unreadable() {
    // What a process killed *between* creating and writing leaves behind. It is not a claim and not another
    // instance, so refusing would leave a daemon unable to start after exactly the crash this module exists to
    // recover from.
    let dir = tempfile::Builder::new().prefix("empty").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    std::fs::write(&path, "").expect("writes");
    assert_eq!(ClaimFile::read(&path).expect("reads"), ClaimFile::Absent);

    // Whitespace too, which is what a partial write can leave.
    std::fs::write(&path, "   \n").expect("writes");
    assert_eq!(ClaimFile::read(&path).expect("reads"), ClaimFile::Absent);
}

#[test]
fn a_claim_file_that_is_not_json_is_refused_rather_than_treated_as_absent() {
    // ★ It might be a live owner's file that this build cannot parse. Treating it as absent is how a second daemon
    // starts over a running one — the failure the lock exists to prevent, arriving through the door the policy
    // does not guard.
    let dir = tempfile::Builder::new().prefix("garbage").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    std::fs::write(&path, "not a claim").expect("writes");

    match ClaimFile::read(&path) {
        Err(LockError::Unreadable { path: named, reason }) => {
            assert!(named.contains("daemon.lock"), "{named}");
            assert!(!reason.is_empty());
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_claim_file_a_directory_cannot_be_read_is_refused() {
    // A directory where a file should be is not "no lock": something is there, and something there unreadable is
    // exactly the case that must not become a second instance.
    let dir = tempfile::Builder::new().prefix("isdir").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    std::fs::create_dir_all(&path).expect("creates");
    assert!(matches!(ClaimFile::read(&path), Err(LockError::Unreadable { .. })));
}

#[test]
fn a_valid_claim_file_is_read_into_the_policy() {
    let dir = tempfile::Builder::new().prefix("valid").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    let lock = LockFile::claim(4_242, "0.1.0", 1_000);
    std::fs::write(&path, encode_claim(&lock, &path).expect("encodes")).expect("writes");

    let claim = ClaimFile::read(&path).expect("reads");
    assert_eq!(claim.as_lock(), Some(&lock));

    // And the policy sees a live owner.
    assert!(!claim.decide(2_000, &path).expect("decides").may_run());
}

#[test]
fn a_stale_claim_file_is_read_and_reclaimed() {
    // The crash recovery, through the file rather than through the policy alone.
    let dir = tempfile::Builder::new().prefix("stale").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    std::fs::write(&path, encode_claim(&LockFile::claim(1, "0.1.0", 0), &path).expect("encodes"))
        .expect("writes");

    let claim = ClaimFile::read(&path).expect("reads");
    let decision = claim.decide(HEARTBEAT_STALE_AFTER_MS + 1, &path).expect("decides");
    assert!(matches!(decision, Claim::Reclaimed { .. }));
    assert!(decision.may_run());
}

#[test]
fn a_claim_from_a_newer_build_is_refused() {
    // Through the file, so the version check is exercised where it is actually reached.
    let dir = tempfile::Builder::new().prefix("future").tempdir().expect("a temporary directory");
    let path = dir.path().join("daemon.lock");
    let mut lock = LockFile::claim(1, "9.9.9", 0);
    lock.version = crate::lock::LOCK_FORMAT_VERSION + 1;
    std::fs::write(&path, serde_json::to_string(&lock).expect("serialises")).expect("writes");

    let claim = ClaimFile::read(&path).expect("reads, since the JSON is fine");
    assert!(matches!(claim.decide(0, &path), Err(LockError::FromTheFuture { .. })));
}

#[test]
fn an_encoded_claim_round_trips() {
    let path = Path::new("/lock");
    let lock = LockFile::claim(7, "0.1.0", 1_000);
    let text = encode_claim(&lock, path).expect("encodes");
    let back: LockFile = serde_json::from_str(&text).expect("decodes");
    assert_eq!(back, lock);
    // Pretty, because a user reads this file when they are deciding whether to kill something.
    assert!(text.contains('\n'), "{text}");
}
