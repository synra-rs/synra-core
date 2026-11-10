use super::super::*;
use super::{opened, plugin, session};

/// A complete session over the four chunks `opened` declares.
fn completed() -> SyncSession {
    // Asked before the binding below, because a local named `session` shadows the helper of the same name — and the
    // first version of this did exactly that, so the helper called itself.
    let id = session("round-1");
    let mut session = opened();
    for index in 0..4u32 {
        let _ = session.absorb(&id, index);
    }
    session
}

#[test]
fn a_receiver_step_out_of_order_is_refused_and_leaves_no_trace() {
    // The signature cannot be checked before the digest: the signature covers the whole package, and the digest is what
    // says the whole package is the one that was sent.
    let mut check = ReceiverCheck::new();

    match check.verify_signature(true, "") {
        Err(SyncError::OutOfOrder { missing, before }) => {
            assert_eq!(missing, "signature");
            assert_eq!(before, "package-digest");
        }
        other => panic!("expected an out-of-order refusal, got {other:?}"),
    }

    // ★ And the refusal left nothing behind. A step that failed its predecessor must not appear in `performed`, or the
    // report at the end would name work that a refusal prevented — which is the defect the constructor had.
    assert!(check.performed().is_empty(), "{:?}", check.performed());
}

#[test]
fn an_incomplete_session_cannot_be_digest_verified() {
    // Two of four chunks: hashing now would hash the wrong bytes and could match nothing the sender promised.
    // The helper is asked before the binding, for the same reason as in `completed`: a local named `session` would
    // shadow the function that is called to make the identifier.
    let id = session("round-1");
    let mut incomplete = opened();
    let _ = incomplete.absorb(&id, 0);
    let _ = incomplete.absorb(&id, 1);

    let mut check = ReceiverCheck::new();
    match check.verify_digest(&incomplete, "sha256-declared") {
        Err(SyncError::Incomplete { missing, indexes }) => {
            assert_eq!(missing, 2);
            assert_eq!(indexes, vec![2, 3]);
        }
        other => panic!("expected an incomplete refusal, got {other:?}"),
    }
    assert!(check.performed().is_empty());
}

#[test]
fn a_receiver_with_no_room_for_the_package_is_refused() {
    let complete = completed();
    let mut check = ReceiverCheck::new();
    check
        .verify_digest(&complete, "sha256-declared")
        .expect("the digest matches");
    check
        .verify_signature(true, "")
        .expect("the signature verifies");
    check
        .check_manifest(true, "")
        .expect("the manifest is usable");

    // A figure no volume has, so the refusal is about the comparison rather than about this machine.
    match check.check_room(&std::env::temp_dir(), u64::MAX) {
        Err(SyncError::NoRoom { needed, free }) => {
            assert_eq!(needed, u64::MAX);
            assert!(free > 0, "a real volume reported no free space: {free}");
        }
        other => panic!("expected a room refusal, got {other:?}"),
    }
    // And the step that did not happen is not recorded.
    assert!(
        !check.performed().contains(&ReceiverDuty::ArchiveLimits),
        "{:?}",
        check.performed()
    );

    // The same check with a byte passes, so the gate is about the comparison and not about refusing everything.
    check
        .check_room(&std::env::temp_dir(), 1)
        .expect("one byte fits");
}

#[test]
fn a_receiver_that_walks_every_step_reports_exactly_what_it_did() {
    // ★ The end of the chain: the outcome's list comes from the steps that were performed, and it equals the design's
    // seven obligations only because each one was actually taken.
    let complete = completed();
    let mut check = ReceiverCheck::new();
    check
        .verify_digest(&complete, "sha256-declared")
        .expect("the digest matches");
    check
        .verify_signature(true, "")
        .expect("the signature verifies");
    check
        .check_manifest(true, "")
        .expect("the manifest is usable");
    check
        .check_archive(true, "")
        .expect("the archive limits hold");
    check
        .check_room(&std::env::temp_dir(), 1)
        .expect("one byte fits");
    check
        .check_session_complete(&complete)
        .expect("the session is complete");
    check
        .decide_activation(true)
        .expect("this device enables it");
    check
        .keep_local_grants(true)
        .expect("the grants stay this device's");

    assert_eq!(
        check.performed(),
        ReceiverDuty::ALL,
        "every duty, in the order the type declares"
    );
    assert!(check.activated());

    let outcome = check.finish(plugin("@acme/chat"), session("round-1"), "1.0.0");
    assert!(outcome.installed);
    assert!(outcome.activated);
    assert!(outcome.is_fully_checked());
}

#[test]
fn a_receiver_that_would_replace_the_grants_is_refused() {
    // §5.4 rule 8: the grants are this device's, and a sync does not overwrite them. The step exists so that "the
    // sender's grants were applied" is a refusal rather than a successful install nobody looked at.
    let complete = completed();
    let mut check = ReceiverCheck::new();
    check
        .verify_digest(&complete, "sha256-declared")
        .expect("the digest matches");
    check
        .verify_signature(true, "")
        .expect("the signature verifies");
    check
        .check_manifest(true, "")
        .expect("the manifest is usable");
    check
        .check_archive(true, "")
        .expect("the archive limits hold");
    check
        .check_room(&std::env::temp_dir(), 1)
        .expect("one byte fits");
    check
        .check_session_complete(&complete)
        .expect("the session is complete");
    check
        .decide_activation(true)
        .expect("this device enables it");

    match check.keep_local_grants(false) {
        Err(SyncError::StepRefused { step, why }) => {
            assert_eq!(step, "local-grants");
            assert!(why.contains("local"), "{why}");
        }
        other => panic!("expected a grant refusal, got {other:?}"),
    }
    assert!(!check.performed().contains(&ReceiverDuty::LocalGrants));
}

#[test]
fn the_receiver_checks_cannot_be_run_out_of_order() {
    // ★ 这条测试回答第 176 轮留下的那个问题：**为什么 `performed` 是空的。**
    //
    // 那一轮把三项检查（磁盘空间、是否启用、权限归本机）接到 daemon 上，而 `performed` 仍然是空的。
    // 这一轮查清了：它们**不是独立的检查**，而是那个七项**序列**里的第 4、6、7 项 ——
    // `check_room` 要 `ArchiveLimits` 与 `Manifest`，`decide_activation` 要 `SessionComplete`，
    // `keep_local_grants` 要 `LocalActivation`。daemon 一项前置都没做，所以三项**全部被拒**。
    //
    // 而「一个被拒绝的步骤不留痕迹」（第 130 轮的设计）正是 `performed` 空着的原因 ——
    // 于是那个 outcome **没有**声称做过任何检查，那是对的。
    let mut check = ReceiverCheck::new();

    assert!(
        matches!(
            check.check_room(std::path::Path::new("."), 1),
            Err(SyncError::OutOfOrder { .. })
        ),
        "check_room ran without the checks it depends on"
    );
    assert!(
        matches!(
            check.decide_activation(true),
            Err(SyncError::OutOfOrder { .. })
        ),
        "activation was decided before the session was known complete"
    );
    assert!(
        matches!(
            check.keep_local_grants(true),
            Err(SyncError::OutOfOrder { .. })
        ),
        "grants were kept before activation was decided"
    );

    // 而三次拒绝之后，什么都没有被记为做过。
    assert!(check.performed().is_empty(), "a refused step left a trace");
}
