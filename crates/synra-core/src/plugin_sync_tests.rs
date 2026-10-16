//! Sync, driven from both devices.
//!
//! The comparison tests are written as the *conversation*: what this device has, what the other one said, and what the
//! sender should do about it. The receiver's tests are written as the attack: a chunk from another round, a package
//! whose bytes are not the ones promised, a transfer declared complete with a hole in it.

use synra_protocol::ids::{DeviceId, PluginId, TransferId};

use super::*;

fn plugin(name: &str) -> PluginId {
    PluginId::parse(name).expect("a valid plugin id")
}

fn session(name: &str) -> SyncSessionId {
    SyncSessionId::new(name)
}

/// What a device that has the plugin at a version and digest reports.
fn theirs(version: &str, digest: &str) -> RemoteState {
    RemoteState {
        plugin_id: plugin("@acme/chat"),
        version: Some(version.to_owned()),
        digest: Some(digest.to_owned()),
        active: true,
    }
}

// ── The comparison ────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_device_without_the_plugin_gets_it() {
    let action = decide("1.0.0", "sha256-a", &RemoteState::absent(plugin("@acme/chat")), ConflictPolicy::NeverDowngrade);
    assert!(action.is_push());
    assert_eq!(action.as_str(), "push");
    match action {
        SyncAction::Push { why } => assert!(why.contains("does not have"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_device_with_the_exact_bytes_is_skipped() {
    // ★ The digest and not the version: two devices may hold the same version string with different bytes — a rebuilt
    // artifact, a hand-edited bundle — and comparing versions alone would call that synced.
    let action = decide("1.0.0", "sha256-a", &theirs("1.0.0", "sha256-a"), ConflictPolicy::SourceWins);
    match action {
        SyncAction::Skip { why } => assert!(why.contains("exact bytes"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_same_version_with_different_bytes_is_pushed() {
    // The case the digest comparison exists for.
    let action = decide("1.0.0", "sha256-a", &theirs("1.0.0", "sha256-b"), ConflictPolicy::SourceWins);
    assert!(action.is_push());
}

#[test]
fn never_downgrade_refuses_to_send_an_older_version() {
    // ★ The rule the default exists for: an automatic downgrade can put a device back on a version with a known
    // vulnerability, and "my software was remotely rolled back" is a thing users are right to refuse.
    let action = decide("1.9.0", "sha256-old", &theirs("1.10.0", "sha256-new"), ConflictPolicy::NeverDowngrade);
    match action {
        SyncAction::Skip { why } => {
            assert!(why.contains("1.10.0") && why.contains("older"), "{why}");
        }
        other => panic!("expected a skip, got {other:?}"),
    }
}

#[test]
fn never_downgrade_sends_a_newer_or_equal_version() {
    for (ours, theirs_version) in [("1.10.0", "1.9.0"), ("1.0.0", "1.0.0")] {
        let action =
            decide(ours, "sha256-x", &theirs(theirs_version, "sha256-y"), ConflictPolicy::NeverDowngrade);
        assert!(action.is_push(), "{ours} vs {theirs_version}: {action:?}");
    }
}

#[test]
fn source_wins_sends_whatever_this_device_has() {
    // Available because a user *can* mean it — a device being brought in line deliberately — and never the default.
    let action = decide("1.9.0", "sha256-old", &theirs("1.10.0", "sha256-new"), ConflictPolicy::SourceWins);
    assert!(action.is_push());
    match action {
        SyncAction::Push { why } => assert!(why.contains("by policy"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn keep_newest_sends_only_a_newer_version() {
    assert!(decide("1.10.0", "a", &theirs("1.9.0", "b"), ConflictPolicy::KeepNewest).is_push());
    assert!(!decide("1.9.0", "a", &theirs("1.10.0", "b"), ConflictPolicy::KeepNewest).is_push());
    // Equal versions with different bytes: nothing is newer, so nothing moves.
    let action = decide("1.0.0", "a", &theirs("1.0.0", "b"), ConflictPolicy::KeepNewest);
    match action {
        SyncAction::Skip { why } => assert!(why.contains("at least as new"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn independent_does_nothing() {
    let action = decide("9.9.9", "a", &theirs("1.0.0", "b"), ConflictPolicy::Independent);
    match action {
        SyncAction::Skip { why } => assert!(why.contains("independent"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn ask_carries_both_versions_so_the_user_can_decide() {
    let action = decide("1.9.0", "a", &theirs("1.10.0", "b"), ConflictPolicy::Ask);
    match action {
        SyncAction::Ask { ours, theirs: Some(theirs_version) } => {
            assert_eq!(ours, "1.9.0");
            assert_eq!(theirs_version, "1.10.0");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_version_comparison_does_not_get_ten_wrong() {
    // The mistake that ships an old version to everybody: `1.10.0` sorts before `1.9.0` as text.
    assert_eq!(compare_versions("1.10.0", "1.9.0"), core::cmp::Ordering::Greater);
    assert_eq!(compare_versions("2.0.0", "10.0.0"), core::cmp::Ordering::Less);
    assert_eq!(compare_versions("1.0.0", "1.0.0"), core::cmp::Ordering::Equal);
    assert_eq!(compare_versions("1.0.0", "1.0.0-rc.1"), core::cmp::Ordering::Greater);
}

#[test]
fn every_policy_has_a_name() {
    let policies = [
        ConflictPolicy::NeverDowngrade,
        ConflictPolicy::SourceWins,
        ConflictPolicy::KeepNewest,
        ConflictPolicy::Independent,
        ConflictPolicy::Ask,
    ];
    let mut seen: Vec<&str> = Vec::new();
    for policy in policies {
        let name = policy.as_str();
        assert!(!name.is_empty());
        assert!(!seen.contains(&name), "{name} names two policies");
        seen.push(name);
    }
    assert_eq!(seen.len(), 5);
}

// ── The receiving side ────────────────────────────────────────────────────────────────────────────

/// A session with four chunks.
fn opened() -> SyncSession {
    SyncSession::open(
        session("round-1"),
        plugin("@acme/chat"),
        DeviceId::new(),
        TransferId::new(),
        "1.0.0",
        "sha256-declared",
        4,
    )
    .expect("a session")
}

#[test]
fn a_chunk_from_another_round_is_refused() {
    // ★ The isolation rule. A chunk from a previous round has the same index and different bytes, and absorbing one
    // would corrupt the package in a way no digest catches until the end — or, worse, in a way it does.
    let mut opened = opened();
    match opened.absorb(&session("round-2"), 0) {
        Err(SyncError::WrongSession { theirs, ours }) => {
            assert_eq!(theirs, "round-2");
            assert_eq!(ours, "round-1");
        }
        other => panic!("expected a session refusal, got {other:?}"),
    }
    assert_eq!(opened.received(), 0, "nothing was absorbed");
}

#[test]
fn a_chunk_beyond_the_package_is_refused() {
    let mut opened = opened();
    match opened.absorb(&session("round-1"), 4) {
        Err(SyncError::ChunkOutOfRange { index, total }) => {
            assert_eq!(index, 4);
            assert_eq!(total, 4);
        }
        other => panic!("expected a range refusal, got {other:?}"),
    }
}

#[test]
fn a_session_with_no_chunks_is_not_a_session() {
    match SyncSession::open(
        session("empty"),
        plugin("@acme/chat"),
        DeviceId::new(),
        TransferId::new(),
        "1.0.0",
        "sha256-x",
        0,
    ) {
        Err(SyncError::NoChunks) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn chunks_are_counted_once_and_a_resend_is_not_an_error() {
    // A re-sent chunk is what a resumption *is*: a receiver that refused one would make a retry after a lost
    // acknowledgement look like corruption.
    let mut opened = opened();
    assert!(opened.absorb(&session("round-1"), 0).expect("a chunk"));
    assert!(!opened.absorb(&session("round-1"), 0).expect("a duplicate"), "the second is not new");
    assert_eq!(opened.received(), 1);
    assert_eq!(opened.duplicates(), 1);

    let _ = opened.absorb(&session("round-1"), 3);
    assert_eq!(opened.missing(), vec![1, 2]);
    assert!(!opened.is_complete());
}

#[test]
fn a_complete_session_has_nothing_missing() {
    let mut opened = opened();
    for index in 0..4 {
        let _ = opened.absorb(&session("round-1"), index);
    }
    assert!(opened.is_complete());
    assert!(opened.missing().is_empty());
    assert_eq!(opened.received(), 4);
    assert_eq!(opened.declared_version(), "1.0.0");
    assert_eq!(opened.declared_digest(), "sha256-declared");
    assert_eq!(opened.plugin_id(), &plugin("@acme/chat"));
}

#[test]
fn a_transfer_declared_complete_with_a_hole_is_refused_and_names_the_hole() {
    // ★ "Complete" is the sender's claim, and the receiver's own count is what decides. A sender that skipped a chunk
    // would otherwise have its word taken for the package.
    let mut opened = opened();
    let _ = opened.absorb(&session("round-1"), 0);
    let _ = opened.absorb(&session("round-1"), 2);
    let _ = opened.absorb(&session("round-1"), 3);

    match opened.conclude("sha256-declared", "sha256-declared") {
        Err(SyncError::Incomplete { missing, indexes }) => {
            assert_eq!(missing, 1);
            assert_eq!(indexes, vec![1]);
        }
        other => panic!("expected an incomplete refusal, got {other:?}"),
    }
}

#[test]
fn a_tampered_package_is_refused_by_the_digest_the_receiver_computes() {
    // ★ The rule from the design document's security table: the receiving device checks the whole package's digest
    // itself. A device that trusted the sender's word about the bytes would be one where compromising a single
    // machine compromises every machine it can reach.
    let mut opened = opened();
    for index in 0..4 {
        let _ = opened.absorb(&session("round-1"), index);
    }
    // Every chunk arrived, and the assembled bytes are not what was promised: one chunk was substituted in transit.
    match opened.conclude("sha256-declared", "sha256-something-else") {
        Err(SyncError::DigestMismatch { declared, found }) => {
            assert_eq!(declared, "sha256-declared");
            assert_eq!(found, "sha256-something-else");
        }
        other => panic!("expected a digest refusal, got {other:?}"),
    }
    // And the same bytes as declared are accepted, so the check is not one that refuses everything.
    assert_eq!(opened.conclude("sha256-declared", "sha256-declared"), Ok(()));
}

#[test]
fn the_missing_list_is_in_order_so_a_retransmit_is_deterministic() {
    // The sender is asked for exactly these, and a list that reordered between reads would make two retransmits of the
    // same hole ask different questions.
    let mut opened = opened();
    let _ = opened.absorb(&session("round-1"), 2);
    assert_eq!(opened.missing(), vec![0, 1, 3]);
    assert_eq!(opened.missing(), vec![0, 1, 3]);
}

// ── The receiver's obligations and the outcome ────────────────────────────────────────────────────

#[test]
fn an_outcome_records_every_duty_the_device_owed_itself() {
    // The seven things the design document says must not be skipped, made answerable rather than claimed. The caller
    // names them, which is the point: a constructor cannot report work it did not see.
    let outcome = SyncOutcome::installed(
        plugin("@acme/chat"),
        session("round-1"),
        "1.0.0",
        true,
        ReceiverDuty::ALL.to_vec(),
    );
    assert!(outcome.is_fully_checked());
    assert!(outcome.installed);
    assert!(outcome.activated);
    assert_eq!(outcome.performed.len(), ReceiverDuty::ALL.len());
    assert!(outcome.describe().contains("enabled"), "{}", outcome.describe());

    // And an outcome that installed without checking is a bug the type can report. The `performed` argument here is empty
    // because it is overwritten by the struct update below — a placeholder that says so, rather than a list that pretends
    // to be the work.
    let unchecked = SyncOutcome {
        performed: vec![ReceiverDuty::PackageDigest],
        ..SyncOutcome::installed(plugin("@acme/chat"), session("round-1"), "1.0.0", true, Vec::new())
    };
    assert!(!unchecked.is_fully_checked());
    // The original is untouched, which is what makes the two assertions about the same value.
    assert!(outcome.is_fully_checked());
}

#[test]
fn a_refusal_is_not_fully_checked_because_nothing_was_installed() {
    let outcome = SyncOutcome::refused(plugin("@acme/chat"), session("round-1"), "the signature did not verify");
    assert!(!outcome.installed);
    assert!(!outcome.activated);
    assert!(outcome.installed_version.is_none());
    assert!(outcome.is_fully_checked(), "nothing was installed, so nothing was owed");
    assert!(outcome.describe().contains("signature"), "{}", outcome.describe());
}

#[test]
fn every_duty_has_a_name_and_the_list_is_the_design_documents() {
    let mut seen: Vec<&str> = Vec::new();
    for duty in ReceiverDuty::ALL {
        let name = duty.as_str();
        assert!(!name.is_empty());
        assert!(!seen.contains(&name), "{name} names two duties");
        seen.push(name);
    }
    assert_eq!(ReceiverDuty::ALL.len(), 7);
    // The two that are about *this* device rather than about the package, which is what "the receiver decides" means.
    assert!(ReceiverDuty::ALL.contains(&ReceiverDuty::LocalActivation));
    assert!(ReceiverDuty::ALL.contains(&ReceiverDuty::LocalGrants));
    assert!(ReceiverDuty::ALL.contains(&ReceiverDuty::SessionComplete));
}

// ── The table ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_table_says_what_each_device_has() {
    let mut table = SyncTable::new();
    assert!(table.is_empty());
    let laptop = DeviceId::new();
    let phone = DeviceId::new();
    table.record(laptop, theirs("1.0.0", "a"));
    table.record(phone, RemoteState::absent(plugin("@acme/chat")));

    assert_eq!(table.len(), 2);
    assert_eq!(table.state_of(&plugin("@acme/chat"), laptop).and_then(|state| state.version.as_deref()), Some("1.0.0"));
    assert!(table.state_of(&plugin("@acme/chat"), phone).is_some_and(|state| !state.has_it()));
    assert_eq!(table.for_plugin(&plugin("@acme/chat")).len(), 2);
    assert!(table.for_plugin(&plugin("@other/thing")).is_empty());
}

#[test]
fn recording_a_device_twice_replaces_what_was_known() {
    // A device's version changes, and the table is a cache of the last thing it said.
    let mut table = SyncTable::new();
    let laptop = DeviceId::new();
    table.record(laptop, theirs("1.0.0", "a"));
    table.record(laptop, theirs("1.1.0", "b"));

    assert_eq!(table.len(), 1);
    assert_eq!(table.state_of(&plugin("@acme/chat"), laptop).and_then(|state| state.version.as_deref()), Some("1.1.0"));
}

#[test]
fn a_record_says_what_happened_and_why() {
    let peer = DeviceId::new();
    let pushed = SyncRecord::new(
        plugin("@acme/chat"),
        peer,
        SyncAction::Push { why: "the other device does not have this plugin".to_owned() },
        1_000,
    );
    assert!(pushed.describe().contains("push"), "{}", pushed.describe());
    assert!(pushed.describe().contains("does not have"), "{}", pushed.describe());
    assert_eq!(pushed.started_at_ms, 1_000);

    let asked = SyncRecord::new(
        plugin("@acme/chat"),
        peer,
        SyncAction::Ask { ours: "1.0.0".to_owned(), theirs: None },
        1_000,
    );
    assert!(asked.describe().contains("ask"), "{}", asked.describe());
    assert!(asked.describe().contains("nothing"), "{}", asked.describe());
}

#[test]
fn every_refusal_explains_itself() {
    let refusals = [
        SyncError::WrongSession { theirs: "round-2".to_owned(), ours: "round-1".to_owned() },
        SyncError::ChunkOutOfRange { index: 9, total: 4 },
        SyncError::NoChunks,
        SyncError::DigestMismatch { declared: "sha256-a".to_owned(), found: "sha256-b".to_owned() },
        SyncError::Incomplete { missing: 2, indexes: vec![1, 3] },
    ];
    for refusal in &refusals {
        let sentence = refusal.to_string();
        assert!(sentence.len() > 20, "{refusal:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
    }
    assert!(refusals[0].to_string().contains("round-2"));
    assert!(refusals[3].to_string().contains("sha256-b"));
}

// ── The receiver's steps, in the order that makes them mean something ────────────────────────────

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
    check.verify_digest(&complete, "sha256-declared").expect("the digest matches");
    check.verify_signature(true, "").expect("the signature verifies");
    check.check_manifest(true, "").expect("the manifest is usable");

    // A figure no volume has, so the refusal is about the comparison rather than about this machine.
    match check.check_room(&std::env::temp_dir(), u64::MAX) {
        Err(SyncError::NoRoom { needed, free }) => {
            assert_eq!(needed, u64::MAX);
            assert!(free > 0, "a real volume reported no free space: {free}");
        }
        other => panic!("expected a room refusal, got {other:?}"),
    }
    // And the step that did not happen is not recorded.
    assert!(!check.performed().contains(&ReceiverDuty::ArchiveLimits), "{:?}", check.performed());

    // The same check with a byte passes, so the gate is about the comparison and not about refusing everything.
    check.check_room(&std::env::temp_dir(), 1).expect("one byte fits");
}

#[test]
fn a_receiver_that_walks_every_step_reports_exactly_what_it_did() {
    // ★ The end of the chain: the outcome's list comes from the steps that were performed, and it equals the design's
    // seven obligations only because each one was actually taken.
    let complete = completed();
    let mut check = ReceiverCheck::new();
    check.verify_digest(&complete, "sha256-declared").expect("the digest matches");
    check.verify_signature(true, "").expect("the signature verifies");
    check.check_manifest(true, "").expect("the manifest is usable");
    check.check_archive(true, "").expect("the archive limits hold");
    check.check_room(&std::env::temp_dir(), 1).expect("one byte fits");
    check.check_session_complete(&complete).expect("the session is complete");
    check.decide_activation(true).expect("this device enables it");
    check.keep_local_grants(true).expect("the grants stay this device's");

    assert_eq!(check.performed(), ReceiverDuty::ALL, "every duty, in the order the type declares");
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
    check.verify_digest(&complete, "sha256-declared").expect("the digest matches");
    check.verify_signature(true, "").expect("the signature verifies");
    check.check_manifest(true, "").expect("the manifest is usable");
    check.check_archive(true, "").expect("the archive limits hold");
    check.check_room(&std::env::temp_dir(), 1).expect("one byte fits");
    check.check_session_complete(&complete).expect("the session is complete");
    check.decide_activation(true).expect("this device enables it");

    match check.keep_local_grants(false) {
        Err(SyncError::StepRefused { step, why }) => {
            assert_eq!(step, "local-grants");
            assert!(why.contains("local"), "{why}");
        }
        other => panic!("expected a grant refusal, got {other:?}"),
    }
    assert!(!check.performed().contains(&ReceiverDuty::LocalGrants));
}


// ── ⑨：发起端把结局写进它对本机的认识 ────────────────────────────────────────────────────────

use crate::messaging::SyncResult;

fn a_result(ok: bool, version: Option<&str>, activated: bool) -> SyncResult {
    SyncResult {
        ok,
        installed_version: version.map(str::to_owned),
        activated,
        error: if ok { None } else { Some("refused".to_owned()) },
    }
}

#[test]
fn a_successful_round_updates_what_the_other_device_has() {
    // ★ 这也是 `SyncTable::record` 的第一个**生产**调用者：在此之前只有测试在写这张表，
    // 所以「A 更新同步状态」这一步没有实现。
    let mut table = SyncTable::new();
    let laptop = DeviceId::new();

    table.apply_result(laptop, &plugin("@acme/chat"), &a_result(true, Some("1.2.0"), true), "sha256-pushed");

    let state = table.state_of(&plugin("@acme/chat"), laptop).expect("recorded");
    assert_eq!(state.version.as_deref(), Some("1.2.0"));
    // ★ 摘要来自发起端自己算的那个，而不是回复 —— 回复里根本没有摘要。
    assert_eq!(state.digest.as_deref(), Some("sha256-pushed"));
    assert!(state.active);
}

#[test]
fn a_failed_round_does_not_move_what_the_other_device_has() {
    // ★ 这一条才是这个函数存在的理由。一次失败的同步**没有**改变对端持有什么：
    // 写成「什么也没有」会让下一次推送判断成「它需要」而重复传输，
    // 写成「新版本」更糟 —— 表会声称对端有一个它从未收到的包。
    let mut table = SyncTable::new();
    let laptop = DeviceId::new();
    let id = plugin("@acme/chat");
    table.record(
        laptop,
        RemoteState { plugin_id: id.clone(), version: Some("1.0.0".to_owned()), digest: Some("old".to_owned()), active: true },
    );

    table.apply_result(laptop, &id, &a_result(false, None, false), "sha256-pushed");

    let state = table.state_of(&id, laptop).expect("still recorded");
    assert_eq!(state.version.as_deref(), Some("1.0.0"), "a failure moved the table");
    assert_eq!(state.digest.as_deref(), Some("old"));
    assert!(state.active);

    // 以及一个自称成功却没有版本的回复：自相矛盾，不更新好过记一个半真半假的状态。
    table.apply_result(laptop, &id, &a_result(true, None, true), "sha256-pushed");
    assert_eq!(table.state_of(&id, laptop).expect("recorded").version.as_deref(), Some("1.0.0"));
}


// ── §5.5：一次同步留下了什么 ────────────────────────────────────────────────────────────────────

#[test]
fn a_record_starts_empty_and_ends_with_a_verdict() {
    // 记录在**开始**时建立，结束时才有结局 —— 所以「没有结局」与「有结局没有结束时间」这两种
    // 自相矛盾的状态在类型上是分开的。
    let started = SyncRecord::new(
        plugin("@acme/chat"),
        DeviceId::new(),
        SyncAction::Ask { ours: String::new(), theirs: None },
        1_000,
    );

    assert!(started.verdict.is_none());
    assert!(started.finished_at_ms.is_none());
    assert!(started.trace_id.is_none(), "还没认出是哪一轮");
    assert_eq!(started.bytes_transferred, 0);

    let done = started
        .identified(
            SyncId::new("sync-1"),
            SyncDirection::Push,
            Some("1.2.0".to_owned()),
            synra_protocol::ids::TraceId::new(),
        )
        .finished(SyncVerdict::Succeeded, 4_096, 2_000)
        .expect("the first verdict is accepted");

    assert_eq!(done.id.as_str(), "sync-1");
    assert_eq!(done.direction, SyncDirection::Push);
    assert_eq!(done.version.as_deref(), Some("1.2.0"));
    assert_eq!(done.verdict, Some(SyncVerdict::Succeeded));
    assert_eq!(done.finished_at_ms, Some(2_000));
    assert_eq!(done.bytes_transferred, 4_096);
    assert!(done.trace_id.is_some());
}

#[test]
fn a_second_verdict_is_refused_because_it_would_replace_the_first() {
    // ★ 这是 `finished` 返回 `Result` 而不是 `self` 的原因：覆盖结局是「最后的说法赢」，
    // 而那种错没人看得出来 —— 一条先失败后成功的记录会读成成功。
    let done = SyncRecord::new(
        plugin("@acme/chat"),
        DeviceId::new(),
        SyncAction::Ask { ours: String::new(), theirs: None },
        1_000,
    )
    .finished(SyncVerdict::Failed { error: "the signature did not verify".to_owned() }, 0, 2_000)
    .expect("the first verdict is accepted");

    match done.clone().finished(SyncVerdict::Succeeded, 10, 3_000) {
        Err(SyncError::StepRefused { step, why }) => {
            assert_eq!(step, "sync-record");
            assert!(why.contains("already"), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // 而原记录没有被改动：它仍然说失败。
    assert_eq!(
        done.verdict,
        Some(SyncVerdict::Failed { error: "the signature did not verify".to_owned() })
    );
}

#[test]
fn a_skipped_round_is_not_a_failed_one() {
    // 三态而不是布尔：跳过意味着双方已经一致，不需要任何人做什么；失败意味着有人得看一眼。
    // 合成一个 `ok: false` 会让界面把两件事说成一件。
    let skipped = SyncRecord::new(
        plugin("@acme/chat"),
        DeviceId::new(),
        SyncAction::Skip { why: "both devices have the same artifact".to_owned() },
        1_000,
    )
    .finished(SyncVerdict::Skipped { reason: "both devices have the same artifact".to_owned() }, 0, 1_500)
    .expect("a verdict");

    assert!(matches!(skipped.verdict, Some(SyncVerdict::Skipped { .. })));
    assert_ne!(skipped.verdict, Some(SyncVerdict::Failed { error: String::new() }));
}


#[test]
fn a_record_round_trips_through_a_database_row() {
    // 表那一半在 `synra-store`（迁移 v10）；这一半把两者接起来，而往返是唯一能证明
    // 「投影列与文档说的是同一件事」的办法 —— 三种结局各走一遍，因为 `Skipped` 与 `Failed`
    // 携带的内容不同，只测一种会漏掉另一种的字段。
    for (verdict, action) in [
        (
            SyncVerdict::Succeeded,
            SyncAction::Push { why: "the peer had nothing".to_owned() },
        ),
        (
            SyncVerdict::Skipped { reason: "both ends agree".to_owned() },
            SyncAction::Skip { why: "same digest".to_owned() },
        ),
        (
            SyncVerdict::Failed { error: "the signature did not verify".to_owned() },
            SyncAction::Refuse { why: "the publisher is untrusted here".to_owned() },
        ),
    ] {
        let record = SyncRecord::new(plugin("@acme/chat"), DeviceId::new(), action, 1_000)
            .identified(
                SyncId::new("sync-1"),
                SyncDirection::Push,
                Some("1.2.0".to_owned()),
                synra_protocol::ids::TraceId::new(),
            )
            .finished(verdict, 4_096, 2_000)
            .expect("a verdict");

        let row = record.to_row().expect("serialises");
        // 投影列与文档来自同一个记录，而不是各写各的。
        assert_eq!(row.sync_id, "sync-1");
        assert_eq!(row.plugin_id, "@acme/chat");
        assert_eq!(row.peer_device, record.peer.to_string());
        assert_eq!(row.started_at_ms, 1_000);
        assert_eq!(row.finished_at_ms, Some(2_000));

        // 而整份记录回得来：包括决定里的原因、结局里的错误、字节数与追踪。
        assert_eq!(SyncRecord::from_row(&row).expect("deserialises"), record);
    }
}

#[test]
fn a_row_that_is_not_this_rounds_document_is_an_error_rather_than_a_guess() {
    // 坏文档必须是错误：一个「猜出来」的记录会让历史页面显示一轮从未发生过的同步。
    let row = synra_store::records::SyncLogRow {
        sync_id: "sync-1".to_owned(),
        plugin_id: "@acme/chat".to_owned(),
        peer_device: "device-b".to_owned(),
        started_at_ms: 1_000,
        finished_at_ms: None,
        document: "{ this is not json".to_owned(),
    };
    assert!(SyncRecord::from_row(&row).is_err());
}


// ── 接收端的收件箱：④–⑦ 的库层 ─────────────────────────────────────────────────────────────────

fn an_inbox() -> SyncInbox {
    SyncInbox::begin(
        session("round-1"),
        plugin("@acme/chat"),
        DeviceId::new(),
        TransferId::new(),
        "1.2.0",
        "sha256-declared",
        3,
    )
    .expect("a round")
}

#[test]
fn chunks_are_assembled_in_index_order_not_arrival_order() {
    // ★ 这是这个类型存在的全部理由：会话知道哪一块到了，检查序列知道整包要验什么，
    // 而**字节**没有地方放 —— daemon 发文件、不收文件，它的入站路径处理的是意图。
    let mut inbox = an_inbox();
    let id = session("round-1");

    // 倒着发，而且中间插一次重传。
    inbox.absorb(&id, 2, b"ccc".to_vec()).expect("third");
    inbox.absorb(&id, 0, b"aaa".to_vec()).expect("first");
    inbox.absorb(&id, 2, b"ccc".to_vec()).expect("third again");
    inbox.absorb(&id, 1, b"bbb".to_vec()).expect("second");

    assert_eq!(inbox.held(), 3, "a retransmission added a chunk");
    // 按 index 而不是按到达顺序 —— 那是「发送端哈希过的包」与「它的一个排列」之间的区别。
    assert_eq!(inbox.assemble().expect("assembled"), b"aaabbbccc");
    assert!(inbox.session().is_complete());
}

#[test]
fn a_package_with_a_hole_is_refused_rather_than_padded() {
    // 用「恰好到了的那几块」拼出来的包会因为一个理由失败它的摘要，而那个理由说不出是哪一块丢了。
    let mut inbox = an_inbox();
    let id = session("round-1");
    inbox.absorb(&id, 0, b"aaa".to_vec()).expect("first");
    inbox.absorb(&id, 2, b"ccc".to_vec()).expect("third");

    match inbox.assemble() {
        Err(SyncError::Incomplete { missing, indexes }) => {
            assert_eq!(missing, 1);
            assert_eq!(indexes, vec![1]);
        }
        other => panic!("expected an incomplete refusal, got {other:?}"),
    }
}

#[test]
fn a_chunk_from_another_round_is_counted_and_refused() {
    // 非零的计数是「有人往这台设备发了一个它不在里面的轮次」的唯一证据，
    // 而 `WrongSession` 存在正是因为混轮会以一个摘要到最后一刻才发现不了的方式损坏一个包。
    let mut inbox = an_inbox();

    match inbox.absorb(&session("round-2"), 0, b"aaa".to_vec()) {
        Err(SyncError::WrongSession { theirs, ours }) => {
            assert_eq!(theirs, "round-2");
            assert_eq!(ours, "round-1");
        }
        other => panic!("expected a session refusal, got {other:?}"),
    }
    assert_eq!(inbox.refused_chunks(), 1);
    assert_eq!(inbox.held(), 0, "a foreign chunk was stored");
}

#[test]
fn an_index_beyond_the_declaration_is_refused_and_not_counted_as_foreign() {
    // 越界与错轮次是两件事：前者是发送端数错了，后者是发送端在另一个轮次里 ——
    // 把它们合成一个计数会让「有人发错轮次」这个信号被数错冲淡。
    let mut inbox = an_inbox();
    match inbox.absorb(&session("round-1"), 3, b"ddd".to_vec()) {
        Err(SyncError::ChunkOutOfRange { index, total }) => {
            assert_eq!(index, 3);
            assert_eq!(total, 3);
        }
        other => panic!("expected a range refusal, got {other:?}"),
    }
    assert_eq!(inbox.refused_chunks(), 0);
}
