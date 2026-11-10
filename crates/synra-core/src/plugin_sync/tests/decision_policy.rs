use super::super::*;
use super::{plugin, theirs};

#[test]
fn a_device_without_the_plugin_gets_it() {
    let action = decide(
        "1.0.0",
        "sha256-a",
        &RemoteState::absent(plugin("@acme/chat")),
        ConflictPolicy::NeverDowngrade,
    );
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
    let action = decide(
        "1.0.0",
        "sha256-a",
        &theirs("1.0.0", "sha256-a"),
        ConflictPolicy::SourceWins,
    );
    match action {
        SyncAction::Skip { why } => assert!(why.contains("exact bytes"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_same_version_with_different_bytes_is_pushed() {
    // The case the digest comparison exists for.
    let action = decide(
        "1.0.0",
        "sha256-a",
        &theirs("1.0.0", "sha256-b"),
        ConflictPolicy::SourceWins,
    );
    assert!(action.is_push());
}

#[test]
fn never_downgrade_refuses_to_send_an_older_version() {
    // ★ The rule the default exists for: an automatic downgrade can put a device back on a version with a known
    // vulnerability, and "my software was remotely rolled back" is a thing users are right to refuse.
    let action = decide(
        "1.9.0",
        "sha256-old",
        &theirs("1.10.0", "sha256-new"),
        ConflictPolicy::NeverDowngrade,
    );
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
        let action = decide(
            ours,
            "sha256-x",
            &theirs(theirs_version, "sha256-y"),
            ConflictPolicy::NeverDowngrade,
        );
        assert!(action.is_push(), "{ours} vs {theirs_version}: {action:?}");
    }
}

#[test]
fn source_wins_sends_whatever_this_device_has() {
    // Available because a user *can* mean it — a device being brought in line deliberately — and never the default.
    let action = decide(
        "1.9.0",
        "sha256-old",
        &theirs("1.10.0", "sha256-new"),
        ConflictPolicy::SourceWins,
    );
    assert!(action.is_push());
    match action {
        SyncAction::Push { why } => assert!(why.contains("by policy"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn keep_newest_sends_only_a_newer_version() {
    assert!(
        decide(
            "1.10.0",
            "a",
            &theirs("1.9.0", "b"),
            ConflictPolicy::KeepNewest
        )
        .is_push()
    );
    assert!(
        !decide(
            "1.9.0",
            "a",
            &theirs("1.10.0", "b"),
            ConflictPolicy::KeepNewest
        )
        .is_push()
    );
    // Equal versions with different bytes: nothing is newer, so nothing moves.
    let action = decide(
        "1.0.0",
        "a",
        &theirs("1.0.0", "b"),
        ConflictPolicy::KeepNewest,
    );
    match action {
        SyncAction::Skip { why } => assert!(why.contains("at least as new"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn independent_does_nothing() {
    let action = decide(
        "9.9.9",
        "a",
        &theirs("1.0.0", "b"),
        ConflictPolicy::Independent,
    );
    match action {
        SyncAction::Skip { why } => assert!(why.contains("independent"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn ask_carries_both_versions_so_the_user_can_decide() {
    let action = decide("1.9.0", "a", &theirs("1.10.0", "b"), ConflictPolicy::Ask);
    match action {
        SyncAction::Ask {
            ours,
            theirs: Some(theirs_version),
        } => {
            assert_eq!(ours, "1.9.0");
            assert_eq!(theirs_version, "1.10.0");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_version_comparison_does_not_get_ten_wrong() {
    // The mistake that ships an old version to everybody: `1.10.0` sorts before `1.9.0` as text.
    assert_eq!(
        compare_versions("1.10.0", "1.9.0"),
        core::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions("2.0.0", "10.0.0"),
        core::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0"),
        core::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-rc.1"),
        core::cmp::Ordering::Greater
    );
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
