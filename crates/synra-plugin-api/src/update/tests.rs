//! The threshold table, one row at a time, and the cases where two rows hold at once.

use crate::publisher::{Fingerprint, PluginTrust, Untrusted};
use crate::update::{
    ChangeSize, UpdateAction, UpdateBlocker, UpdateFacts, UpdatePolicy, decide,
};

fn routine(change: ChangeSize) -> UpdateFacts {
    UpdateFacts::routine(PluginTrust::TrustedPublisher, change)
}

#[test]
fn a_routine_update_is_automatic_only_when_the_policy_allows_it() {
    // The table's last row, and the one that depends on the policy: everything else about this update is unremarkable.
    let facts = routine(ChangeSize::Patch);

    assert_eq!(decide(UpdatePolicy::AutoAll, &facts), UpdateAction::Auto);
    assert_eq!(decide(UpdatePolicy::AutoMinor, &facts), UpdateAction::Auto);
    // ★ And the default is not automatic. A device that installs software while nobody is looking is a device whose owner
    // cannot say what is running on it, and the design only reaches "automatic" as its **last** row.
    assert_eq!(decide(UpdatePolicy::NotifyOnly, &facts), UpdateAction::Notify { blockers: Vec::new() });
    assert_eq!(UpdatePolicy::default(), UpdatePolicy::NotifyOnly);
}

#[test]
fn a_major_version_is_not_a_minor_policy_s_business() {
    let facts = routine(ChangeSize::Major);

    assert_eq!(decide(UpdatePolicy::AutoMinor, &facts), UpdateAction::Notify { blockers: Vec::new() });
    assert_eq!(decide(UpdatePolicy::AutoAll, &facts), UpdateAction::Auto);
}

#[test]
fn an_untrusted_publisher_is_reported_rather_than_asked_about() {
    // ★ The table's second row, and the difference between it and the two below: a device that has not been told to trust a
    // publisher is not being asked to approve anything. The answer is "no, and here is what happened".
    for trust in [
        PluginTrust::UnknownPublisher,
        PluginTrust::Unsigned,
        PluginTrust::Untrusted { why: Untrusted::Revoked { reason: "withdrawn".to_owned() } },
    ] {
        let facts = UpdateFacts::routine(trust.clone(), ChangeSize::Patch);
        let action = decide(UpdatePolicy::AutoAll, &facts);

        match action {
            UpdateAction::Notify { blockers } => {
                assert_eq!(blockers.len(), 1, "{trust:?}");
                assert_eq!(blockers[0].as_str(), "publisher-not-trusted");
                // And the trust is carried, because "a first plugin from a publisher you know" and "unsigned" are
                // different sentences and only one of them is worth acting on.
                assert!(
                    matches!(&blockers[0], UpdateBlocker::PublisherNotTrusted { trust: carried } if *carried == trust),
                    "{blockers:?}"
                );
            }
            other => panic!("an untrusted publisher is never automatic, got {other:?}"),
        }
    }
}

#[test]
fn a_new_permission_is_asked_about_even_when_the_policy_says_automatic() {
    // ★ The policy cannot consent on the user's behalf. `AutoAll` is a statement about versions, and this row is not about
    // a version at all.
    let mut facts = routine(ChangeSize::Patch);
    facts.added_capabilities = vec!["device:send:*".to_owned()];

    match decide(UpdatePolicy::AutoAll, &facts) {
        UpdateAction::Ask { blockers } => {
            assert_eq!(blockers.len(), 1);
            assert_eq!(blockers[0].as_str(), "needs-consent");
            // And the capability is named: "this update wants `device:send:*`" is a decision, "1 new permission" is not.
            assert!(
                matches!(&blockers[0], UpdateBlocker::NeedsConsent { added } if added == &["device:send:*"]),
                "{blockers:?}"
            );
        }
        other => panic!("a new permission is never automatic, got {other:?}"),
    }
}

#[test]
fn a_changed_publisher_key_is_asked_about_with_both_fingerprints() {
    let mut facts = routine(ChangeSize::Patch);
    facts.publisher_key_changed = Some((fingerprint("OLD"), fingerprint("NEW")));

    match decide(UpdatePolicy::AutoAll, &facts) {
        UpdateAction::Ask { blockers } => {
            assert_eq!(blockers[0].as_str(), "publisher-changed");
            assert!(
                matches!(
                    &blockers[0],
                    UpdateBlocker::PublisherChanged { from, to }
                        if *from == fingerprint("OLD") && *to == fingerprint("NEW")
                ),
                "{blockers:?}"
            );
        }
        other => panic!("a changed key is never automatic, got {other:?}"),
    }
}

#[test]
fn a_revoked_installed_version_is_forced_whatever_the_policy_says() {
    // ★ The table's fourth row, and the only outcome that is not a choice. A caller that treated this as routine would
    // leave a revoked version running when the download failed, which is the case the row exists for.
    let mut facts = routine(ChangeSize::Major);
    facts.installed_revoked = true;

    match decide(UpdatePolicy::NotifyOnly, &facts) {
        UpdateAction::Forced { why } => assert!(why.contains("revoked"), "{why}"),
        other => panic!("a revocation is not optional, got {other:?}"),
    }
    // And above the *other* blockers too: a revoked version whose update also wants a new permission is still forced,
    // because the alternative is not "ask" — it is "keep running something that was withdrawn".
    facts.added_capabilities = vec!["device:send:*".to_owned()];
    assert!(matches!(decide(UpdatePolicy::NotifyOnly, &facts), UpdateAction::Forced { .. }));
    assert!(matches!(decide(UpdatePolicy::AutoAll, &facts), UpdateAction::Forced { .. }));
}

#[test]
fn every_blocker_is_reported_rather_than_the_first_one() {
    // ★ The decision this module makes and the table does not state. These conditions hold at once in practice — an update
    // from an unknown publisher that also wants a new permission — and a caller that returned the first match would make
    // the user fix one thing, retry, and discover the next. Worse, it would hide the changed key behind a message about
    // permissions, which is the one a person is least equipped to notice unaided.
    let mut facts = UpdateFacts::routine(PluginTrust::UnknownPublisher, ChangeSize::Patch);
    facts.added_capabilities = vec!["storage:local:write".to_owned()];
    facts.publisher_key_changed = Some((fingerprint("OLD"), fingerprint("NEW")));

    let action = decide(UpdatePolicy::AutoAll, &facts);
    match action {
        // The untrusted publisher still wins the *action* — this is a notification, not a question.
        UpdateAction::Notify { blockers } => {
            let names: Vec<&str> = blockers.iter().map(UpdateBlocker::as_str).collect();
            assert_eq!(
                names,
                vec!["publisher-not-trusted", "publisher-changed", "needs-consent"],
                "all three, in the table's order"
            );
        }
        other => panic!("expected a notification, got {other:?}"),
    }
}

#[test]
fn a_trusted_publisher_with_two_other_reasons_is_a_question_with_two_reasons() {
    // The same list, without the informational one: now it *is* a decision, and both reasons are on it.
    let mut facts = routine(ChangeSize::Patch);
    facts.added_capabilities = vec!["storage:local:write".to_owned()];
    facts.publisher_key_changed = Some((fingerprint("OLD"), fingerprint("NEW")));

    match decide(UpdatePolicy::AutoAll, &facts) {
        UpdateAction::Ask { blockers } => {
            assert_eq!(blockers.len(), 2);
            assert!(blockers.iter().all(UpdateBlocker::needs_a_decision));
        }
        other => panic!("expected a question, got {other:?}"),
    }
}

#[test]
fn the_policy_s_names_are_the_ones_the_interface_uses() {
    // A stored setting is a string, so the spellings are part of the interface rather than an implementation detail. The
    // design's table says `AutoMinor`/`AutoAll`; the wire form is kebab-case like every other enum in this workspace.
    assert_eq!(UpdatePolicy::NotifyOnly.as_str(), "notify-only");
    assert_eq!(UpdatePolicy::AutoMinor.as_str(), "auto-minor");
    assert_eq!(UpdatePolicy::AutoAll.as_str(), "auto-all");
}

/// A fingerprint from a short label, so a test reads as the two keys rather than as two hashes.
///
/// A fingerprint is **sixteen hex digits** in groups of four, so this packs the label's own bytes into that shape. The value
/// is nonsense as a key and well-formed as a fingerprint, which is all these tests compare.
fn fingerprint(label: &str) -> Fingerprint {
    let hex: String = label.bytes().map(|byte| format!("{byte:02x}")).collect();
    let mut padded = hex;
    while padded.len() < 16 {
        padded.push('0');
    }
    let groups: Vec<String> = (0..4)
        .map(|index| padded[index * 4..index * 4 + 4].to_uppercase())
        .collect();
    Fingerprint::parse(&groups.join(" ")).expect("a fingerprint")
}
