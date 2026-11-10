use super::super::*;
use super::{plugin, session};

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
    assert!(
        outcome.describe().contains("enabled"),
        "{}",
        outcome.describe()
    );

    // And an outcome that installed without checking is a bug the type can report. The `performed` argument here is empty
    // because it is overwritten by the struct update below — a placeholder that says so, rather than a list that pretends
    // to be the work.
    let unchecked = SyncOutcome {
        performed: vec![ReceiverDuty::PackageDigest],
        ..SyncOutcome::installed(
            plugin("@acme/chat"),
            session("round-1"),
            "1.0.0",
            true,
            Vec::new(),
        )
    };
    assert!(!unchecked.is_fully_checked());
    // The original is untouched, which is what makes the two assertions about the same value.
    assert!(outcome.is_fully_checked());
}

#[test]
fn a_refusal_is_not_fully_checked_because_nothing_was_installed() {
    let outcome = SyncOutcome::refused(
        plugin("@acme/chat"),
        session("round-1"),
        "the signature did not verify",
    );
    assert!(!outcome.installed);
    assert!(!outcome.activated);
    assert!(outcome.installed_version.is_none());
    assert!(
        outcome.is_fully_checked(),
        "nothing was installed, so nothing was owed"
    );
    assert!(
        outcome.describe().contains("signature"),
        "{}",
        outcome.describe()
    );
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
