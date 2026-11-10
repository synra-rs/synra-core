use super::super::HostError;
use super::{A, host};

#[test]
fn a_rename_reaches_the_name_that_goes_into_a_handshake() {
    let (mut host, _db) = host(A, "Old name");
    host.rename_self("Kitchen tablet").expect("a rename");

    // Both copies, because the fault this method exists to prevent is one copy being updated and the other not — and
    // asserting on only the visible one is how that fault gets reintroduced.
    assert_eq!(
        host.identity().display_name,
        "Kitchen tablet",
        "the stored identity"
    );
    assert_eq!(
        host.announced_name(),
        "Kitchen tablet",
        "the announced name"
    );
}

#[test]
fn a_refused_rename_leaves_both_copies_untouched() {
    let (mut host, _db) = host(A, "Old name");
    let error = host.rename_self("   ").expect_err("a blank name");
    assert!(matches!(error, HostError::Unnameable { .. }));
    assert_eq!(
        host.identity().display_name,
        "Old name",
        "the stored identity"
    );
    assert_eq!(host.announced_name(), "Old name", "the announced name");
}

#[test]
fn a_name_the_kernel_refuses_changes_nothing() {
    // ★ Refused by `check_display_name`, not by a rule of this module's own.
    //
    // The host and the identity must agree on what a name is; a host with its own stricter rule would accept a rename
    // the identity refuses, or the reverse, and the two copies would then disagree — which is the fault `rename_self`
    // exists to remove. So the cases below are the kernel's cases, not this test's.
    let (mut host, _db) = host(A, "Old name");
    let too_long = "a".repeat(crate::identity::MAX_DISPLAY_NAME_LEN + 1);
    for name in ["", "   ", &too_long, "with\nnewline"] {
        assert!(host.rename_self(name).is_err(), "{name:?} is not a name");
    }
    assert_eq!(
        host.announced_name(),
        "Old name",
        "nothing was half-applied"
    );
}

#[test]
fn a_padded_name_lands_in_both_copies_trimmed_and_identically() {
    // ★ The trim, checked on both copies.
    //
    // `check_display_name` trims before it validates, so `" padded "` is a name whose checked form is `"padded"`.
    // `Identity::rename` stores the checked form; if `rename_self` stored what it was handed, the host would announce
    // `" padded "` and the identity would report `"padded"` — two devices disagreeing about this one's name, which is
    // the fault this method exists to prevent.
    let (mut host, _db) = host(A, "Old name");
    host.rename_self(" padded ")
        .expect("a name of padding is a name");
    assert_eq!(
        host.announced_name(),
        "padded",
        "the announced name is the checked one"
    );
    assert_eq!(
        host.identity().display_name,
        "padded",
        "and so is the stored one"
    );
}

#[test]
fn the_refusal_echoes_only_enough_of_the_name_to_recognise_it() {
    // A user can paste four hundred characters of emoji; a log line that carries all of it is a problem of its own.
    let long = "🎉".repeat(400);
    let error = host(A, "Old name")
        .0
        .rename_self(&long)
        .expect_err("not a name");
    let echoed = match error {
        HostError::Unnameable { name } => name,
        other => panic!("expected a refusal, got {other}"),
    };
    assert!(
        echoed.chars().count() <= 24,
        "the echo is {} characters, not a bounded prefix",
        echoed.chars().count()
    );
}
