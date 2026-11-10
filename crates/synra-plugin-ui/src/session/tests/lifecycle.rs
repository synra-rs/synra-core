use super::*;

#[test]
fn validation_does_not_mark_a_document_ready() {
    // "The WebView exists" and "the page is listening" are different facts, and a plugin that misses its first
    // event is one with a bug nobody can reproduce.
    let (registry, nonce) = with_chat();
    assert_eq!(registry.report().ready, 0, "nothing should be ready yet");
    assert_eq!(registry.report().ready, 0);

    let session = registry
        .validate(nonce, &chat(), "1.0.0", 2_000)
        .expect("validates");
    assert!(
        !session.is_ready(),
        "authority inspection does not prove listeners are installed"
    );
    assert_eq!(registry.report().ready, 0);
    session.token().mark_ready();
    assert!(session.is_ready());
    assert_eq!(registry.report().ready, 1);
}

// ── Revoking ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn revoking_stops_every_later_call() {
    // The kernel cannot reach into a WebView and stop it, so the token is the only lever.
    let (registry, nonce) = with_chat();
    assert!(registry.validate(nonce, &chat(), "1.0.0", 1).is_ok());

    assert!(registry.revoke(nonce));
    assert!(registry.validate(nonce, &chat(), "1.0.0", 2).is_err());
    assert!(registry.is_empty());
}

#[test]
fn revoking_something_that_is_not_there_is_not_an_error() {
    // A plugin deactivated twice, or one that never had a page. Reporting it as a failure would make a caller
    // handle a case that is not a problem.
    let registry = UiSessionRegistry::new();
    assert!(!registry.revoke(0));
    let (registry, nonce) = with_chat();
    assert!(registry.revoke(nonce));
    assert!(!registry.revoke(nonce));
}

#[test]
fn every_session_of_a_plugin_can_be_revoked_by_id() {
    // A caller on deactivation knows the plugin and not the nonce.
    let registry = UiSessionRegistry::new();
    registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 1, 0);
    registry.issue_with(&notes(), "1.0.0", grants(&["log:*"]), 2, 0);

    assert_eq!(registry.revoke_plugin(&chat()), 1);
    assert_eq!(registry.len(), 1);
    assert!(registry.revoke_plugin(&chat()) == 0, "nothing left to revoke");
}

#[test]
fn issuing_again_replaces_the_plugins_previous_session() {
    // A plugin has one page, so a second session for it is a page that was replaced — and leaving the old token
    // live would leave the old page able to call.
    let registry = UiSessionRegistry::new();
    let first = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 1, 0);
    let second = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 2, 0);

    assert_eq!(registry.len(), 1, "the old session was not dropped");
    assert!(registry.validate(first, &chat(), "1.0.0", 1).is_err(), "the old token still works");
    assert!(registry.validate(second, &chat(), "1.0.0", 1).is_ok());
}

#[test]
fn replacing_one_plugins_session_leaves_another_alone() {
    // The retain is by plugin, so a reload of one plugin must not sweep another's session.
    let registry = UiSessionRegistry::new();
    let notes_nonce = registry.issue_with(&notes(), "1.0.0", grants(&["log:*"]), 1, 0);
    registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 2, 0);
    registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 3, 0);

    assert_eq!(registry.len(), 2);
    assert!(registry.validate(notes_nonce, &notes(), "1.0.0", 1).is_ok());
}

#[test]
fn revoking_everything_is_for_a_shutdown() {
    let registry = UiSessionRegistry::new();
    registry.issue_with(&chat(), "1.0.0", grants(&[]), 1, 0);
    registry.issue_with(&notes(), "1.0.0", grants(&[]), 2, 0);
    registry.revoke_all();
    assert!(registry.is_empty());
}

// ── Sweeping ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_expired_session_is_swept() {
    // Nothing else notices an expiry: until the sweep, the session holds a grants snapshot and an entry.
    let registry = UiSessionRegistry::new();
    let old = registry.issue_with(&chat(), "1.0.0", grants(&[]), 1, 0);
    let fresh = registry.issue_with(
        &notes(),
        "1.0.0",
        grants(&[]),
        2,
        SESSION_LIFETIME_MS - 1,
    );

    assert_eq!(registry.sweep_expired(SESSION_LIFETIME_MS), 1, "the old one should be swept");
    assert_eq!(registry.len(), 1);
    assert!(registry.validate(old, &chat(), "1.0.0", SESSION_LIFETIME_MS).is_err());
    // The fresh one was issued one millisecond before the sweep instant, so it survives.
    assert!(registry
        .validate(fresh, &notes(), "1.0.0", SESSION_LIFETIME_MS)
        .is_ok());
}

#[test]
fn sweeping_nothing_reports_nothing() {
    let registry = UiSessionRegistry::new();
    assert_eq!(registry.sweep_expired(u64::MAX), 0);
}
