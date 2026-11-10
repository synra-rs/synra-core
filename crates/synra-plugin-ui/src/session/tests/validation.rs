use super::*;

#[test]
fn a_valid_session_admits_a_call() {
    let (registry, nonce) = with_chat();
    let session = registry
        .validate(nonce, &chat(), "1.0.0", 2_000)
        .expect("validates");
    assert_eq!(session.plugin_id(), &chat());
    assert_eq!(session.nonce, nonce);
    assert!(session.grants().contains(&Capability::parse("log:*").expect("valid")));
}

#[test]
fn an_unknown_nonce_is_refused_without_saying_why() {
    // "You were deactivated" and "that token never existed" must give the same answer, or a plugin could probe for
    // which plugins are installed by presenting guessed nonces and reading the difference.
    let registry = UiSessionRegistry::new();
    assert_eq!(
        registry.validate(0xDEAD, &chat(), "1.0.0", 0).map(|_| ()),
        Err(SessionRefusal::Unknown)
    );

    let (registry, nonce) = with_chat();
    registry.revoke(nonce);
    assert_eq!(
        registry.validate(nonce, &chat(), "1.0.0", 2_000).map(|_| ()),
        Err(SessionRefusal::Unknown),
        "a revoked session must be indistinguishable from one that never existed"
    );
}

#[test]
fn a_session_cannot_be_used_by_another_plugin() {
    // The attack the whole design is about: a plugin holding a valid token making calls as its owner.
    let (registry, nonce) = with_chat();
    match registry.validate(nonce, &notes(), "1.0.0", 2_000) {
        Err(SessionRefusal::WrongPlugin { actual, claimed }) => {
            assert_eq!(actual, "@synra-plugin/chat");
            assert_eq!(claimed, "@synra-plugin/notes");
        }
        other => panic!("expected a wrong-plugin refusal, got {other:?}"),
    }
}

#[test]
fn a_valid_nonce_is_not_enough_on_its_own() {
    // Stated separately because it is the property, and a test that only checked the happy path would pass against
    // an implementation that ignored the claimed plugin entirely.
    let (registry, nonce) = with_chat();
    assert!(registry.validate(nonce, &chat(), "1.0.0", 2_000).is_ok());
    assert!(registry.validate(nonce, &notes(), "1.0.0", 2_000).is_err());
}

#[test]
fn an_expired_session_is_refused_and_says_how_long_ago() {
    let (registry, nonce) = with_chat();
    let expired_at = 1_000 + SESSION_LIFETIME_MS;
    match registry.validate(nonce, &chat(), "1.0.0", expired_at + 500) {
        Err(SessionRefusal::Expired { ago_ms }) => assert_eq!(ago_ms, 500),
        other => panic!("expected an expiry, got {other:?}"),
    }
    // At the instant it expires it is expired, not one millisecond later.
    assert!(registry.validate(nonce, &chat(), "1.0.0", expired_at).is_err());
    assert!(registry.validate(nonce, &chat(), "1.0.0", expired_at - 1).is_ok());
}

#[test]
fn a_version_change_is_refused() {
    // An update replaces the artifact under a live page. Continuing would run the new code with the old grants and
    // against the old artifact.
    let (registry, nonce) = with_chat();
    match registry.validate(nonce, &chat(), "1.1.0", 2_000) {
        Err(SessionRefusal::VersionChanged { session, running }) => {
            assert_eq!(session, "1.0.0");
            assert_eq!(running, "1.1.0");
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
}

#[test]
fn the_grants_are_the_ones_frozen_at_activation() {
    // A permission change that took effect halfway through an operation is worse than one that waits for a
    // reload — which is why the session holds a snapshot rather than consulting the live grants.
    let registry = UiSessionRegistry::new();
    let nonce = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 7, 0);

    let session = registry.validate(nonce, &chat(), "1.0.0", 1).expect("validates");
    assert!(session.grants().contains(&Capability::parse("log:*").expect("valid")));
    assert!(!session.grants().contains(&Capability::parse("storage:local:read").expect("valid")));
}
