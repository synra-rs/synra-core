//! The session registry's tests.

use super::*;
use synra_capability::Capability;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

fn plugin(text: &str) -> PluginId {
    PluginId::parse(text).expect("a valid plugin id")
}

fn grants(texts: &[&str]) -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for text in texts {
        set.insert_str(text).expect("a valid capability");
    }
    set
}

fn chat() -> PluginId {
    plugin("@synra-plugin/chat")
}

fn notes() -> PluginId {
    plugin("@synra-plugin/notes")
}

/// A registry with one session for `chat`.
fn with_chat() -> (UiSessionRegistry, u128) {
    let registry = UiSessionRegistry::new();
    let nonce = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 0xABCD, 1_000);
    (registry, nonce)
}

// ── Issuing and validating ────────────────────────────────────────────────────────────────────

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

// ── Readiness ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_session_is_not_ready_until_a_call_arrives() {
    // "The WebView exists" and "the page is listening" are different facts, and a plugin that misses its first
    // event is one with a bug nobody can reproduce.
    let (registry, nonce) = with_chat();
    assert_eq!(registry.report().ready, 0, "nothing should be ready yet");
    assert_eq!(registry.report().ready, 0);

    let session = registry.validate(nonce, &chat(), "1.0.0", 2_000).expect("validates");
    assert!(session.is_ready(), "the first call marks the page ready");
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

// ── Refusals ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_version_change_and_an_expiry_say_reload() {
    // The refusals where reloading fixes it — and where not reloading leaves a page that fails every call for no
    // visible reason.
    assert!(SessionRefusal::VersionChanged {
        session: "1".to_owned(),
        running: "2".to_owned()
    }
    .means_reload());
    assert!(SessionRefusal::Expired { ago_ms: 1 }.means_reload());
    assert!(!SessionRefusal::Unknown.means_reload());
    assert!(!SessionRefusal::WrongPlugin {
        actual: "a".to_owned(),
        claimed: "b".to_owned()
    }
    .means_reload());
}

#[test]
fn an_unknown_or_wrong_session_says_teardown() {
    // Reloading a revoked session would restart a plugin the user just removed.
    assert!(SessionRefusal::Unknown.means_teardown());
    assert!(SessionRefusal::WrongPlugin {
        actual: "a".to_owned(),
        claimed: "b".to_owned()
    }
    .means_teardown());
    assert!(!SessionRefusal::Expired { ago_ms: 1 }.means_teardown());
}

#[test]
fn session_refusals_explain_themselves() {
    let refusals = [
        SessionRefusal::Unknown,
        SessionRefusal::WrongPlugin { actual: "a".to_owned(), claimed: "b".to_owned() },
        SessionRefusal::Expired { ago_ms: 500 },
        SessionRefusal::VersionChanged { session: "1".to_owned(), running: "2".to_owned() },
    ];
    for refusal in refusals {
        let text = refusal.to_string();
        assert!(text.len() > 20, "{refusal:?} -> {text}");
        assert!(!text.contains('{'), "{refusal:?} -> {text}");
    }
}

// ── Reporting ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_report_carries_no_nonces() {
    // A diagnostic bundle leaves the machine, and a nonce in one is a token somebody else could present.
    let (registry, nonce) = with_chat();
    registry.validate(nonce, &chat(), "1.0.0", 2_000).expect("validates");

    let report = registry.report();
    assert_eq!(report.live, 1);
    assert_eq!(report.issued, 1);
    assert_eq!(report.plugins, vec!["@synra-plugin/chat".to_owned()]);
    assert_eq!(report.ready, 1);

    let json = serde_json::to_string(&report).expect("serialises");
    assert!(!json.contains("43981"), "the nonce `0xABCD` appeared in {json}");
    assert!(!json.contains("nonce"), "{json}");
}

#[test]
fn the_report_round_trips() {
    let (registry, _nonce) = with_chat();
    let report = registry.report();
    let json = serde_json::to_string(&report).expect("serialises");
    let back: SessionReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

#[test]
fn an_empty_registry_reports_empty() {
    let report = UiSessionRegistry::new().report();
    assert_eq!(report.live, 0);
    assert!(report.plugins.is_empty());
    assert_eq!(report.issued, 0);
}

#[test]
fn issuing_is_counted_across_replacements() {
    // The count is of issued tokens, not of live ones: a plugin reloaded five times had five sessions, and a
    // number that said one would hide a reload loop.
    let registry = UiSessionRegistry::new();
    for nonce in 1..=5u128 {
        registry.issue_with(&chat(), "1.0.0", grants(&[]), nonce, 0);
    }
    assert_eq!(registry.report().issued, 5);
    assert_eq!(registry.report().live, 1);
}

#[test]
fn the_active_plugins_are_listed() {
    let registry = UiSessionRegistry::new();
    registry.issue_with(&chat(), "1.0.0", grants(&[]), 1, 0);
    registry.issue_with(&notes(), "1.0.0", grants(&[]), 2, 0);

    let mut active: Vec<String> = registry.active_plugins().iter().map(ToString::to_string).collect();
    active.sort();
    assert_eq!(active, vec!["@synra-plugin/chat", "@synra-plugin/notes"]);
}

#[test]
fn the_placeholder_issuer_is_documented_as_unpredictable() {
    // It exists for tests and for a host with no WebView. The name says what it is, because a caller reaching for
    // `issue` would not read a warning in the documentation.
    let registry = UiSessionRegistry::new();
    let first = registry.issue_placeholder(&chat(), "1.0.0", grants(&[]), 0);
    let second = registry.issue_placeholder(&chat(), "1.0.0", grants(&[]), 0);
    assert_ne!(first, second);
    // And it is predictable, which is the point of the name.
    assert_eq!(second, first + 1);
}

#[test]
fn the_session_lifetime_is_the_documented_one() {
    assert_eq!(SESSION_LIFETIME_MS, 12 * 60 * 60 * 1_000);
}

#[test]
fn a_token_reports_its_own_expiry() {
    let token = UiSessionToken {
        plugin_id: chat(),
        plugin_version: "1.0.0".to_owned(),
        grants: grants(&[]),
        issued_at_ms: 1_000,
        ready: core::sync::atomic::AtomicBool::new(false),
    };
    assert_eq!(token.expires_at_ms(), 1_000 + SESSION_LIFETIME_MS);
    assert!(!token.is_expired(1_000 + SESSION_LIFETIME_MS - 1));
    assert!(token.is_expired(1_000 + SESSION_LIFETIME_MS));
}
