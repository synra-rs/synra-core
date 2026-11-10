use super::*;

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
    registry
        .validate(nonce, &chat(), "1.0.0", 2_000)
        .expect("validates")
        .token()
        .mark_ready();

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
