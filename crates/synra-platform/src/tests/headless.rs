use std::path::Path;
use super::super::actions::{PlatformAction, Policies};
use super::super::error::{PathRefusal, PlatformError, UrlRefusal};
use super::super::host::HeadlessPlatform;
use super::absolute;
use super::super::host::Platform as _;

#[test]
fn a_headless_host_performs_nothing() {
    // Every action reports `Unsupported` rather than pretending to succeed, so a caller that forgot to provide
    // a real implementation finds out immediately.
    let host = HeadlessPlatform::new();
    assert_eq!(host.name(), "headless");
    assert!(matches!(host.open_url("https://example.com"), Err(PlatformError::Unsupported(_))));
    assert!(matches!(host.read_clipboard(), Err(PlatformError::Unsupported(_))));
    assert!(matches!(host.write_clipboard("x"), Err(PlatformError::Unsupported(_))));
    assert!(matches!(host.notify("t", "b"), Err(PlatformError::Unsupported(_))));
    // Key simulation is refused for a second reason before the host is consulted: it is off by default, and
    // that refusal is about the policy rather than about the host having no keyboard.
    assert!(matches!(
        host.simulate_keys("cmd+c"),
        Err(PlatformError::SimulateKeysNotGranted)
    ));
    // With the policy in place it reaches the host, which then refuses.
    let granted = HeadlessPlatform::with_policies(Policies::new().with_simulate_keys(true));
    assert!(matches!(
        granted.simulate_keys("cmd+c"),
        Err(PlatformError::Unsupported(_))
    ));
    assert!(host.supported_actions().is_empty());
}

#[test]
fn a_headless_host_still_reports_a_bad_address() {
    // The order matters: a plugin that supplied `javascript:` should be told its address is refused, not that
    // this host has no browser. The first is a mistake the author can fix and the second is a fact about the
    // installation.
    let host = HeadlessPlatform::new();
    match host.open_url("javascript:alert(1)") {
        Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::LocalScheme),
        other => panic!("expected a URL refusal, got {other:?}"),
    }
    match host.open_url("http://example.com") {
        Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::Insecure),
        other => panic!("expected an insecure refusal, got {other:?}"),
    }
}

#[test]
fn a_headless_host_uses_the_policies_it_was_given() {
    let host = HeadlessPlatform::with_policies(Policies::new().with_insecure_urls(true));
    assert!(host.policies().allows_insecure_urls());
    // Still unsupported, but the address check passed, so the error is about the host.
    assert!(matches!(host.open_url("http://example.com"), Err(PlatformError::Unsupported(_))));
}

#[test]
fn the_headless_host_checks_paths_before_refusing() {
    let host = HeadlessPlatform::new();
    // A relative path is refused for being relative, not for the host being headless.
    match host.open_path(Path::new("report.pdf")) {
        Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::NotAbsolute),
        other => panic!("expected a path refusal, got {other:?}"),
    }
    // And an absolute document reaches the host, which then refuses. The path is bound rather than passed as a
    // temporary, because `as_path` borrows it.
    let document = absolute("report.pdf");
    match host.open_path(document.as_path()) {
        Err(PlatformError::Unsupported(_)) => {}
        other => panic!("expected the host to refuse {document:?}, got {other:?}"),
    }
}

#[test]
fn platform_errors_explain_themselves() {
    let errors = vec![
        PlatformError::BadUrl { url: "u".to_owned(), reason: UrlRefusal::Insecure },
        PlatformError::BadPath { path: "p".to_owned(), reason: PathRefusal::Executable },
        PlatformError::SimulateKeysNotGranted,
        PlatformError::NoRecentInteraction { elapsed_ms: 5_000 },
        PlatformError::RateLimited { action: PlatformAction::Notify, remaining_ms: 10 },
        PlatformError::QuotaExceeded { action: PlatformAction::Notify, used: 3, limit: 3 },
        PlatformError::TooLong { field: "f", len: 1, max: 0 },
        PlatformError::Unavailable("do a thing"),
        PlatformError::Unsupported("do a thing"),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text:?}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
