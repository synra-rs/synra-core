use super::super::CallError;
use crate::test_host::Stub;
use super::{all_capabilities, budget, session};

#[test]
fn a_pure_session_refuses_the_calls_that_act() {
    // ★ The mechanism of the purity rule, which existed as a function nothing called.
    //
    // ★ **What this test does not cover, stated because it was nearly missed.** It builds the pure session by hand
    // with `HostCalls::pure()`, so it proves the refusal works and **not** that a `can-handle` pass is actually given
    // such a session. Removing the linker's `if !state.side_effects { calls = calls.pure() }` leaves this test green — a
    // second control confirmed that — because the path from `Work::CanHandle` to this refusal needs a compiled guest to
    // run at all. `work_carries_whether_it_may_act` covers the decision, and the store's own test covers the handover;
    // the two lines in `linker::run` that join them are the part no test reaches.
    //
    // `Work::allows_side_effects` answers `false` for `CanHandle` and `true` for everything else, and its doc says "the
    // host is what makes that true, by running it with a context whose action-shaped calls are refused". **No such
    // context existed.** A plugin's `can-handle` could send a message, open a browser, write storage or fetch a URL —
    // for every share the router asked about, before the user had chosen anything, and again for every share they then
    // cancelled.
    let host = Stub::with_devices(&[("device-a", "Laptop", "desktop")]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit).pure();

    // Every action-shaped call is refused, and the code says why: the plugin holds the capability, so
    // `capabilityDenied` would send a user to grant something they already granted.
    for (import, argument) in [
        (
            "event-emit",
            r#"{"event":"_plugin.@acme/chat.something","payload":"{}"}"#,
        ),
        (
            "device-send",
            r#"{"target":"00000000-0000-4000-8000-000000000001","event":"_plugin.@acme/chat.something","payload":"{}"}"#,
        ),
        ("storage-set", r#"{"key":"k","value":"v"}"#),
        ("secret-set", r#"{"key":"k","value":"v"}"#),
        ("platform-open-url", "https://example"),
        ("platform-notify", r#"{"title":"t","body":"b"}"#),
        ("action-invoke", r#"{"plugin":"@acme/other","name":"greet","args":"{}"}"#),
    ] {
        let refused = calls
            .call(&format!("synra:plugin/host#{import}"), argument)
            .expect_err("a matching pass may not call something that acts");

        assert_eq!(refused.code, CallError::SIDE_EFFECT_NOT_ALLOWED, "{import}");
        // ★ The message names the reason, because the code alone does not tell an author what to do. "Side effect not
        // allowed" during a matching pass means "move this call into `share.execute`", and saying so is the difference
        // between a fixable refusal and a mysterious one.
        assert!(refused.message.contains("can-handle"), "{import}: {}", refused.message);
    }
}

#[test]
fn a_matching_pass_may_still_read_and_log() {
    // ★ The other half, and the reason the list is drawn where it is.
    //
    // A matching pass that refused `storage-get` would break every plugin that looks up its own settings before answering,
    // and one that refused `log` would take away the only way a plugin author can find out why their matcher said no.
    // Neither changes anything outside the plugin, so neither is a side effect.
    let host = Stub::with_devices(&[("device-a", "Laptop", "desktop")]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit).pure();

    for (import, argument) in [
        ("log", r#"{"level":"info","message":"considering"}"#),
        ("env-locale", ""),
        ("env-can", "log:info"),
        ("storage-get", "known"),
        ("storage-keys", "pre"),
        ("secret-get", "token"),
        ("device-list", ""),
    ] {
        let answer = calls.call(&format!("synra:plugin/host#{import}"), argument);
        // ★ Asserted as "not refused for purity" rather than "succeeded". A read can fail for its own reasons — the stub
        // holds no secret, so `secret-get` answers `notFound` — and a test that demanded success would be asserting
        // about the fixture rather than about the rule.
        let refused_for_purity = answer
            .as_ref()
            .err()
            .is_some_and(|error| error.code == CallError::SIDE_EFFECT_NOT_ALLOWED);
        assert!(!refused_for_purity, "{import} reads, so it is allowed: {answer:?}");
    }
}
