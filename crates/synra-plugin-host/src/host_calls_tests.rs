//! The host calls, driven from both sides: what the contract says, and what a plugin gets for asking.
//!
//! The stub host records everything, so a test can assert both the answer and the *effect* — which is what makes the
//! gate rules testable: a refusal that still reached the host would be a refusal that did nothing.

use synra_capability::CapabilitySet;
use synra_observe::audit::AuditOutcome;
use synra_protocol::ids::PluginId;
use synra_store::sqlite::now_ms;


use crate::host_surface::{CAPABILITIES, is_declared_capability, provides};
use crate::host_surface::provided;

use super::*;
use crate::quota::RateKind;
use crate::quota::Quota;
use crate::test_host::Stub;

/// A session with a generous budget and the given grants.
fn session<'a>(
    host: &'a Stub,
    grants: &'a CapabilitySet,
    budget: &'a Budget,
    audit: &'a mut Vec<AuditEntry>,
) -> HostCalls<'a> {
    HostCalls::new(host, plugin(), grants, budget, audit)
}

fn plugin() -> PluginId {
    PluginId::parse("@acme/chat").expect("a plugin id")
}

fn budget() -> Budget {
    Budget::new(Quota::default())
}

/// Every capability the contract mentions, so a test can grant exactly one and see what it reaches.
fn all_capabilities() -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for capability in CAPABILITIES {
        let _ = set.insert_str(capability);
    }
    set
}

fn granted(capabilities: &[&str]) -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for capability in capabilities {
        let _ = set.insert_str(capability);
    }
    set
}

// ── The table and the host are the same surface ───────────────────────────────────────────────────

#[test]
fn every_function_in_the_contract_reaches_the_host_rather_than_an_unknown_function_refusal() {
    // ★ The test that keeps the host and the contract the same size. The generated table has one entry per WIT
    // function, and this drives every one of them: a function the table lists and `run` does not handle answers
    // `unknownFunction`, which is the failure that would otherwise reach a plugin author as their own mistake.
    let host = Stub::with_devices(&[("device-a", "Laptop", "desktop")]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    // A map here and not in the crate: the *test* wants a lookup by function name, and nothing in the host's own
    // signature should name a standard container — which is why `implemented` answers with pairs.
    let arguments = std::collections::BTreeMap::from([
        ("log", r#"{"level":"info","message":"hello"}"#),
        (
            "event-emit",
            r#"{"event":"_plugin.@acme/chat.something","payload":"{}"}"#,
        ),
        ("event-subscribe", "a.*"),
        (
            "device-send",
            r#"{"target":"00000000-0000-4000-8000-000000000001","event":"_plugin.@acme/chat.something","payload":"{}"}"#,
        ),
        (
            "device-broadcast",
            r#"{"event":"_plugin.@acme/chat.something","payload":"{}"}"#,
        ),
        ("storage-get", "known"),
        ("storage-set", r#"{"key":"k","value":"v"}"#),
        ("storage-delete", "k"),
        ("storage-keys", "pre"),
        ("secret-get", "token"),
        ("secret-set", r#"{"key":"token","value":"s"}"#),
        ("secret-delete", "token"),
        ("network-fetch", r#"{"url":"https://example"}"#),
        ("network-websocket", "wss://example"),
        ("transfer-send", r#"{"target":"device-a","event":"file","payload":"{}"}"#),
        ("transfer-status", "transfer-1"),
        ("platform-open-url", "https://example"),
        ("platform-open-path", "/tmp/a"),
        ("platform-reveal-path", "/tmp/a"),
        ("platform-simulate-keys", "ctrl+s"),
        ("platform-notify", r#"{"title":"t","body":"b"}"#),
        ("platform-read-clipboard", ""),
        ("platform-write-clipboard", "text"),
        ("action-declare", r#"{"name":"greet","schema":"{}"}"#),
        ("action-invoke", r#"{"plugin":"@acme/other","name":"greet","args":"{}"}"#),
    ]);

    let mut refusals: Vec<(String, &'static str)> = Vec::new();
    for import in provided() {
        let function = import.rsplit_once('#').map_or(import, |(_, name)| name);
        let argument = arguments.get(function).copied().unwrap_or("");
        if let Err(error) = calls.call(import, argument) {
            refusals.push((function.to_owned(), error.code));
        }
    }

    // The deliberate refusals: this host has no callback table, so it cannot deliver events to a plugin; it has no
    // WebSocket; and the stub holds no secret — which is `notFound` rather than a failure, because an absent secret is an
    // ordinary answer.
    assert_eq!(
        refusals,
        vec![
            ("event-subscribe".to_owned(), CallError::NOT_IMPLEMENTED),
            ("network-websocket".to_owned(), CallError::HOST_FAILED),
            ("secret-get".to_owned(), "notFound"),
        ]
    );
}

#[test]
fn subscribing_to_events_is_refused_rather_than_reported_as_recorded() {
    // ★ This call used to answer `Ok("")` — success — with a comment saying "what this answers is that the pattern was
    // recorded". **Nothing was recorded**: there is no callback table, and the design's own answer is a guest-export
    // callback table, which is a contract change rather than a line here.
    //
    // The failure a plugin could not detect is the point. A subscriber that never receives an event cannot tell "nothing
    // has happened yet" from "this host delivers nothing", so a plugin would ship a feature that silently does nothing
    // and its author would have no way to find out.
    let host = Stub::with_devices(&[]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let refused = calls
        .call("synra:plugin/host#event-subscribe", "a.*")
        .expect_err("a subscription that cannot be kept is not a success");

    assert_eq!(refused.code, CallError::NOT_IMPLEMENTED);
    // And the audit says the honest thing: the capability was **held** — the gate let the call through — and the
    // operation itself failed. `Denied` would say the user had not granted it, which would send them looking for a
    // permission they already gave.
    assert!(
        audit
            .iter()
            .any(|entry| entry.outcome == AuditOutcome::Failed),
        "a call the gate allowed and the host could not do is recorded as failed: {audit:?}"
    );
    assert!(
        !audit.iter().any(|entry| entry.outcome == AuditOutcome::Denied),
        "nothing was denied: {audit:?}"
    );
}

#[test]
fn work_carries_whether_it_may_act() {
    // ★ The decision the store is given per call.
    //
    // `allows_side_effects` is a one-line match, and it is the whole of the policy: `can-handle` runs for every plugin
    // before a user has chosen, so it may not act; every other entry point is a thing the user or the kernel asked for.
    // Asserted per entry point rather than as "not CanHandle", so a new `Work` variant has to be considered here.
    use crate::Work;

    assert!(!Work::CanHandle { item_json: "{}".to_owned() }.allows_side_effects());
    for work in [
        Work::Deactivate,
        Work::Activate { config_json: "{}".to_owned() },
        Work::Tick { tick_json: "{}".to_owned() },
        Work::Execute { action: "open".to_owned(), args_json: "{}".to_owned() },
        Work::Migrate { from_version: "1".to_owned(), to_version: "2".to_owned() },
        Work::InvokeAction { name: "greet".to_owned(), args_json: "{}".to_owned() },
    ] {
        assert!(work.allows_side_effects(), "{work:?} is something somebody asked for");
    }
}

#[test]
fn every_action_shaped_name_is_one_the_contract_declares() {
    // ★ What keeps a hand-written list honest.
    //
    // `ACTION_SHAPED` is a judgement about what each function *does* rather than a property the generated gate table
    // records, so it cannot be derived. What it can be is checked: a name here that the contract does not declare is a
    // typo that silently protects nothing, and a function the contract declares and this list does not mention is one
    // nobody decided about.
    //
    // ★ This is the weaker half on purpose — it cannot know that `platform-notify` acts. What it stops is the list
    // rotting: a renamed function, or a new one added to the WIT file and not considered.
    let declared: Vec<&str> = provided()
        .iter()
        .map(|import| import.rsplit_once('#').map_or(*import, |(_, name)| name))
        .collect();

    for name in HostCalls::ACTION_SHAPED {
        assert!(
            declared.contains(name),
            "`{name}` is listed as action-shaped but the contract does not declare it"
        );
    }
    // And every declared function is either in the list or has been looked at: the ones deliberately absent are named
    // here, so adding a function to the contract and not to either list fails this test.
    const NOT_ACTION_SHAPED: &[&str] = &[
        "env-sdk-version", "env-host-kind", "env-locale", "env-dark-mode", "env-can",
        "platform-capabilities", "plugin-id", "log", "event-subscribe", "device-list",
        "storage-get", "storage-keys", "storage-quota", "secret-get", "transfer-status",
        "platform-read-clipboard", "action-list",
    ];
    for name in &declared {
        assert!(
            HostCalls::ACTION_SHAPED.contains(name)
                || NOT_ACTION_SHAPED.contains(name),
            "`{name}` is declared and nobody decided whether it acts"
        );
    }
}

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

#[test]
fn a_plugin_cannot_emit_an_event_in_another_plugins_namespace() {
    // ★ One plugin speaking as another.
    //
    // `EventName::check_emittable_by` was written, tested and documented as the enforcement point — its own doc says
    // "The host calls this on every outbound plugin event. It is the difference between 'plugins have their own
    // namespace' being true and it being a sentence in a document" — and **the host did not call it**. Every call site
    // was in its own test module, so a plugin could emit `_plugin.@acme/notes.something` and every subscriber would believe it
    // came from `notes`.
    let host = Stub::with_devices(&[]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let refused = calls
        .call(
            "synra:plugin/host#event-emit",
            r#"{"event":"_plugin.@acme/notes.something","payload":"{}"}"#,
        )
        .expect_err("another plugin's namespace is not this plugin's to use");

    assert_eq!(refused.code, CallError::CAPABILITY_DENIED);
    // The message names whose namespace it is, because "denied" alone does not tell an author what to change.
    assert!(refused.message.contains("notes"), "{}", refused.message);
}

#[test]
fn a_plugin_cannot_emit_a_host_event() {
    // ★ The other half, and the more dangerous one: a plugin telling the kernel, and every other plugin, that
    // something happened that did not. `_synra.device.changed` is the kernel's own statement about the device list.
    let host = Stub::with_devices(&[]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    for event in ["_synra.device.changed", "device.hello", "synra.internal.anything"] {
        let refused = calls
            .call(
                "synra:plugin/host#event-emit",
                &format!(r#"{{"event":"{event}","payload":"{{}}"}}"#),
            )
            .expect_err("a host event is not a plugin's to emit");

        assert_eq!(refused.code, CallError::CAPABILITY_DENIED, "{event}");
        // And it names the event, so an author reading the refusal knows which call to change rather than guessing
        // among the several an event-emitting plugin makes.
        assert!(refused.message.contains(event), "{}", refused.message);
        // ★ The capability is not the reason, and the message must not suggest it is: the plugin holds
        // `event:emit:*`, which is what let this call reach the check at all. What it lacks is a namespace, and
        // sending an author to look for a permission they already have is the failure this distinction avoids.
        assert!(
            !refused.message.contains("capability") && !refused.message.contains("permission"),
            "{}",
            refused.message
        );
    }
}

#[test]
fn the_host_implements_every_function_the_contract_declares_and_no_others() {
    // The same property from the other side: the bare-name map is one entry per import, so a name cannot serve two
    // functions and a function cannot be missing.
    let implemented = implemented();
    assert_eq!(implemented.len(), provided().len());
    // The count is written down as well as derived, because a *contract* change is a decision rather than a
    // consequence: a function added to the WIT file without anybody noticing is what this number is here to catch.
    assert_eq!(implemented.len(), 35, "the contract's own count");
    for (function, import) in &implemented {
        assert!(import.ends_with(&format!("#{function}")), "{function} -> {import}");
        assert!(provides(import));
    }
}

// ── The gate ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_call_the_contract_does_not_declare_is_refused_before_anything_is_counted() {
    // ★ Not "refused because it is gated and unheld" — refused because it is not a function. The table is generated
    // from the WIT file, so a name it does not list is a name nothing implements.
    let host = Stub::default();
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    for name in [
        "synra:plugin/host#teleport",
        "synra:plugin/host#storage-get-all",
        "wasi:filesystem/types@0.2.0",
        "storage-get",
        "",
    ] {
        match calls.call(name, "") {
            Err(error) => assert_eq!(error.code, CallError::UNKNOWN_FUNCTION, "{name}"),
            Ok(answer) => panic!("{name} was accepted: {answer}"),
        }
    }
    assert!(host.called().is_empty(), "nothing reached the host");
    assert!(audit.is_empty(), "a call to nothing is not a cost to bill");
}

#[test]
fn a_gated_call_without_the_capability_is_refused_and_does_not_reach_the_host() {
    // ★ The property that makes the gate a gate: a refusal that still performed the call would be a refusal that did
    // nothing. The stub records every call that got through, and it is asked to have none.
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let gated = [
        ("synra:plugin/host#storage-set", r#"{"key":"k","value":"v"}"#),
        ("synra:plugin/host#storage-get", "known"),
        ("synra:plugin/host#device-list", ""),
        ("synra:plugin/host#device-send", r#"{"target":"d","event":"e","payload":"{}"}"#),
        ("synra:plugin/host#network-fetch", r#"{"url":"https://example"}"#),
        ("synra:plugin/host#platform-open-url", "https://example"),
        ("synra:plugin/host#secret-get", "token"),
        ("synra:plugin/host#transfer-send", r#"{"target":"d","event":"k","payload":"{}"}"#),
        ("synra:plugin/host#action-declare", r#"{"name":"n","schema":"{}"}"#),
    ];
    for (import, argument) in gated {
        match calls.call(import, argument) {
            Err(error) => {
                assert_eq!(error.code, CallError::CAPABILITY_DENIED, "{import}");
                // The refusal names the capability, so a plugin author knows what to ask the user for.
                assert!(error.message.contains(':'), "{import}: {}", error.message);
            }
            Ok(answer) => panic!("{import} was accepted: {answer}"),
        }
    }
    assert!(host.called().is_empty(), "a refused call reached the host: {:?}", host.called());
    // And every refusal is in the audit, because "which plugin tried to do what it could not" is what it is read for.
    assert_eq!(audit.len(), gated.len());
    assert!(audit.iter().all(|entry| entry.outcome == AuditOutcome::Denied));
}

#[test]
fn the_ungated_functions_reach_the_host_with_nothing_granted() {
    // ★ The five `env-*` queries exist because a plugin needs the answers *before* it can decide what to ask for;
    // gating them would mean requesting a capability to discover whether it wants it.
    let host = Stub::default();
    let grants = CapabilitySet::new();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(calls.call("synra:plugin/host#env-sdk-version", ""), Ok("1.0.0".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-host-kind", ""), Ok("headless".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-locale", ""), Ok("en-GB".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-dark-mode", ""), Ok("true".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-can", "log:*"), Ok("true".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-can", "storage:local:write"), Ok("false".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#plugin-id", ""), Ok("@acme/chat".to_owned()));
    assert_eq!(
        calls.call("synra:plugin/host#platform-capabilities", ""),
        Ok("[\"platform:notify\"]".to_owned())
    );
    // None of these is audited: there is no capability for them to be a record *about*.
    assert!(audit.is_empty(), "{audit:?}");
}

#[test]
fn a_capability_that_covers_one_function_does_not_cover_another() {
    // The gate is per function and not per domain: holding `storage:local:read` must not let a plugin write.
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(calls.call("synra:plugin/host#storage-get", "known"), Ok("a value".to_owned()));
    match calls.call("synra:plugin/host#storage-set", r#"{"key":"k","value":"v"}"#) {
        Err(error) => assert_eq!(error.code, CallError::CAPABILITY_DENIED),
        other => panic!("a write was accepted with a read grant: {other:?}"),
    }
    assert_eq!(host.called(), vec!["storage-get".to_owned()]);
}

// ── The rate limit ────────────────────────────────────────────────────────────────────────────────

#[test]
fn calling_faster_than_the_limit_allows_is_refused_and_counted() {
    // The limit is per kind rather than per function, and this drives it until it refuses: the refusal is a value a
    // plugin handles, not a trap.
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();

    // ★ The property, and it is about a *refused* call rather than about the next one: the count of calls that reached
    // the host must equal the count that were admitted. A refusal that still performed the call is the bug this rules
    // out, and it is checkable without knowing when the bucket will refuse next — which the second version of this test
    // tried to assume, and which is not knowable: a refilled token makes the call after a refusal succeed, and that is
    // the rate limiter working rather than failing.
    let mut admitted = 0u64;
    let mut refusals = 0u64;
    let mut refused_after_a_refusal = false;
    let mut last_was_refused = false;
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for _ in 0..10_000 {
            match calls.call("synra:plugin/host#log", r#"{"level":"info","message":"x"}"#) {
                Ok(_) => {
                    admitted += 1;
                    last_was_refused = false;
                }
                Err(error) => {
                    assert_eq!(error.code, CallError::RATE_LIMITED);
                    refusals += 1;
                    refused_after_a_refusal |= last_was_refused;
                    last_was_refused = true;
                    // ★ The count of calls that reached the host is the count that were admitted, at every refusal —
                    // which is the assertion that a refusal does not perform the call.
                    assert_eq!(
                        host.called().len() as u64,
                        admitted,
                        "a refused call reached the host"
                    );
                }
            }
        }
    }
    assert!(refusals > 0, "the budget never refused");
    assert!(refused_after_a_refusal, "the limit refused once and then stopped");
    assert!(audit.iter().any(|entry| entry.outcome == AuditOutcome::RateLimited));
}

#[test]
fn the_ungated_calls_are_not_rate_limited() {
    // A plugin that needs an environment fact to decide what to ask for must be able to ask, however often.
    let host = Stub::default();
    let grants = CapabilitySet::new();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    for _ in 0..5_000 {
        assert_eq!(calls.call("synra:plugin/host#plugin-id", ""), Ok("@acme/chat".to_owned()));
    }
}

#[test]
fn the_rate_kind_is_chosen_by_what_the_call_costs() {
    // A storage write and a storage read are the same kind of thing to the host, and a network call is not.
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#storage-set"), RateKind::HostCalls);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#storage-get"), RateKind::HostCalls);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#network-fetch"), RateKind::NetworkRequests);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#device-send"), RateKind::DeviceSends);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#event-emit"), RateKind::Events);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#transfer-send"), RateKind::FsOps);
    assert_eq!(HostCalls::rate_kind("synra:plugin/host#platform-notify"), RateKind::HostCalls);
}

// ── The answers ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_device_list_is_the_json_the_contracts_list_becomes() {
    let host = Stub::with_devices(&[("device-a", "Laptop", "desktop"), ("device-b", "Phone", "mobile")]);
    let grants = granted(&["device:list"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let answer = calls.call("synra:plugin/host#device-list", "").expect("a list");
    let parsed: serde_json::Value = serde_json::from_str(&answer).expect("valid JSON");
    let array = parsed.as_array().expect("an array");
    assert_eq!(array.len(), 2);
    assert_eq!(array.first().and_then(|value| value.get("name")).and_then(|v| v.as_str()), Some("Laptop"));
    assert_eq!(array.first().and_then(|value| value.get("kind")).and_then(|v| v.as_str()), Some("desktop"));
}

#[test]
fn an_absent_key_is_a_not_found_error_rather_than_a_host_failure() {
    // ★ A plugin branching on `notFound` is doing something ordinary; one branching on `hostFailed` is not. A host that
    // answered the same code for both would make the two indistinguishable.
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(calls.call("synra:plugin/host#storage-get", "known"), Ok("a value".to_owned()));
    let error = calls.call("synra:plugin/host#storage-get", "absent").expect_err("an error");
    assert_eq!(error.code, "notFound");
    // And a failure the host had is a different code, so a plugin can tell them apart.
    let failed = host.device_send(&plugin(), "unknown", "e", "{}").expect_err("a host failure");
    assert_eq!(failed.code, CallError::HOST_FAILED);
}

#[test]
fn a_storage_quota_is_a_pair_of_numbers_a_plugin_can_read() {
    // ★ Usage from the host, the ceiling from the quota — and this test used to check neither.
    //
    // It asserted `[128,1024]`, which was the *stub's* two constants: the double answered `storage_quota` with a canned
    // pair, so the test verified that a number the double made up came back out. Two real numbers replaced it, and the
    // assertion is now about where each one comes from — a plugin reading its quota is reading its own usage and the
    // kernel's decision about its ceiling.
    let host = Stub::using(128);
    let grants = granted(&["storage:local:read"]);
    // A quota with a ceiling a person can read, so the assertion names the value rather than the default.
    let quota = Quota { max_storage_bytes: 1_024, ..Quota::default() };
    let budget = Budget::new(quota);
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let answer = calls.call("synra:plugin/host#storage-quota", "").expect("a quota");
    assert_eq!(answer, "[128,1024]", "the host's usage and the quota's ceiling");
    let parsed: serde_json::Value = serde_json::from_str(&answer).expect("valid JSON");
    assert_eq!(parsed, serde_json::json!([128, 1024]));
}

#[test]
fn a_write_that_would_exceed_the_quota_is_refused_before_it_is_stored() {
    // ★ The one shape of enforcement that does not enforce anything is the check placed *after* the write.
    //
    // A plugin that kept writing would keep growing past its ceiling while being told each time that it had. So this
    // asserts both halves: the refusal, and that the host was **never asked to write**.
    let host = Stub::using(1_000);
    let grants = granted(&["storage:local:write"]);
    let quota = Quota { max_storage_bytes: 1_010, ..Quota::default() };
    let budget = Budget::new(quota);
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    // Eleven bytes onto a thousand, with nothing replaced: over by one.
    let refused = calls
        .call("synra:plugin/host#storage-set", r#"{"key":"fresh","value":"0123456789a"}"#)
        .expect_err("over the quota");

    assert_eq!(refused.code, CallError::QUOTA_EXCEEDED, "{refused:?}");
    // ★ And it says so with a code of its own rather than `rateLimited`: a plugin told it is going too fast would wait and
    // try the same thing again, when what it needs to do is store less.
    assert!(
        !host.called().contains(&"storage-set".to_owned()),
        "the host was not asked to write: {:?}",
        host.called()
    );
}

#[test]
fn a_write_that_replaces_a_larger_value_is_measured_by_the_difference() {
    // ★ The arithmetic is `used - replaced + new`, not `used + new`.
    //
    // A plugin rewriting a key with a shorter value is *shrinking* its storage, and a check that ignored what it replaced
    // would refuse a write that makes the situation better — the shape of limit that punishes tidying up.
    //
    // `known` is the key the stub holds, and it answers with `"a value"` — seven bytes.
    let host = Stub::using(12);
    let grants = granted(&["storage:local:write"]);
    let quota = Quota { max_storage_bytes: 12, ..Quota::default() };
    let budget = Budget::new(quota);
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    // Already at the ceiling, and the write is smaller than what it replaces: 12 - 7 + 5 = 10, which fits.
    calls
        .call("synra:plugin/host#storage-set", r#"{"key":"known","value":"short"}"#)
        .expect("a smaller value fits");

    assert!(host.called().contains(&"storage-set".to_owned()), "and the host wrote it");
}

#[test]
fn a_key_list_is_an_array_of_strings_with_the_awkward_characters_escaped() {
    // The list is written by hand rather than through `serde_json`, so the escaping is the thing to test.
    assert_eq!(json_array(&["a".to_owned(), "b\"c".to_owned()]), "[\"a\",\"b\\\"c\"]");
    assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
    assert_eq!(json_string("a\nb\tc"), "\"a\\nb\\tc\"");
    assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    assert_eq!(json_string("héllo"), "\"héllo\"", "a non-ASCII character is not escaped");
    assert_eq!(json_array(&[]), "[]");

    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    let answer = calls.call("synra:plugin/host#storage-keys", "pre").expect("keys");
    assert_eq!(answer, "[\"preone\",\"pretwo\"]");
}

#[test]
fn a_log_line_reaches_the_host_with_the_level_and_the_context() {
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(
        calls.call("synra:plugin/host#log", r#"{"level":"warn","message":"careful","context":"startup"}"#),
        Ok("null".to_owned())
    );
    assert_eq!(host.called(), vec!["log".to_owned()]);
    // And a line whose JSON is not what `log` takes is a bad argument rather than a panic: a `log` call is the last
    // thing that should be able to bring the host down.
    match calls.call("synra:plugin/host#log", "not json") {
        Err(error) => assert_eq!(error.code, CallError::BAD_ARGUMENT),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_platform_action_carries_its_own_capability_and_its_own_argument() {
    // ★ One capability per action rather than one `platform:*`: a plugin that notifies has no business simulating
    // keystrokes, and one capability for both would make the permission dialog ask for both.
    let host = Stub::default();
    let grants = granted(&["platform:notify", "platform:read-clipboard"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(
        calls.call("synra:plugin/host#platform-notify", r#"{"title":"Hello","body":"World"}"#),
        Ok("null".to_owned())
    );
    assert_eq!(
        calls.call("synra:plugin/host#platform-read-clipboard", ""),
        Ok(r#""clipboard text""#.to_owned())
    );
    match calls.call("synra:plugin/host#platform-simulate-keys", "ctrl+s") {
        Err(error) => assert_eq!(error.code, CallError::CAPABILITY_DENIED),
        other => panic!("simulating keys was accepted with a notify grant: {other:?}"),
    }
    assert_eq!(host.called(), vec!["platform".to_owned(), "platform".to_owned()]);
}

#[test]
fn every_platform_action_names_its_own_capability() {
    let mut capabilities: Vec<&str> = Vec::new();
    for action in PlatformAction::ALL {
        let capability = action.capability();
        assert!(!capabilities.contains(&capability), "{capability} gates two actions");
        capabilities.push(capability);
        // And the contract knows the capability, which is what makes the gate table and this agree.
        assert!(is_declared_capability(capability), "{capability}");
        // And the name round-trips, so the glue layer and this agree about which action is which.
        assert_eq!(PlatformAction::parse(action.as_str()), Some(*action));
    }
    assert_eq!(capabilities.len(), 7);
    assert_eq!(PlatformAction::parse("teleport"), None);
}

#[test]
fn a_websocket_is_refused_because_this_host_has_none() {
    // ★ The contract declares it, so it cannot be an unknown function — and this build has no socket. A plugin handed
    // a subscription that never delivers would wait for ever rather than find out.
    let host = Stub::default();
    let grants = granted(&["network:websocket:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    match calls.call("synra:plugin/host#network-websocket", "wss://example") {
        Err(error) => {
            assert_eq!(error.code, CallError::HOST_FAILED);
            assert!(error.message.contains("network-fetch"), "{}", error.message);
        }
        other => panic!("{other:?}"),
    }
    assert!(host.called().is_empty());
}

#[test]
fn a_returned_value_that_is_empty_becomes_the_json_null_the_glue_expects() {
    // The `outcome` variant carries a string, and a function with nothing to say says `null` rather than an empty
    // string — an empty string is a value a plugin would have to distinguish from "no answer".
    let host = Stub::default();
    let grants = granted(&["event:emit:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    assert_eq!(
        calls.call(
            "synra:plugin/host#event-emit",
            r#"{"event":"_plugin.@acme/chat.something","payload":"{}"}"#
        ),
        Ok("null".to_owned())
    );
}

// ── The audit ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_gate_records_its_four_metrics() {
    // ★ The design's `gate_*` metrics, from the one place that knows their answers.
    //
    // `RingRecorder` was written, tested and reachable from nothing: every one of the ~30 metrics in the design's list was
    // unwired, and the recorder had no producer at all. This is the first — the gate, because it is where "was it allowed,
    // for which plugin, against which capability, and if not, was it the set or the limiter" is already decided.
    let host = Stub::default();
    let grants = granted(&["device:list"]);
    let budget = budget();
    let recorder = synra_observe::metrics::RingRecorder::new();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit).with_metrics(&recorder);

    // One allowed, one denied.
    let _ = calls.call("synra:plugin/host#device-list", "");
    let _ = calls.call("synra:plugin/host#device-send", "{}");

    let snapshot = recorder.snapshot();
    assert_eq!(
        snapshot.get("gate_checks_total{result=allowed}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the allowed check"
    );
    assert_eq!(
        snapshot.get("gate_checks_total{result=denied}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "and the refused one"
    );
    // ★ And the refusal names the capability, which is the label the design asks `gate_denied_total` to carry — it is the
    // question "which permission do plugins keep asking for and not have", and a count without it cannot answer that.
    assert_eq!(
        snapshot.get("gate_denied_total{capability=device:send:*}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "named rather than counted in the abstract"
    );
}

#[test]
fn a_gated_call_records_how_long_it_took() {
    // ★ Nothing in production had ever called `histogram_observe`; only the recorder's own tests did. A histogram no
    // caller uses is a shape rather than a measurement — and the number was already in the caller's hand, because
    // `elapsed_ms` went into the audit entry and nowhere else.
    //
    // The gate metrics above answer "what was decided"; this answers "how slow is it", which is a question about a
    // distribution and cannot be read off any number of audit rows.
    let host = Stub::default();
    let grants = granted(&["device:list"]);
    let budget = budget();
    let recorder = synra_observe::metrics::RingRecorder::new();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit).with_metrics(&recorder);

    let _ = calls.call("synra:plugin/host#device-list", "");

    let snapshot = recorder.snapshot();
    // Labelled by the import, which is what a call is — the same shape `gate_denied_total` carries a capability in — and
    // the recorder's own cardinality guard is what bounds the series a caller could create.
    assert!(
        snapshot.get("host_call_ms{import=synra:plugin/host#device-list}").is_some(),
        "the duration was not recorded"
    );
}

#[test]
fn a_refusal_tells_a_plugin_what_it_already_holds_in_that_domain() {
    // ★ The wiring rather than the derivation.
    //
    // `CapabilityDenied::of` is tested in its own crate. What this asserts is that the gate hands it the **session's own
    // grants** — a refusal built against an empty set would look identical from the outside and would tell every author
    // "you hold nothing in that domain", which is exactly the kind of quiet wrong answer that makes an error message
    // useless.
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let refused = calls
        .call("synra:plugin/host#storage-set", r#"{"key":"k","value":"v"}"#)
        .expect_err("the write capability is not held");
    let details: serde_json::Value =
        serde_json::from_str(refused.details.as_deref().expect("details")).expect("valid JSON");

    assert_eq!(details["capability"], "storage:local:write");
    assert_eq!(details["granted"][0], "storage:local:read", "what the plugin actually holds");
    assert!(
        details["suggestion"].as_str().is_some_and(|text| text.contains("already holds")),
        "and the suggestion notices it: {details}"
    );
}

#[test]
fn every_gated_call_is_audited_against_the_capability_it_needed() {
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let _ = calls.call("synra:plugin/host#storage-get", "known");
    let _ = calls.call("synra:plugin/host#storage-delete", "k");

    assert_eq!(audit.len(), 2, "both calls are recorded, the refused one included");
    let first = audit.first().expect("a record");
    assert_eq!(first.plugin, plugin());
    assert_eq!(first.capability.to_string(), "storage:local:read");
    assert_eq!(first.outcome, AuditOutcome::Allowed);
    assert!(first.at_ms >= 0, "a timestamp is always set");
    assert!(first.elapsed_ms.is_some(), "how long it took is recorded");
}

#[test]
fn the_audit_names_the_plugin_that_called_and_never_the_arguments() {
    // The design document is explicit: the record is about the permission, and the capability describes a destination
    // rather than a content. A secret written here must not appear in the audit.
    let host = Stub::default();
    let grants = granted(&["storage:secure:write"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let _ = calls.call("synra:plugin/host#secret-set", r#"{"key":"token","value":"hunter2"}"#);
    let rendered = format!("{audit:?}");
    assert!(!rendered.contains("hunter2"), "the secret is in the audit: {rendered}");
    assert!(rendered.contains("@acme/chat"), "{rendered}");
}

#[test]
fn a_debug_form_names_the_plugin_and_how_much_has_been_audited() {
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let calls = session(&host, &grants, &budget, &mut audit);
    let text = format!("{calls:?}");
    assert!(text.contains("HostCalls"), "{text}");
    assert!(text.contains("@acme/chat"), "{text}");
    assert_eq!(calls.plugin(), &plugin());
    assert_eq!(calls.grants().len(), 1);
}

#[test]
fn every_error_code_is_a_name_a_plugin_branches_on() {
    // The codes are the stable surface: a plugin matches on them, so they are camelCase identifiers rather than
    // sentences, and they do not change with the wording of a message.
    let errors = [
        CallError::unknown("synra:plugin/host#teleport"),
        CallError::denied("storage:local:write", &CapabilitySet::new()),
        CallError::new(CallError::RATE_LIMITED, "too fast"),
        CallError::new(CallError::BAD_ARGUMENT, "not json"),
        CallError::new(CallError::HOST_FAILED, "the keychain is locked"),
    ];
    for (index, error) in errors.iter().enumerate() {
        let code = error.code;
        assert!(code.chars().next().is_some_and(char::is_lowercase), "{code}");
        assert!(code.chars().all(|character| character.is_ascii_alphanumeric()), "{code}");
        assert!(!error.message.is_empty(), "{code}");
        assert!(!error.to_string().is_empty() || index == 0, "{code}");
    }
    // And a refusal names the capability, because the next thing a plugin does is ask the user for it.
    assert!(errors[1].message.contains("storage:local:write"));
    // ★ The three elements the design asks a refusal to carry, read out of the details a plugin is handed: what the call
    // needed, what the plugin holds, and what to do about it. The first of the three was all that existed, so this is the
    // assertion that would have failed against the old shape.
    let details: serde_json::Value =
        serde_json::from_str(errors[1].details.as_deref().expect("details")).expect("valid JSON");
    assert_eq!(details["capability"], "storage:local:write");
    assert_eq!(details["granted"], serde_json::json!([]));
    assert!(
        details["suggestion"].as_str().is_some_and(|text| text.contains("ask the user")),
        "{details}"
    );
    // The serialised form carries the code, which is what the glue layer hands the guest.
    let json = serde_json::to_string(&errors[2]).expect("serialises");
    assert!(json.contains("\"code\":\"rateLimited\""), "{json}");
    // An error with no details omits the field rather than sending `null`.
    assert!(!json.contains("details"), "{json}");
}

#[test]
fn the_clock_the_session_uses_is_the_stores() {
    // One clock for the kernel: an audit entry and a device's `last_seen_ms` must be comparable, and two clocks would
    // make a plugin's call appear to have happened before the device it addressed.
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    let before = now_ms();
    let _ = calls.call("synra:plugin/host#log", r#"{"level":"info","message":"x"}"#);
    let after = now_ms();
    let at = audit.first().map(|entry| entry.at_ms).expect("a record");
    assert!(at >= before && at <= after, "{before} <= {at} <= {after}");
}

#[test]
fn scoped_network_import_is_loadable_with_a_specific_host() {
    let grants = granted(&["network:fetch:api.github.com"]);
    assert!(host_surface::permits(
        "synra:plugin/host#network-fetch",
        &grants
    ));
}

#[test]
fn scoped_network_calls_allow_only_the_actual_requested_host() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:api.github.com"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        assert!(
            calls
                .call(
                    "synra:plugin/host#network-fetch",
                    r#"{"url":"https://api.github.com/repos"}"#
                )
                .is_ok()
        );
        let denied = calls
            .call(
                "synra:plugin/host#network-fetch",
                r#"{"url":"https://evil.example/"}"#,
            )
            .unwrap_err();
        assert_eq!(denied.code, CallError::CAPABILITY_DENIED);
    }
    assert_eq!(host.called(), ["network-fetch"]);
    assert_eq!(audit.len(), 2);
    assert_eq!(audit.last().unwrap().outcome, AuditOutcome::Denied);
}

#[test]
fn scoped_network_url_authority_and_method_are_concrete_and_rechecked() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:api.github.com:POST"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        assert!(
            calls
                .call(
                    "synra:plugin/host#network-fetch",
                    r#"{"url":"https://API.GITHUB.COM.:8443/","method":"POST"}"#
                )
                .is_ok()
        );
        for request in [
            r#"{"url":"https://api.github.com/"}"#,
            r#"{"url":"https://api.github.com.evil/","method":"POST"}"#,
            r#"{"url":"https://api.github.com@evil.example/","method":"POST"}"#,
        ] {
            assert_eq!(
                calls
                    .call("synra:plugin/host#network-fetch", request)
                    .unwrap_err()
                    .code,
                CallError::CAPABILITY_DENIED
            );
        }
    }
    assert_eq!(host.called(), ["network-fetch"]);
}

#[test]
fn scoped_network_json_escaping_does_not_change_the_destination() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:api.github.com"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    assert!(
        calls
            .call(
                "synra:plugin/host#network-fetch",
                r#"{"url":"https:\/\/api.github.com\/repos"}"#
            )
            .is_ok()
    );
}

#[test]
fn scoped_network_malformed_targets_fail_before_host_effects() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for request in [
            r#"{"url":"file://api.github.com/path"}"#,
            r#"{"url":"https://*.github.com/"}"#,
            r#"{"url":"https://api.github.com/","method":"bad method"}"#,
            r#"{"url":"https://api.github.com\\@evil.example/"}"#,
            "not json",
        ] {
            assert_eq!(
                calls
                    .call("synra:plugin/host#network-fetch", request)
                    .unwrap_err()
                    .code,
                CallError::BAD_ARGUMENT
            );
        }
    }
    assert!(host.called().is_empty());
    assert!(
        audit
            .iter()
            .all(|entry| entry.outcome == AuditOutcome::Failed)
    );
}

#[test]
fn scoped_log_import_requires_at_least_one_supported_level() {
    for (caps, available) in [
        (&["log:info"][..], true),
        (&["log:*"][..], true),
        (&["log:unknown"][..], false),
        (&["log:info:**"][..], true),
        (&["log:**:info"][..], true),
        (&["log:**:unknown"][..], false),
        (&["network:fetch:*"][..], false),
        (&[][..], false),
    ] {
        assert_eq!(
            host_surface::permits("synra:plugin/host#log", &granted(caps)),
            available,
            "{caps:?}"
        );
    }
}

#[test]
fn scoped_log_calls_enforce_the_actual_level_and_revocation() {
    let host = Stub::default();
    let budget = budget();
    let mut audit = Vec::new();
    for (caps, level, allowed) in [
        (&["log:info"][..], "info", true),
        (&["log:info"][..], "warn", false),
        (&[][..], "info", false),
    ] {
        let grants = granted(caps);
        let mut calls = session(&host, &grants, &budget, &mut audit);
        let argument = serde_json::json!({"level": level, "message": "hello"}).to_string();
        let result = calls.call("synra:plugin/host#log", &argument);
        if allowed {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(result.unwrap_err().code, CallError::CAPABILITY_DENIED);
        }
    }
    assert_eq!(host.called(), ["log"]);
    assert_eq!(
        audit.iter().map(|entry| entry.outcome).collect::<Vec<_>>(),
        [
            AuditOutcome::Allowed,
            AuditOutcome::Denied,
            AuditOutcome::Denied
        ]
    );
}

#[test]
fn scoped_log_wildcards_accept_the_five_levels_but_never_an_invented_target() {
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for level in ["trace", "debug", "info", "warn", "error"] {
            let argument = serde_json::json!({"level": level, "message": "hello"}).to_string();
            assert!(calls.call("synra:plugin/host#log", &argument).is_ok());
        }
        for level in ["*", "unknown", "INFO", "info:extra"] {
            let argument = serde_json::json!({"level": level, "message": "hello"}).to_string();
            assert_eq!(
                calls
                    .call("synra:plugin/host#log", &argument)
                    .unwrap_err()
                    .code,
                CallError::BAD_ARGUMENT
            );
        }
    }
    assert_eq!(host.called(), vec!["log"; 5]);
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Failed)
            .count(),
        4
    );
}

#[test]
fn scoped_log_escaped_json_levels_preserve_their_concrete_authority() {
    let host = Stub::default();
    let grants = granted(&["log:info"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    assert!(
        calls
            .call(
                "synra:plugin/host#log",
                r#"{"level":"i\u006efo","message":"hello"}"#
            )
            .is_ok()
    );
    assert_eq!(host.called(), ["log"]);
}

#[test]
fn plugins_with_the_same_package_name_cannot_emit_each_others_events() {
    let host = Stub::default();
    let grants = granted(&["event:emit:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let argument = r#"{"event":"_plugin.@acme/chat.ready","payload":"{}"}"#;
    let mut owner = HostCalls::new(
        &host,
        PluginId::parse("@acme/chat").unwrap(),
        &grants,
        &budget,
        &mut audit,
    );
    assert!(owner.call("synra:plugin/host#event-emit", argument).is_ok());
    let mut other = HostCalls::new(
        &host,
        PluginId::parse("@other/chat").unwrap(),
        &grants,
        &budget,
        &mut audit,
    );
    assert_eq!(
        other
            .call("synra:plugin/host#event-emit", argument)
            .unwrap_err()
            .code,
        CallError::CAPABILITY_DENIED
    );
    assert_eq!(host.called(), ["event-emit"]);
}

#[test]
fn scoped_events_authorize_the_concrete_name_and_recheck_revocation() {
    let host = Stub::default();
    let budget = budget();
    let mut audit = Vec::new();
    for (caps, event, allowed) in [
        (
            &["event:emit:_plugin.@acme/chat.ready"][..],
            "_plugin.@acme/chat.ready",
            true,
        ),
        (
            &["event:emit:_plugin.@acme/chat.ready"][..],
            "_plugin.@acme/chat.other",
            false,
        ),
        (&[][..], "_plugin.@acme/chat.ready", false),
    ] {
        let grants = granted(caps);
        let mut calls = session(&host, &grants, &budget, &mut audit);
        let argument = serde_json::json!({"event": event, "payload": "{}"}).to_string();
        let result = calls.call("synra:plugin/host#event-emit", &argument);
        if allowed {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(result.unwrap_err().code, CallError::CAPABILITY_DENIED);
        }
    }
    assert_eq!(host.called(), ["event-emit"]);
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Denied)
            .count(),
        2
    );
    for cap in [
        "event:emit:_plugin.@acme/chat.ready",
        "event:emit:_plugin.@acme/chat.*",
        "event:**",
    ] {
        assert!(host_surface::permits(
            "synra:plugin/host#event-emit",
            &granted(&[cap])
        ));
    }
}

#[test]
fn event_capabilities_cannot_override_identity_or_invent_event_names() {
    let host = Stub::default();
    let grants = granted(&["event:emit:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for (event, expected) in [
            ("_plugin.@other/chat.ready", CallError::CAPABILITY_DENIED),
            (
                "_plugin.@acme/synra-plugin-chat.ready",
                CallError::CAPABILITY_DENIED,
            ),
            ("_plugin.chat.ready", CallError::BAD_ARGUMENT),
            ("_plugin.@acme/chat.*", CallError::BAD_ARGUMENT),
            ("_synra.device.changed", CallError::CAPABILITY_DENIED),
        ] {
            let argument = serde_json::json!({"event": event}).to_string();
            assert_eq!(
                calls
                    .call("synra:plugin/host#event-emit", &argument)
                    .unwrap_err()
                    .code,
                expected
            );
        }
    }
    assert!(host.called().is_empty());
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Denied)
            .count(),
        3
    );
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Failed)
            .count(),
        2
    );
}

#[test]
fn escaped_event_owner_strings_preserve_their_authority_and_maximal_names_fit() {
    let host = Stub::default();
    let grants = granted(&["event:emit:_plugin.@acme/chat.*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        assert!(
            calls
                .call(
                    "synra:plugin/host#event-emit",
                    r#"{"event":"_plugin.@acme\/chat.ready","payload":"{}"}"#
                )
                .is_ok()
        );
        let prefix = "_plugin.@acme/chat.";
        let event = format!(
            "{prefix}{}",
            "x".repeat(synra_protocol::event::MAX_EVENT_NAME_LEN - prefix.len())
        );
        let argument = serde_json::json!({"event": event}).to_string();
        assert!(
            calls
                .call("synra:plugin/host#event-emit", &argument)
                .is_ok()
        );
    }
    assert_eq!(host.called(), ["event-emit", "event-emit"]);
    assert_eq!(
        synra_protocol::event::MAX_EVENT_NAME_LEN + "event:subscribe:".len(),
        synra_capability::capability::MAX_LEN
    );
}
