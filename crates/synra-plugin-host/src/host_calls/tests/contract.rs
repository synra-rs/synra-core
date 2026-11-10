use super::super::{CallError, HostCalls, implemented};
use crate::host_surface::{provides, provided};
use crate::test_host::Stub;
use super::{all_capabilities, budget, session};

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

    // The deliberate refusals: this host has no WebSocket, and the stub holds no secret — which is `notFound`
    // rather than a failure, because an absent secret is an
    // ordinary answer.
    assert_eq!(
        refusals,
        vec![
            ("network-websocket".to_owned(), CallError::HOST_FAILED),
            ("secret-get".to_owned(), "notFound"),
        ]
    );
}

#[test]
fn runtime_subscription_is_not_a_host_import() {
    let host = Stub::default();
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    let refused = calls
        .call("synra:plugin/host#event-subscribe", "a.*")
        .expect_err("no callback registration import");
    assert_eq!(refused.code, CallError::UNKNOWN_FUNCTION);
    assert!(host.called().is_empty());
    // An unknown import has no capability to audit; never invent a granted capability for it.
    assert!(audit.is_empty());
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
        Work::Event {
            event_json: "{}".to_owned(),
        },
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
        "env-sdk-version",
        "env-host-kind",
        "env-locale",
        "env-dark-mode",
        "env-can",
        "platform-capabilities",
        "plugin-id",
        "log",
        "device-list",
        "storage-get",
        "storage-keys",
        "storage-quota",
        "secret-get",
        "transfer-status",
        "platform-read-clipboard",
        "action-list",
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
