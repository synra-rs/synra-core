use synra_capability::CapabilitySet;
use super::super::{Budget, CallError, Host, PlatformAction, json_array, json_string};
use crate::host_surface::is_declared_capability;
use crate::quota::Quota;
use crate::test_host::Stub;
use super::{budget, granted, plugin, session};

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
