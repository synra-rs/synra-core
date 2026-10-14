//! The host calls, driven from both sides: what the contract says, and what a plugin gets for asking.
//!
//! The stub host records everything, so a test can assert both the answer and the *effect* — which is what makes the
//! gate rules testable: a refusal that still reached the host would be a refusal that did nothing.

use std::sync::Mutex;

use synra_capability::CapabilitySet;
use synra_observe::audit::AuditOutcome;
use synra_protocol::ids::PluginId;
use synra_store::sqlite::now_ms;


use crate::host_surface::{CAPABILITIES, is_declared_capability, provides};
use crate::host_surface::provided;

use super::*;
use crate::quota::RateKind;
use crate::quota::Quota;

/// A host that records what it was asked and answers with a value taken from the function's name.
#[derive(Default)]
struct Stub {
    /// Every `(function, argument)` that got as far as the host.
    seen: Mutex<Vec<(String, String)>>,
    /// The device list it reports.
    devices: Vec<(String, String, String)>,
    /// Whether a secret is held, so `secret-get` has something to find.
    secret: Option<String>,
}

impl Stub {
    fn with_devices(devices: &[(&str, &str, &str)]) -> Self {
        Self {
            devices: devices
                .iter()
                .map(|(id, name, kind)| ((*id).to_owned(), (*name).to_owned(), (*kind).to_owned()))
                .collect(),
            ..Self::default()
        }
    }

    /// Everything the host was asked, as bare function names.
    fn called(&self) -> Vec<String> {
        self.seen.lock().expect("not poisoned").iter().map(|(name, _)| name.clone()).collect()
    }
}

impl Host for Stub {
    fn sdk_version(&self) -> String {
        "1.0.0".to_owned()
    }
    fn host_kind(&self) -> String {
        "headless".to_owned()
    }
    fn locale(&self) -> String {
        "en-GB".to_owned()
    }
    fn dark_mode(&self) -> bool {
        true
    }
    fn can(&self, _plugin: &PluginId, capability: &str) -> bool {
        capability == "log:*"
    }
    fn platform_capabilities(&self) -> Vec<String> {
        vec!["platform:notify".to_owned()]
    }

    fn log(&self, _plugin: &PluginId, level: &str, message: &str, context: Option<&str>) -> Result<(), CallError> {
        self.record("log", &format!("{level}/{message}/{}", context.unwrap_or("-")));
        Ok(())
    }
    fn event_emit(&self, _plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError> {
        self.record("event-emit", &format!("{event}/{payload}"));
        Ok(())
    }

    fn devices(&self) -> Vec<(String, String, String)> {
        self.record("device-list", "");
        self.devices.clone()
    }
    fn device_send(
        &self,
        _plugin: &PluginId,
        target: &str,
        event: &str,
        payload: &str,
    ) -> Result<(), CallError> {
        self.record("device-send", &format!("{target}/{event}/{payload}"));
        if target == "unknown" {
            return Err(CallError::new(CallError::HOST_FAILED, "no such device"));
        }
        Ok(())
    }
    fn device_broadcast(&self, _plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError> {
        self.record("device-broadcast", &format!("{event}/{payload}"));
        Ok(())
    }

    fn storage_get(&self, _plugin: &PluginId, key: &str) -> Result<Option<String>, CallError> {
        self.record("storage-get", key);
        Ok((key == "known").then(|| "a value".to_owned()))
    }
    fn storage_set(&self, _plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError> {
        self.record("storage-set", &format!("{key}={value}"));
        Ok(())
    }
    fn storage_delete(&self, _plugin: &PluginId, key: &str) -> Result<(), CallError> {
        self.record("storage-delete", key);
        Ok(())
    }
    fn storage_keys(&self, _plugin: &PluginId, prefix: Option<&str>) -> Result<Vec<String>, CallError> {
        self.record("storage-keys", prefix.unwrap_or(""));
        Ok(vec![format!("{}one", prefix.unwrap_or("")), format!("{}two", prefix.unwrap_or(""))])
    }
    fn storage_quota(&self, _plugin: &PluginId) -> Result<(u64, u64), CallError> {
        self.record("storage-quota", "");
        Ok((128, 1_024))
    }

    fn secret_get(&self, _plugin: &PluginId, key: &str) -> Result<Option<String>, CallError> {
        self.record("secret-get", key);
        Ok(self.secret.clone())
    }
    fn secret_set(&self, _plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError> {
        self.record("secret-set", &format!("{key}={value}"));
        Ok(())
    }
    fn secret_delete(&self, _plugin: &PluginId, key: &str) -> Result<(), CallError> {
        self.record("secret-delete", key);
        Ok(())
    }

    fn fetch(&self, _plugin: &PluginId, request_json: &str) -> Result<String, CallError> {
        self.record("network-fetch", request_json);
        Ok("{\"status\":200}".to_owned())
    }

    fn transfer_send(
        &self,
        _plugin: &PluginId,
        kind: &str,
        target: &str,
        meta_json: &str,
    ) -> Result<String, CallError> {
        self.record("transfer-send", &format!("{kind}/{target}/{meta_json}"));
        Ok("transfer-1".to_owned())
    }
    fn transfer_status(&self, _plugin: &PluginId, transfer_id: &str) -> Result<String, CallError> {
        self.record("transfer-status", transfer_id);
        Ok("{\"state\":\"running\"}".to_owned())
    }

    fn platform(&self, _plugin: &PluginId, action: &str, argument: &str) -> Result<Option<String>, CallError> {
        self.record("platform", &format!("{action}/{argument}"));
        if action == PlatformAction::ReadClipboard.as_str() {
            return Ok(Some("clipboard text".to_owned()));
        }
        Ok(None)
    }

    fn action_declare(&self, _plugin: &PluginId, name: &str, schema_json: &str) -> Result<(), CallError> {
        self.record("action-declare", &format!("{name}/{schema_json}"));
        Ok(())
    }
    fn action_list(&self, _plugin: &PluginId) -> Result<String, CallError> {
        self.record("action-list", "");
        Ok("[{\"plugin\":\"@acme/other\",\"name\":\"greet\"}]".to_owned())
    }
    fn action_invoke(
        &self,
        _plugin: &PluginId,
        target_plugin: &str,
        name: &str,
        args_json: &str,
    ) -> Result<String, CallError> {
        self.record("action-invoke", &format!("{target_plugin}/{name}/{args_json}"));
        Ok("\"hello\"".to_owned())
    }
}

impl Stub {
    /// Records a call, and does nothing if the lock is poisoned — a stub that panicked inside another test's stub
    /// should not turn into a second failure here.
    fn record(&self, name: &str, argument: &str) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((name.to_owned(), argument.to_owned()));
        }
    }
}

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

    let arguments = BTreeMap::from([
        ("log", r#"{"level":"info","message":"hello"}"#),
        ("event-emit", r#"{"event":"a.b","payload":"{}"}"#),
        ("event-subscribe", "a.*"),
        ("device-send", r#"{"target":"device-a","event":"a.b","payload":"{}"}"#),
        ("device-broadcast", r#"{"event":"a.b","payload":"{}"}"#),
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

    // The two deliberate refusals: this build has no WebSocket, and the stub holds no secret — which is `notFound`
    // rather than a failure, because an absent secret is an ordinary answer.
    assert_eq!(
        refusals,
        vec![
            ("network-websocket".to_owned(), CallError::HOST_FAILED),
            ("secret-get".to_owned(), "notFound"),
        ]
    );
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

    // ★ The assertion is on the *count before and after one refused call*, which is the only way to say "a refusal
    // does not reach the host" without a second call of its own changing the number being compared.
    let mut reached_at_refusal = 0;
    let mut refusals = 0;
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for _ in 0..10_000 {
            match calls.call("synra:plugin/host#log", r#"{"level":"info","message":"x"}"#) {
                Ok(_) => {}
                Err(error) => {
                    assert_eq!(error.code, CallError::RATE_LIMITED);
                    refusals += 1;
                    reached_at_refusal = host.called().len();
                    // The very next call is refused too, and it must not have reached the host.
                    let again = calls.call("synra:plugin/host#log", r#"{"level":"info","message":"x"}"#);
                    assert!(again.is_err(), "the limit stopped refusing: {again:?}");
                    assert_eq!(
                        host.called().len(),
                        reached_at_refusal,
                        "a rate-limited call still reached the host"
                    );
                    break;
                }
            }
        }
    }
    assert!(refusals > 0, "the budget never refused");
    // The burst is the bound the default quota sets, and the token bucket refills while the loop runs — so the count is
    // asserted as a *range* around the burst rather than as the burst, because an exact number would be a test that
    // fails when the machine is fast enough to refill a token.
    assert!(
        (1_000..1_100).contains(&reached_at_refusal),
        "the burst is 1000 and the refill is 500/s, so the refusal came at {reached_at_refusal}"
    );
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
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let answer = calls.call("synra:plugin/host#storage-quota", "").expect("a quota");
    assert_eq!(answer, "[128,1024]");
    let parsed: serde_json::Value = serde_json::from_str(&answer).expect("valid JSON");
    assert_eq!(parsed, serde_json::json!([128, 1024]));
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
        Ok("clipboard text".to_owned())
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
        calls.call("synra:plugin/host#event-emit", r#"{"event":"a.b","payload":"{}"}"#),
        Ok("null".to_owned())
    );
}

// ── The audit ─────────────────────────────────────────────────────────────────────────────────────

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
        CallError::denied("storage:local:write"),
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
    assert_eq!(
        errors[1].details.as_deref(),
        Some("{\"capability\":\"storage:local:write\"}")
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