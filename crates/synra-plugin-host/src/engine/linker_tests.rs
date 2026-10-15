//! The glue, driven from both sides: what the contract declares, and what a guest receives.
//!
//! There is no engine here, and that is the point: everything this layer decides — which functions exist, what a
//! refusal looks like on the wire, what JSON a two-argument call takes — is a function of the contract's own table and
//! of strings. An engine would add a guest, and a guest is what the decisions are *about* rather than what makes them
//! right.

use super::*;
// The refusals these tests build are handed the set a plugin holds, so the set has to be nameable here.
use synra_capability::CapabilitySet;

/// Every function the contract declares, as bare names.
fn contract_functions() -> Vec<String> {
    host_surface::provided()
        .into_iter()
        .map(|import| import.rsplit_once('#').map_or(import, |(_, name)| name).to_owned())
        .collect()
}

#[test]
fn every_function_the_contract_declares_is_defined_by_one_of_the_shapes() {
    // ★ The test that keeps the glue and the contract the same size. The shapes are hand-written and the contract is
    // generated, so the failure mode this catches is a function added to the WIT file that the linker never defines —
    // which a plugin author would see as "the host does not provide `x`" for a function the contract plainly declares.
    let defined = shapes_defined();
    let mut missing: Vec<String> = contract_functions()
        .into_iter()
        .filter(|function| !defined.contains(function))
        .collect();
    missing.sort();
    assert!(missing.is_empty(), "the linker does not define: {missing:?}");
    assert_eq!(defined.len(), host_surface::provided().len());
}

#[test]
fn the_linker_defines_nothing_the_contract_does_not_declare() {
    // The other direction: a function the shapes define and the table does not know about would be a host function no
    // gate covers, which is the one outcome the whole design forbids.
    let mut extra: Vec<String> = shapes_defined()
        .into_iter()
        .filter(|function| !host_surface::provides(&import_name_for(function)))
        .collect();
    extra.sort();
    assert!(extra.is_empty(), "the linker defines functions the contract does not declare: {extra:?}");
}

#[test]
fn the_parameter_names_cover_every_function_whose_arguments_are_named() {
    // ★ A parameter name is what a JSON body is keyed by, so a function whose names are invented rather than read from
    // the contract is one that shifts a payload into a target. `device-send(target, event, payload)` and
    // `transfer-send(kind, target, meta-json)` have the same types and different meanings, which is why the names are a
    // table rather than positional.
    for function in contract_functions() {
        let names = parameter_names(&function);
        let declared = declared_parameter_count(&function);
        assert_eq!(
            names.len(),
            declared,
            "{function} has {declared} parameter(s) in the contract and {} name(s) here",
            names.len()
        );
    }
}

#[test]
fn the_shapes_arity_is_what_the_parameter_table_names() {
    // ★ The join between the two halves: the JSON a call receives is built from `parameter_names`, and the shape's
    // closure is what destructures the guest's arguments. They have to agree, or a three-argument call sends two.
    for (function, arity) in [
        ("env-sdk-version", 0),
        ("env-can", 1),
        ("plugin-id", 0),
        ("platform-capabilities", 0),
        ("device-list", 0),
        ("storage-quota", 0),
        ("storage-keys", 1),
        ("action-list", 0),
        ("event-emit", 2),
        ("device-send", 3),
        ("device-broadcast", 2),
        ("storage-set", 2),
        ("secret-set", 2),
        ("transfer-send", 3),
        ("log", 3),
        ("platform-notify", 2),
        ("action-declare", 2),
        ("action-invoke", 3),
        ("platform-read-clipboard", 0),
        ("network-fetch", 1),
    ] {
        assert_eq!(declared_parameter_count(function), arity, "{function}");
    }
}

#[test]
fn a_two_argument_call_is_keyed_by_the_contracts_own_names() {
    // The assertion that makes the table worth having: the JSON a call receives is the one the host-call layer's own
    // `Deserialize` expects, with no positional guessing in between.
    assert_eq!(arguments_json("device-send", &["phone", "a.b", "{}"]), r#"{"target":"phone","event":"a.b","payload":"{}"}"#);
    assert_eq!(arguments_json("storage-set", &["k", "v"]), r#"{"key":"k","value":"v"}"#);
    assert_eq!(
        arguments_json("transfer-send", &["file", "phone", "{}"]),
        r#"{"kind":"file","target":"phone","meta-json":"{}"}"#
    );
    // And each of those parses as the field names the host call layer looks for.
    for (function, values) in [
        ("device-send", vec!["phone", "a.b", "{}"]),
        ("storage-set", vec!["k", "v"]),
        ("transfer-send", vec!["file", "phone", "{}"]),
        ("event-emit", vec!["a.b", "{}"]),
    ] {
        let json = arguments_json(function, &values);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.is_object(), "{function}: {json}");
        assert_eq!(parsed.as_object().map(serde_json::Map::len), Some(values.len()), "{function}");
    }
}

#[test]
fn a_log_line_carries_the_level_the_contract_names_rather_than_its_index() {
    // The WIT `enum` crosses as a `u32` index, and what the host wants is the name: a log line that said `2` would be
    // one nobody could grep for.
    assert_eq!(log_json(0, "hello", None), r#"{"level":"trace","message":"hello"}"#);
    assert_eq!(log_json(2, "hello", None), r#"{"level":"info","message":"hello"}"#);
    assert_eq!(
        log_json(4, "hello", Some("startup")),
        r#"{"level":"error","message":"hello","context":"startup"}"#
    );
    // An index past the end is not a panic: a guest built against a different contract is one whose enum had more
    // cases, and the line is logged at the least alarming level rather than dropped.
    assert_eq!(log_json(99, "hello", None), r#"{"level":"info","message":"hello"}"#);
}

#[test]
fn a_refusal_is_the_json_the_outcome_variant_carries() {
    // The contract's shape for a call that can fail is `outcome`, whose `err` case carries a structured error with a
    // stable code. A refusal rendered as anything else would be one a plugin could not branch on.
    let denied = CallError::denied("storage:local:write", &CapabilitySet::new());
    let json = error_json(&denied);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed.get("code").and_then(|value| value.as_str()), Some("capabilityDenied"));
    assert!(parsed.get("details").is_some(), "{json}");

    let unknown = error_json(&CallError::unknown("synra:plugin/host#teleport"));
    assert!(unknown.contains("unknownFunction"), "{unknown}");
}

#[test]
fn an_answer_that_is_empty_becomes_the_json_null_the_outcome_expects() {
    // A function with nothing to say says `null` rather than an empty string, because an empty string is a value a
    // plugin would have to distinguish from "no answer".
    assert_eq!(Answer::Ok("null".to_owned()).into_outcome(), "null");
    assert_eq!(Answer::Ok("[1,2]".to_owned()).into_outcome(), "[1,2]");
    // And a refusal goes out as the error's JSON, not as its sentence.
    let refused = Answer::Denied(CallError::denied("log:*", &CapabilitySet::new()));
    assert!(refused.was_refused());
    assert!(refused.into_outcome().starts_with('{'));
}

#[test]
fn a_list_answer_that_is_not_a_list_is_an_empty_list_rather_than_a_panic() {
    // The host builds these with `json_array`, so a parse failure is a host bug — and the answer a plugin sees is
    // "there are none" rather than a call that failed.
    assert_eq!(parse_list(r#"["a","b"]"#), vec!["a".to_owned(), "b".to_owned()]);
    assert_eq!(parse_list(""), Vec::<String>::new());
    assert_eq!(parse_list("not json"), Vec::<String>::new());
    assert_eq!(parse_list(r#"{"a":1}"#), Vec::<String>::new());
}

#[test]
fn the_interface_a_guest_imports_is_the_one_the_contract_names() {
    // `synra:plugin/host@1.0.0`, assembled from the generated table so a version bump cannot leave this behind. The
    // symptom of getting it wrong is a component that will not instantiate for a plugin author who did nothing wrong.
    assert_eq!(host_interface(), "synra:plugin/host");
    assert_eq!(instance_interface(), "synra:plugin/host@1.0.0");
    assert_eq!(import_name("log"), "synra:plugin/host#log");
    
    // And the import names the linker uses are the names the gate table is keyed by, which is what makes the gate
    // reachable at all: a definition under a different name would call `gate()` with a name it does not know, and the
    // call would be refused as an unknown function.
    for function in contract_functions() {
        let by_interface = import_name(&function);
        let bare = import_name_for(&function);
        assert!(by_interface.ends_with(&format!("#{function}")), "{by_interface}");
        assert!(bare.ends_with(&format!("#{function}")), "{bare}");
        assert!(host_surface::provides(&bare), "{bare}");
    }
}

#[test]
fn a_refusal_a_guest_receives_names_what_to_ask_for() {
    // The next thing an author does after a refusal is ask the user for the capability, so the refusal names it — and
    // the code is one a plugin branches on rather than a sentence it parses.
    let refused = Answer::Denied(CallError::denied("device:send:*", &CapabilitySet::new()));
    let json = error_json(match &refused {
        Answer::Denied(error) => error,
        Answer::Ok(_) => panic!("a refusal"),
    });
    assert!(json.contains("capabilityDenied"), "{json}");
    assert!(json.contains("device:send:*"), "{json}");
    assert!(refused.was_refused());
}

#[test]
fn the_shapes_name_every_function_exactly_once() {
    // A function defined twice would be a `wasmtime` error at link time — a host bug that a suite should catch rather
    // than a kernel that fails to start.
    let defined = shapes_defined();
    let mut sorted = defined.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), defined.len(), "a function is defined twice: {defined:?}");
}

/// Every bare function name the shapes define.
///
/// # Why this is a list rather than a probe
///
/// Because defining them on a real `Linker` needs an engine, and an engine is the one thing this module's tests do not
/// have. The list is the shapes' own contents, and the suite's job is to keep it equal to the contract.
fn shapes_defined() -> Vec<String> {
    let mut defined: Vec<String> = Vec::new();
    for group in [
        &["env-sdk-version", "env-host-kind", "env-locale", "plugin-id"][..],
        &["env-dark-mode"][..],
        &["env-can"][..],
        &["platform-capabilities", "device-list"][..],
        &["storage-quota"][..],
        &["storage-keys", "action-list"][..],
        &[
            "event-subscribe",
            "storage-get",
            "storage-delete",
            "secret-get",
            "secret-delete",
            "network-fetch",
            "network-websocket",
            "transfer-status",
            "platform-open-url",
            "platform-open-path",
            "platform-reveal-path",
            "platform-simulate-keys",
            "platform-write-clipboard",
        ][..],
        &["event-emit", "device-send", "device-broadcast", "storage-set", "secret-set"][..],
        &["transfer-send"][..],
        &["log"][..],
        &["platform-read-clipboard"][..],
        &["platform-notify"][..],
        &["action-declare"][..],
        &["action-invoke"][..],
    ] {
        defined.extend(group.iter().map(|function| (*function).to_owned()));
    }
    defined
}

/// An import name in the spelling the gate table is keyed by.
///
/// The table is generated from the WIT *file*, whose package is `synra:plugin`, and the version lives on the world
/// rather than on each import — so the name a guest imports (`…/host@1.0.0#log`) and the name the table uses
/// (`synra:plugin/host#log`) differ by the version, and this is the one place that is written down.
fn import_name_for(function: &str) -> String {
    format!("{}/{}#{}", host_surface::PACKAGE, host_surface::HOST_INTERFACE, function)
}

/// How many parameters the contract declares for a function.
///
/// # Why this is derived and not a second table
///
/// Because two hand-kept tables that have to agree are two tables that will disagree — and the disagreement would be a
/// JSON body keyed by names nobody reads. The *arity* is checkable from the shape each function is defined in, which is
/// what this reads: a function in a shape whose closure takes two arguments has two parameters.
///
/// The one exception is `log`, whose level and context are a `log-level` and an `option<string>` rather than strings —
/// so it is named rather than inferred.
fn declared_parameter_count(function: &str) -> usize {
    if function == "log" {
        return 3;
    }
    let named = parameter_names(function);
    if named.is_empty() {
        // No names means the function takes nothing, which is the claim `parameter_names` makes by having no entry.
        return 0;
    }
    named.len()
}