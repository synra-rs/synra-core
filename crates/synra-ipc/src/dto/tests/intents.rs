use synra_protocol::DeviceId;

use super::super::{IntentCandidate, IntentDecisionDto, IntentPrompt, IntentRetry, IntentSnapshot, IntentSourceDto};
use super::{intent_id, plugin_id};

#[test]
fn an_intent_source_carries_only_what_its_kind_needs() {
    // A single struct with both text and paths optional would let the interface send a share with neither.
    let share = IntentSourceDto::Share { text: "hi".to_owned(), title: None };
    assert_eq!(share.kind(), "share");

    let files = IntentSourceDto::ShareFiles { paths: vec!["/a".to_owned()] };
    assert_eq!(files.kind(), "shareFiles");

    assert_eq!(IntentSourceDto::Clipboard.kind(), "clipboard");

    let action = IntentSourceDto::PluginAction {
        plugin_id: plugin_id(),
        action: "send".to_owned(),
        args: serde_json::json!({}),
    };
    assert_eq!(action.kind(), "pluginAction");
}

#[test]
fn an_intent_source_is_tagged_on_the_wire() {
    let json = serde_json::to_string(&IntentSourceDto::Clipboard).expect("serialises");
    assert!(json.contains("\"kind\":\"clipboard\""), "{json}");
    let back: IntentSourceDto = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, IntentSourceDto::Clipboard);
}

#[test]
fn an_absent_title_is_omitted() {
    let json = serde_json::to_string(&IntentSourceDto::Share {
        text: "hi".to_owned(),
        title: None,
    })
    .expect("serialises");
    assert!(!json.contains("title"), "{json}");
}

#[test]
fn every_intent_source_carries_something_the_user_would_not_want_logged() {
    // The kernel records the kind and never the content, and this is what the diagnostics screen uses to say
    // so. A source that reported `false` here would be one the interface might echo.
    for source in [
        IntentSourceDto::Share { text: "x".to_owned(), title: None },
        IntentSourceDto::ShareFiles { paths: vec!["/a".to_owned()] },
        IntentSourceDto::Clipboard,
        IntentSourceDto::PluginAction {
            plugin_id: plugin_id(),
            action: "x".to_owned(),
            args: serde_json::json!(null),
        },
    ] {
        assert!(source.carries_user_content(), "{:?}", source.kind());
    }
}

#[test]
fn a_decision_says_whether_it_accepts() {
    assert!(IntentDecisionDto::AcceptDefault.is_accepting());
    assert!(IntentDecisionDto::Accept { device_id: DeviceId::new() }.is_accepting());
    assert!(!IntentDecisionDto::Decline { reason: None }.is_accepting());
}

#[test]
fn a_decision_is_tagged_on_the_wire() {
    for decision in [
        IntentDecisionDto::AcceptDefault,
        IntentDecisionDto::Decline { reason: Some("no".to_owned()) },
    ] {
        let json = serde_json::to_string(&decision).expect("serialises");
        assert!(json.contains("\"decision\""), "{json}");
        let back: IntentDecisionDto = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, decision);
    }
}

#[test]
fn an_intent_snapshot_round_trips() {
    let snapshot = IntentSnapshot {
        intent_id: intent_id(),
        trace_id: synra_protocol::ids::TraceId::new(),
        state: "awaiting_decision".to_owned(),
        plugin_id: Some(plugin_id()),
        candidates: vec![IntentCandidate {
            plugin_id: plugin_id(),
            title: "Chat".to_owned(),
            device_id: DeviceId::new(),
            online: true,
        }],
        prompt: Some(IntentPrompt {
            message: "intent.confirm".to_owned(),
            params: serde_json::json!({ "title": "Chat" }),
            options: vec!["accept".to_owned(), "decline".to_owned()],
        }),
        error: None,
        retry: Some(IntentRetry { attempts: 2, max_attempts: 8, gave_up: false, next_at_ms: Some(90_000) }),
        started_at_ms: 1_000,
    };
    let json = serde_json::to_string(&snapshot).expect("serialises");
    let back: IntentSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, snapshot);
}
