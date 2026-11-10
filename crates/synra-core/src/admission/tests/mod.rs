use synra_capability::{Capability, CapabilitySet};
use synra_protocol::ids::IntentId;
use synra_protocol::session::IntentInvocation;
use synra_protocol::PluginId;

use super::AdmissionContext;

mod decisions;
mod host;
mod outcomes;

pub(super) fn capability(text: &str) -> Capability {
    Capability::parse(text).expect("a valid capability")
}

pub(super) fn invocation() -> IntentInvocation {
    IntentInvocation {
        intent_id: IntentId::new(),
        plugin_id: PluginId::parse("@synra-plugin/chat").expect("a valid id"),
        action: "send-message".to_owned(),
        args: serde_json::value::RawValue::from_string("{}".to_owned()).expect("valid JSON"),
        display: None,
    }
}

/// A capability set built from strings, failing the test rather than the caller if one is malformed.
fn set_of(texts: &[&str]) -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for text in texts {
        set.insert_str(text).expect("a valid capability");
    }
    set
}

/// A context whose plugin holds everything.
fn permissive() -> AdmissionContext {
    AdmissionContext::new(set_of(&[
        "device:send:*",
        "platform:open-url",
        "network:fetch:*",
    ]))
}
