//! The session registry's tests.

use super::*;
use synra_capability::Capability;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

fn plugin(text: &str) -> PluginId {
    PluginId::parse(text).expect("a valid plugin id")
}

fn grants(texts: &[&str]) -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for text in texts {
        set.insert_str(text).expect("a valid capability");
    }
    set
}

fn chat() -> PluginId {
    plugin("@synra-plugin/chat")
}

fn notes() -> PluginId {
    plugin("@synra-plugin/notes")
}

/// A registry with one session for `chat`.
fn with_chat() -> (UiSessionRegistry, u128) {
    let registry = UiSessionRegistry::new();
    let nonce = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 0xABCD, 1_000);
    (registry, nonce)
}

mod validation;
mod lifecycle;
mod reporting;
