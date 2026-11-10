use synra_capability::Capability;
use synra_protocol::PluginId;

use super::{AuditEntry, AuditOutcome, AuditRing, DEFAULT_RETENTION_DAYS, MEMORY_CAPACITY, PluginActivity, Retention};

mod entries;
mod ring;
mod retention_and_activity;

fn plugin(name: &str) -> PluginId {
    PluginId::parse(name).expect("valid plugin id")
}

fn capability(text: &str) -> Capability {
    Capability::parse(text).expect("valid capability")
}

fn entry(at_ms: i64, plugin_id: &PluginId, cap: &str, outcome: AuditOutcome) -> AuditEntry {
    AuditEntry::new(at_ms, plugin_id.clone(), capability(cap), outcome, Some(5))
}
