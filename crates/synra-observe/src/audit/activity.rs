use synra_protocol::PluginId;

use super::{AuditEntry, AuditRing};

/// A summary of one plugin's activity, for the settings screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginActivity {
    /// Which plugin.
    pub plugin: PluginId,
    /// How many calls have been recorded.
    pub total: u64,
    /// The most recent records held, newest first.
    pub recent: Vec<AuditEntry>,
    /// The refusals held, newest first.
    pub refusals: Vec<AuditEntry>,
}

impl PluginActivity {
    /// Builds a summary from a ring.
    #[must_use]
    pub fn of(ring: &AuditRing, plugin: &PluginId, limit: usize) -> Self {
        let mut recent = ring.for_plugin(plugin);
        recent.reverse();
        recent.truncate(limit);

        let mut refusals = ring.refusals_for_plugin(plugin);
        refusals.reverse();
        refusals.truncate(limit);

        Self {
            plugin: plugin.clone(),
            total: ring.count_for_plugin(plugin),
            recent,
            refusals,
        }
    }

    /// Whether anything has been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// A sentence for the interface.
    #[must_use]
    pub fn summarise(&self) -> String {
        if self.is_empty() {
            return "has not used any capabilities".to_owned();
        }
        match self.refusals.len() {
            0 => format!("{} capabilities used, none refused", self.total),
            count => format!("{} capabilities used, {count} refused", self.total),
        }
    }
}
