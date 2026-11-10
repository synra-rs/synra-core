use std::collections::HashMap;

use synra_protocol::PluginId;

use super::AuditEntry;

/// How many records are kept in memory.
///
/// The database keeps the long history; this is what the settings screen can show without a query. Ten
/// thousand entries at roughly a hundred bytes is a megabyte, which is affordable for something a user
/// opens and expects to be instant.
pub const MEMORY_CAPACITY: usize = 10_000;

/// A bounded in-memory ring of recent records.
///
/// The index by plugin exists because the interface asks exactly one question — "what has this plugin been
/// doing?" — and answering it by scanning ten thousand entries per screen refresh is the kind of thing that
/// makes a settings page feel slow.
#[derive(Debug)]
pub struct AuditRing {
    entries: Vec<AuditEntry>,
    capacity: usize,
    /// The next index to overwrite, once the ring is full.
    next: usize,
    /// How many records were evicted.
    evicted: u64,
    /// Per-plugin counts, so the interface can show a number without scanning.
    counts: HashMap<PluginId, u64>,
}

impl AuditRing {
    /// A ring holding the most recent `capacity` records.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(1024)),
            capacity,
            next: 0,
            evicted: 0,
            counts: HashMap::new(),
        }
    }

    /// A ring with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MEMORY_CAPACITY)
    }

    /// Records a call.
    pub fn record(&mut self, entry: AuditEntry) {
        *self.counts.entry(entry.plugin.clone()).or_insert(0) += 1;

        if self.capacity == 0 {
            // A configuration that disables the audit view still counts, so the number on the plugin's page
            // is not silently zero.
            self.evicted += 1;
            return;
        }

        if self.entries.len() < self.capacity {
            self.entries.push(entry);
            return;
        }
        // Overwrites the oldest, which is what makes this a ring rather than a growing list.
        if let Some(slot) = self.entries.get_mut(self.next) {
            *slot = entry;
        }
        self.next = (self.next + 1) % self.capacity;
        self.evicted += 1;
    }

    /// Every record, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<AuditEntry> {
        let mut ordered = self.entries.clone();
        ordered.sort_by_key(|entry| entry.at_ms);
        ordered
    }

    /// One plugin's records, oldest first.
    #[must_use]
    pub fn for_plugin(&self, plugin: &PluginId) -> Vec<AuditEntry> {
        let mut ordered: Vec<AuditEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.plugin == *plugin)
            .cloned()
            .collect();
        ordered.sort_by_key(|entry| entry.at_ms);
        ordered
    }

    /// One plugin's refusals.
    ///
    /// The list the interface puts first: a refusal is the moment the capability system did its job, and the
    /// user is the person who should know.
    #[must_use]
    pub fn refusals_for_plugin(&self, plugin: &PluginId) -> Vec<AuditEntry> {
        self.for_plugin(plugin)
            .into_iter()
            .filter(|entry| entry.outcome.is_refusal())
            .collect()
    }

    /// How many records have been made for a plugin, including those evicted.
    ///
    /// The count is of what happened, not of what is still held. A user asking "how often did this run"
    /// wants the total, and a number that silently decreased as the ring wrapped would be worse than none.
    #[must_use]
    pub fn count_for_plugin(&self, plugin: &PluginId) -> u64 {
        self.counts.get(plugin).copied().unwrap_or(0)
    }

    /// How many records are held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many records were evicted to make room.
    #[must_use]
    pub const fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Forgets one plugin's records.
    ///
    /// The user's "clear this plugin's history" action. The counts are zeroed too, because a cleared history
    /// that still reports a total is a history the user cannot actually clear.
    pub fn clear_plugin(&mut self, plugin: &PluginId) {
        self.entries.retain(|entry| entry.plugin != *plugin);
        self.counts.remove(plugin);
        // The ring is compacted by the removal, so the next write goes to the end.
        self.next = self.entries.len().min(self.capacity.saturating_sub(1));
    }

    /// Forgets everything.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.counts.clear();
        self.next = 0;
    }

    /// Every record older than a cutoff, for the database's retention sweep.
    #[must_use]
    pub fn older_than(&self, cutoff_ms: i64) -> Vec<AuditEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.at_ms < cutoff_ms)
            .cloned()
            .collect()
    }
}

impl Default for AuditRing {
    fn default() -> Self {
        Self::new()
    }
}
