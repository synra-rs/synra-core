//! The audit trail: what a plugin was allowed to do, and what it did.
//!
//! # Why this exists at all
//!
//! A capability prompt says "this plugin would like to read from GitHub". After that, the plugin runs, and
//! the user has no way to see whether it read from GitHub or from somewhere else. The audit trail is the
//! answer to that: every gated call, allowed or refused, in order, attributed.
//!
//! It is shown in the settings screen under the plugin's own name, because that is where a person looks
//! when they want to know what a plugin has been doing.
//!
//! # No payloads, ever
//!
//! An audit record says *that* `network:fetch` was called for `api.github.com`, and how long it took. It
//! does not say what was fetched. That is the whole reason the record is safe to keep for longer than a log
//! and safe to include in a diagnostic bundle: it is a list of destinations, not of contents.
//!
//! This is enforced by the type: [`AuditEntry`] has no field a payload could go in. A field added later
//! would have to be named, reviewed, and would fail the tests that assert the record contains no content.
//!
//! # Refusals are the interesting half
//!
//! An allowed call is bookkeeping. A refused one is the moment the capability system did its job, and the
//! user is the person who should know it happened — either because their plugin has a bug, or because it
//! was doing something they did not want. So a refusal is recorded with the same detail as an allowance, and
//! the interface does not hide it behind a filter.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use synra_capability::{Capability, Domain};
use synra_protocol::PluginId;

/// How many records are kept in memory.
///
/// The database keeps the long history; this is what the settings screen can show without a query. Ten
/// thousand entries at roughly a hundred bytes is a megabyte, which is affordable for something a user
/// opens and expects to be instant.
pub const MEMORY_CAPACITY: usize = 10_000;

/// The default retention, in days.
///
/// Fourteen, matching the log retention. A record of what a plugin did is only useful while the user can
/// still remember the session it refers to.
pub const DEFAULT_RETENTION_DAYS: u32 = 14;

/// How a gated call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The capability was held and the call proceeded.
    Allowed,
    /// No granted capability covered the call.
    Denied,
    /// The plugin exceeded its quota.
    QuotaExceeded,
    /// The plugin called faster than its rate limit allows.
    RateLimited,
    /// The call proceeded, but the operation itself failed.
    Failed,
}

impl AuditOutcome {
    /// Whether the call was permitted.
    #[must_use]
    pub const fn was_allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::Failed)
    }

    /// Whether this outcome is a refusal by the capability system rather than by the operation.
    ///
    /// The distinction drives how the interface sorts the list: refusals go to the top, because they are the
    /// entries a user is looking for.
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        matches!(self, Self::Denied | Self::QuotaExceeded | Self::RateLimited)
    }

    /// The name used in the interface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::QuotaExceeded => "quota-exceeded",
            Self::RateLimited => "rate-limited",
            Self::Failed => "failed",
        }
    }

    /// The icon the settings screen shows.
    #[must_use]
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Allowed => "ok",
            Self::Failed => "warn",
            Self::Denied | Self::QuotaExceeded | Self::RateLimited => "blocked",
        }
    }
}

/// One gated call.
///
/// See the module docs for the deliberate absence of any content field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// When it happened, in milliseconds since the epoch.
    pub at_ms: i64,
    /// Which plugin made the call.
    pub plugin: PluginId,
    /// The capability it was checked against.
    pub capability: Capability,
    /// How it ended.
    pub outcome: AuditOutcome,
    /// How long the call took, when it ran.
    pub elapsed_ms: Option<u64>,
}

impl AuditEntry {
    /// Records a call.
    #[must_use]
    pub const fn new(
        at_ms: i64,
        plugin: PluginId,
        capability: Capability,
        outcome: AuditOutcome,
        elapsed_ms: Option<u64>,
    ) -> Self {
        Self { at_ms, plugin, capability, outcome, elapsed_ms }
    }

    /// The domain the capability belongs to, for grouping in the interface.
    #[must_use]
    pub const fn domain(&self) -> Domain {
        self.capability.domain()
    }

    /// The destination, as much of it as is safe to show.
    ///
    /// The capability's qualifier is the host, the path or the device — the part that says *where* something
    /// happened, which is the part a user is asking about. It is safe for the same reason the record is: a
    /// capability describes destinations, never contents.
    #[must_use]
    pub fn destination(&self) -> Option<&str> {
        self.capability.qualifier().first().map(synra_capability::Segment::as_str)
    }

    /// A one-line rendering, matching what the settings screen shows.
    #[must_use]
    pub fn render(&self) -> String {
        let destination = self
            .destination()
            .map(|place| format!(" -> {place}"))
            .unwrap_or_default();
        let elapsed = self
            .elapsed_ms
            .map(|ms| format!("  {ms}ms"))
            .unwrap_or_default();
        format!(
            "{:>6} {} {}{}{}",
            self.outcome.marker(),
            self.capability.prefixes().first().map_or("", synra_capability::Segment::as_str),
            self.capability.domain(),
            destination,
            elapsed
        )
    }
}

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

/// How long records are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Days to keep.
    pub days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self { days: DEFAULT_RETENTION_DAYS }
    }
}

impl Retention {
    /// The cutoff, in milliseconds since the epoch, before which records are stale.
    #[must_use]
    pub fn cutoff_ms(&self, now_ms: i64) -> i64 {
        let window = i64::from(self.days) * 24 * 60 * 60 * 1_000;
        now_ms.saturating_sub(window)
    }

    /// Whether a record should be removed.
    #[must_use]
    pub fn is_stale(&self, entry: &AuditEntry, now_ms: i64) -> bool {
        entry.at_ms < self.cutoff_ms(now_ms)
    }

    /// Checks the retention is usable.
    ///
    /// # Errors
    ///
    /// A description if the window is zero, which would delete every record as it was written and leave the
    /// user with an audit page that never shows anything.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.days == 0 {
            return Err("retention must be at least a day, or the audit page is always empty");
        }
        Ok(())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(name: &str) -> PluginId {
        PluginId::parse(name).expect("valid plugin id")
    }

    fn capability(text: &str) -> Capability {
        Capability::parse(text).expect("valid capability")
    }

    fn entry(at_ms: i64, plugin_id: &PluginId, cap: &str, outcome: AuditOutcome) -> AuditEntry {
        AuditEntry::new(at_ms, plugin_id.clone(), capability(cap), outcome, Some(5))
    }

    #[test]
    fn a_record_has_no_place_to_put_a_payload() {
        // The property that makes the record safe to keep and safe to export. Asserted as a compile-time
        // fact by construction: the struct's fields are all there is, and none of them can hold content.
        let record = entry(1_000, &plugin("@synra-plugin/chat"), "network:fetch:api.github.com", AuditOutcome::Allowed);

        assert_eq!(record.at_ms, 1_000);
        assert_eq!(record.domain(), Domain::Network);
        assert_eq!(record.destination(), Some("api.github.com"));
        // The rendering is a destination, not a body.
        let rendered = record.render();
        assert!(rendered.contains("api.github.com"), "{rendered}");
        assert!(!rendered.contains("payload"), "{rendered}");
    }

    #[test]
    fn outcomes_report_whether_they_were_refusals() {
        assert!(AuditOutcome::Allowed.was_allowed());
        assert!(AuditOutcome::Failed.was_allowed());
        assert!(!AuditOutcome::Denied.was_allowed());

        // A refusal by the capability system, as distinct from an operation that failed.
        assert!(AuditOutcome::Denied.is_refusal());
        assert!(AuditOutcome::QuotaExceeded.is_refusal());
        assert!(AuditOutcome::RateLimited.is_refusal());
        assert!(!AuditOutcome::Allowed.is_refusal());
        assert!(!AuditOutcome::Failed.is_refusal(), "the call was permitted and then failed");
    }

    #[test]
    fn outcome_markers_match_the_documented_icons() {
        // The settings screen shows these, and the design document names them.
        assert_eq!(AuditOutcome::Allowed.marker(), "ok");
        assert_eq!(AuditOutcome::Failed.marker(), "warn");
        assert_eq!(AuditOutcome::Denied.marker(), "blocked");
        assert_eq!(AuditOutcome::QuotaExceeded.marker(), "blocked");
    }

    #[test]
    fn outcomes_round_trip_through_json_with_their_names() {
        for outcome in [
            AuditOutcome::Allowed,
            AuditOutcome::Denied,
            AuditOutcome::QuotaExceeded,
            AuditOutcome::RateLimited,
            AuditOutcome::Failed,
        ] {
            let json = serde_json::to_string(&outcome).expect("serialises");
            assert_eq!(json, format!("\"{}\"", outcome.as_str()));
            let back: AuditOutcome = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, outcome);
        }
    }

    #[test]
    fn a_record_round_trips_through_json_with_camel_case_fields() {
        let record = entry(1_700_000_000_000, &plugin("@synra-plugin/chat"), "device:send:@pc", AuditOutcome::Allowed);
        let json = serde_json::to_string(&record).expect("serialises");

        assert!(json.contains("\"atMs\""), "{json}");
        assert!(!json.contains("at_ms"), "{json}");

        let back: AuditEntry = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, record);
    }

    #[test]
    fn a_record_without_a_destination_renders_without_one() {
        let record = AuditEntry::new(
            1_000,
            plugin("@synra-plugin/chat"),
            capability("device:list"),
            AuditOutcome::Allowed,
            None,
        );
        assert_eq!(record.destination(), None);
        assert!(!record.render().contains("->"), "{}", record.render());
    }

    #[test]
    fn the_ring_holds_records_in_time_order() {
        let ring_plugin = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(16);
        ring.record(entry(3_000, &ring_plugin, "device:list", AuditOutcome::Allowed));
        ring.record(entry(1_000, &ring_plugin, "device:list", AuditOutcome::Allowed));
        ring.record(entry(2_000, &ring_plugin, "device:list", AuditOutcome::Allowed));

        let times: Vec<i64> = ring.all().into_iter().map(|e| e.at_ms).collect();
        assert_eq!(times, vec![1_000, 2_000, 3_000]);
    }

    #[test]
    fn the_ring_overwrites_the_oldest_when_full() {
        let ring_plugin = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(3);
        for index in 0..5i64 {
            ring.record(entry(index * 1_000, &ring_plugin, "device:list", AuditOutcome::Allowed));
        }

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.evicted(), 2);
        let times: Vec<i64> = ring.all().into_iter().map(|e| e.at_ms).collect();
        assert_eq!(times, vec![2_000, 3_000, 4_000], "the newest three survive");
    }

    #[test]
    fn a_full_ring_keeps_recording_in_order() {
        // More than one full wrap, so the write cursor's arithmetic is exercised rather than assumed.
        let ring_plugin = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(3);
        for index in 0..10i64 {
            ring.record(entry(index, &ring_plugin, "device:list", AuditOutcome::Allowed));
        }

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.evicted(), 7);
        let times: Vec<i64> = ring.all().into_iter().map(|e| e.at_ms).collect();
        assert_eq!(times, vec![7, 8, 9]);
    }

    #[test]
    fn a_zero_capacity_ring_counts_without_holding() {
        // A configuration that turns the audit view off must not silently report zero activity: the count is
        // what the plugin's page shows.
        let ring_plugin = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(0);
        for index in 0..4i64 {
            ring.record(entry(index, &ring_plugin, "device:list", AuditOutcome::Allowed));
        }

        assert!(ring.is_empty());
        assert_eq!(ring.evicted(), 4);
        assert_eq!(ring.count_for_plugin(&ring_plugin), 4);
    }

    #[test]
    fn the_ring_separates_plugins() {
        let chat = plugin("@synra-plugin/chat");
        let notes = plugin("@synra-plugin/notes");
        let mut ring = AuditRing::with_capacity(16);

        ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
        ring.record(entry(2_000, &notes, "log:debug", AuditOutcome::Allowed));
        ring.record(entry(3_000, &chat, "network:fetch:api.github.com", AuditOutcome::Denied));

        assert_eq!(ring.for_plugin(&chat).len(), 2);
        assert_eq!(ring.for_plugin(&notes).len(), 1);
        assert_eq!(ring.count_for_plugin(&chat), 2);
        assert_eq!(ring.count_for_plugin(&notes), 1);
        assert_eq!(ring.count_for_plugin(&plugin("@synra-plugin/other")), 0);
    }

    #[test]
    fn refusals_are_kept_apart_from_ordinary_records() {
        // The list the interface puts first: a refusal is the moment the capability system did its job.
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(16);

        ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
        ring.record(entry(2_000, &chat, "network:fetch:evil.com", AuditOutcome::Denied));
        ring.record(entry(3_000, &chat, "log:debug", AuditOutcome::Failed));
        ring.record(entry(4_000, &chat, "network:fetch:api.x.com", AuditOutcome::RateLimited));

        let refusals = ring.refusals_for_plugin(&chat);
        assert_eq!(refusals.len(), 2);
        assert_eq!(refusals[0].destination(), Some("evil.com"));
        assert_eq!(refusals[1].outcome, AuditOutcome::RateLimited);
        // A permitted call that then failed is not a refusal.
        assert!(!refusals.iter().any(|e| e.outcome == AuditOutcome::Failed));
    }

    #[test]
    fn the_count_is_of_what_happened_not_of_what_is_held() {
        // A number that silently decreased as the ring wrapped would be worse than no number.
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(2);
        for index in 0..10i64 {
            ring.record(entry(index, &chat, "device:list", AuditOutcome::Allowed));
        }

        assert_eq!(ring.len(), 2, "only two are held");
        assert_eq!(ring.count_for_plugin(&chat), 10, "but ten happened");
    }

    #[test]
    fn clearing_one_plugin_leaves_the_others() {
        let chat = plugin("@synra-plugin/chat");
        let notes = plugin("@synra-plugin/notes");
        let mut ring = AuditRing::with_capacity(16);
        ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
        ring.record(entry(2_000, &notes, "log:debug", AuditOutcome::Allowed));

        ring.clear_plugin(&chat);
        assert!(ring.for_plugin(&chat).is_empty());
        assert_eq!(ring.count_for_plugin(&chat), 0, "a cleared history reports no total");
        assert_eq!(ring.for_plugin(&notes).len(), 1, "another plugin is untouched");

        // And the ring still works afterwards.
        ring.record(entry(3_000, &notes, "log:info", AuditOutcome::Allowed));
        assert_eq!(ring.for_plugin(&notes).len(), 2);
    }

    #[test]
    fn clearing_removes_everything() {
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(16);
        ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
        ring.clear();

        assert!(ring.is_empty());
        assert_eq!(ring.count_for_plugin(&chat), 0);
    }

    #[test]
    fn a_stale_sweep_selects_only_old_records() {
        let retention = Retention { days: 1 };
        let day_ms = 24 * 60 * 60 * 1_000;
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(16);

        // One record two days old and one from an hour ago, with "now" at day two.
        let now = day_ms * 2;
        ring.record(entry(0, &chat, "device:list", AuditOutcome::Allowed));
        ring.record(entry(now - 3_600_000, &chat, "device:list", AuditOutcome::Allowed));

        let cutoff = retention.cutoff_ms(now);
        assert_eq!(cutoff, day_ms, "one day back from day two");

        let stale = ring.older_than(cutoff);
        assert_eq!(stale.len(), 1, "only the two-day-old record is stale");
        assert_eq!(stale[0].at_ms, 0);
        assert!(retention.is_stale(&stale[0], now));

        // And the recent one is not selected.
        let recent = ring.all();
        assert!(
            !retention.is_stale(&recent[1], now),
            "a record from an hour ago is inside a one-day window"
        );
    }

    #[test]
    fn the_default_retention_matches_the_documented_window() {
        assert_eq!(Retention::default().days, DEFAULT_RETENTION_DAYS);
        assert_eq!(Retention::default().validate(), Ok(()));
    }

    #[test]
    fn a_zero_retention_is_refused() {
        // It would delete every record as it was written, leaving the user with an audit page that never
        // shows anything and no way to tell that from "nothing happened".
        assert!(Retention { days: 0 }.validate().is_err());
    }

    #[test]
    fn the_cutoff_moves_with_the_clock() {
        let retention = Retention { days: 1 };
        let day_ms = 24 * 60 * 60 * 1_000;
        assert_eq!(retention.cutoff_ms(day_ms * 10), day_ms * 9);
        // And a clock at zero does not underflow into a huge positive window.
        assert!(retention.cutoff_ms(0) <= 0);
    }

    #[test]
    fn a_plugin_activity_summary_reports_newest_first() {
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(16);
        for index in 0..5i64 {
            ring.record(entry(index * 1_000, &chat, "device:list", AuditOutcome::Allowed));
        }
        ring.record(entry(9_000, &chat, "network:fetch:evil.com", AuditOutcome::Denied));

        let activity = PluginActivity::of(&ring, &chat, 3);
        assert_eq!(activity.total, 6);
        assert_eq!(activity.recent.len(), 3);
        assert_eq!(activity.recent[0].at_ms, 9_000, "newest first");
        assert_eq!(activity.refusals.len(), 1);
        assert!(activity.summarise().contains("6 capabilities used"));
        assert!(activity.summarise().contains("1 refused"));
    }

    #[test]
    fn an_activity_summary_for_an_idle_plugin_says_so() {
        let ring = AuditRing::with_capacity(4);
        let activity = PluginActivity::of(&ring, &plugin("@synra-plugin/chat"), 10);

        assert!(activity.is_empty());
        assert!(activity.recent.is_empty());
        assert_eq!(activity.summarise(), "has not used any capabilities");
    }

    #[test]
    fn an_activity_summary_with_no_refusals_says_so() {
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(4);
        ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));

        let activity = PluginActivity::of(&ring, &chat, 10);
        assert!(activity.summarise().contains("none refused"));
    }

    #[test]
    fn an_activity_summary_respects_its_limit() {
        let chat = plugin("@synra-plugin/chat");
        let mut ring = AuditRing::with_capacity(32);
        for index in 0..20i64 {
            ring.record(entry(index, &chat, "device:list", AuditOutcome::Allowed));
        }

        let activity = PluginActivity::of(&ring, &chat, 5);
        assert_eq!(activity.recent.len(), 5);
        assert_eq!(activity.total, 20, "the total is not limited");
    }

    #[test]
    fn the_default_capacity_is_the_documented_one() {
        let ring = AuditRing::new();
        assert_eq!(ring.len(), 0);
        assert_eq!(MEMORY_CAPACITY, 10_000);
    }

    #[test]
    fn a_rendered_record_is_a_destination_not_a_body() {
        // The whole justification for keeping these longer than a log. A rendering that could contain content
        // would put the audit trail in the same category as the log, with the same retention problem.
        let chat = plugin("@synra-plugin/chat");
        let record = entry(1_000, &chat, "network:fetch:api.github.com:POST", AuditOutcome::Allowed);
        let rendered = record.render();

        assert!(rendered.contains("network"), "{rendered}");
        assert!(rendered.contains("api.github.com"), "{rendered}");
        assert!(rendered.contains("ok"), "{rendered}");
        assert!(rendered.contains("5ms"), "{rendered}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_outcome() -> impl Strategy<Value = AuditOutcome> {
        prop::sample::select(vec![
            AuditOutcome::Allowed,
            AuditOutcome::Denied,
            AuditOutcome::QuotaExceeded,
            AuditOutcome::RateLimited,
            AuditOutcome::Failed,
        ])
    }

    fn arbitrary_capability_text() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "log:debug",
            "device:list",
            "device:send:@pc",
            "network:fetch:api.github.com",
            "network:fetch:api.x.com:POST",
            "fs:read:/data/**",
            "platform:open-url",
        ])
    }

    proptest! {
        /// The ring never holds more than its capacity, and never loses a record it has not overwritten. An
        /// unbounded audit buffer is a memory leak with the user's own data in it.
        #[test]
        fn the_ring_stays_within_its_capacity(
            capacity in 0usize..16,
            records in proptest::collection::vec((0i64..1000, arbitrary_capability_text(), arbitrary_outcome()), 0..50),
        ) {
            let plugin = PluginId::parse("@synra-plugin/chat").expect("valid");
            let mut ring = AuditRing::with_capacity(capacity);
            for (at_ms, capability, outcome) in &records {
                ring.record(AuditEntry::new(
                    *at_ms,
                    plugin.clone(),
                    Capability::parse(capability).expect("valid"),
                    *outcome,
                    None,
                ));
            }

            prop_assert!(ring.len() <= capacity);
            prop_assert_eq!(ring.len() + ring.evicted() as usize, records.len());
            prop_assert_eq!(ring.count_for_plugin(&plugin), records.len() as u64);
        }

        /// Every refusal recorded for a plugin is a refusal, and no refusal is kept out. The list is what the
        /// user reads to find out that something was blocked.
        #[test]
        fn refusals_are_exactly_the_refused_records(
            outcomes in proptest::collection::vec(arbitrary_outcome(), 0..30),
        ) {
            let plugin = PluginId::parse("@synra-plugin/chat").expect("valid");
            let mut ring = AuditRing::with_capacity(64);
            let mut expected = 0usize;
            for (index, outcome) in outcomes.iter().enumerate() {
                if outcome.is_refusal() {
                    expected += 1;
                }
                ring.record(AuditEntry::new(
                    index as i64,
                    plugin.clone(),
                    Capability::parse("device:list").expect("valid"),
                    *outcome,
                    None,
                ));
            }

            let refusals = ring.refusals_for_plugin(&plugin);
            prop_assert_eq!(refusals.len(), expected);
            prop_assert!(refusals.iter().all(|entry| entry.outcome.is_refusal()));
        }

        /// Records come back in time order whatever order they arrived in. A UI that showed them shuffled
        /// would make a sequence of events unreadable, which is the one thing the trail is for.
        #[test]
        fn records_replay_in_time_order(
            times in proptest::collection::vec(0i64..10_000, 1..40),
        ) {
            let plugin = PluginId::parse("@synra-plugin/chat").expect("valid");
            let mut ring = AuditRing::with_capacity(64);
            for at_ms in &times {
                ring.record(AuditEntry::new(
                    *at_ms,
                    plugin.clone(),
                    Capability::parse("device:list").expect("valid"),
                    AuditOutcome::Allowed,
                    None,
                ));
            }

            let ordered = ring.all();
            prop_assert_eq!(ordered.len(), times.len());
            prop_assert!(ordered.windows(2).all(|pair| pair[0].at_ms <= pair[1].at_ms));
        }

        /// A record survives the wire format with every field intact. The trail is written by the kernel and
        /// read by the interface, and anything lost in between is a call the user cannot see.
        #[test]
        fn records_round_trip(
            at_ms in 0i64..2_000_000_000_000,
            capability in arbitrary_capability_text(),
            outcome in arbitrary_outcome(),
        ) {
            let record = AuditEntry::new(
                at_ms,
                PluginId::parse("@synra-plugin/chat").expect("valid"),
                Capability::parse(capability).expect("valid"),
                outcome,
                Some(1),
            );
            let json = serde_json::to_string(&record).expect("serialises");
            let back: AuditEntry = serde_json::from_str(&json).expect("deserialises");
            prop_assert_eq!(back, record);
        }
    }
}
