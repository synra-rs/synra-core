//! What the kernel pushes to the interface, and how the interface notices it missed one.
//!
//! # Commands are requests; events are state changes
//!
//! The design document's second principle for this boundary is that the interface does not poll. It takes a
//! snapshot once and then consumes what changed — which means an event that never arrives is a screen that is
//! quietly wrong until something else happens to refresh it.
//!
//! So every event carries a **monotonic sequence number**, and the interface's job is to notice a gap. That is
//! what [`SequenceTracker`] is: the whole of the mechanism, with no runtime attached, so the arithmetic that
//! decides whether the interface's picture is still trustworthy is testable on its own.
//!
//! # Why the sequence is not the fix, it is the detector
//!
//! A gap cannot be repaired from the events themselves — the missing ones are gone. The only correct response is
//! to ask for a fresh snapshot, and the value of the sequence number is that it turns "the interface is subtly
//! wrong" into "the interface knows to re-read". A tracker that *ignored* a gap would be worse than none, because
//! the gap would still happen and nothing would notice.
//!
//! # Two ways to be out of order
//!
//! * **A gap** — `seq` jumped forward. Events were dropped, by the channel's own back-pressure or by the
//!   interface being busy. The snapshot is stale.
//! * **A repeat** — `seq` is not greater than the last one seen. The channel delivered something twice, which
//!   Tauri's event system can do across a reload. Applying it twice is how a list gets a duplicated row, so a
//!   repeat is *ignored* rather than applied.
//!
//! They need different responses, which is why the tracker distinguishes them rather than reporting "out of
//! order".
//!
//! # The events are the interface's, not the wire's
//!
//! These are not the protocol's `_synra.*` events. Those are between devices, and a plugin's `handles` refers to
//! them. These are the kernel telling *its own interface* what changed, so the set is chosen by what a screen
//! needs rather than by what a peer may send. The names overlap in meaning and not in mechanism: a
//! `_synra.device.changed` arriving from a peer and a [`KernelEvent::DeviceCardUpdated`] are the same fact at two
//! different distances from the user.

use serde::{Deserialize, Serialize};

use crate::dto::{
    DeviceCard, IntentSnapshot, PluginSnapshot, ScanState, TransferSnapshot, UpdateInfo,
};
use synra_protocol::{DeviceId, IntentId, PluginId, RequestId, TransferId};

/// A change the interface should apply.
///
/// Internally tagged with `type`, so the interface's `switch` is exhaustive over a closed set and a variant it
/// does not know is a compile error rather than a case that never runs — except across a version skew, where the
/// `default` branch is what asks for a fresh snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "payload")]
#[non_exhaustive]
pub enum KernelEvent {
    // ── Devices ──
    /// A device card changed. Upsert by `deviceId`.
    DeviceCardUpdated(Box<DeviceCard>),
    /// A device is gone from the list, because it was forgotten or blocked.
    DeviceRemoved {
        /// Which device.
        device_id: DeviceId,
    },
    /// A discovery scan started, progressed or finished.
    ScanUpdated(Box<ScanState>),

    // ── Pairing ──
    /// A device is asking to pair.
    PairingRequested(Box<crate::dto::PairingPrompt>),
    /// A request is no longer pending, because it was answered or it expired.
    PairingResolved {
        /// Which request.
        request_id: RequestId,
    },

    // ── Intent ──
    /// An intent's state changed, including its candidates becoming available.
    IntentUpdated(Box<IntentSnapshot>),
    /// An intent is over, whatever the outcome.
    IntentFinished {
        /// Which intent.
        intent_id: IntentId,
    },

    // ── Configuration ──
    /// The configuration changed, in full.
    ///
    /// Carries the whole snapshot rather than the patch that produced it: the patch is the caller's own input, and a
    /// reader that reassembled the two would be re-deriving what the kernel already knows.
    ConfigUpdated(Box<crate::dto::ConfigSnapshot>),

    // ── Transfers ──
    /// A transfer's progress or state changed.
    TransferUpdated(Box<TransferSnapshot>),
    /// A transfer is over, whatever the outcome.
    TransferFinished {
        /// Which transfer.
        transfer_id: TransferId,
    },

    // ── Plugins ──
    /// A plugin was installed, removed, enabled, disabled or faulted.
    PluginUpdated(Box<PluginSnapshot>),    /// A plugin is being installed, and this much of it has arrived.
    PluginInstallProgress {
        /// Which plugin.
        plugin_id: PluginId,
        /// How far along, from `0` to `1`.
        progress: f64,
        /// What stage it is at, as a message key.
        stage: String,
    },
    /// An update became available for a plugin.
    PluginUpdateAvailable {
        /// Which plugin.
        plugin_id: PluginId,
        /// What is on offer.
        update: Box<UpdateInfo>,
    },
    /// A plugin exceeded its limits and was degraded or disabled.
    PluginHealthChanged {
        /// Which plugin.
        plugin_id: PluginId,
        /// Where it now sits, `snake_case`.
        health: String,
        /// A message key explaining it.
        explanation: String,
    },
    /// A plugin is asking the user to decide on its capabilities.
    PluginConsentRequested {
        /// Which plugin.
        plugin_id: PluginId,
        /// Its name, so the dialog does not need a lookup.
        title: String,
        /// What it is asking for.
        capabilities: Vec<String>,
        /// The digest the decision is recorded against.
        manifest_digest: String,
    },

    // ── Diagnostics ──
    /// A log line worth showing in the interface.
    ///
    /// Separate from `kernel://log`, which is the throttled bulk channel: this is the one or two lines a screen
    /// shows inline, and sending them through the bulk channel would make the screen's content depend on a
    /// throttle.
    LogLine {
        /// The level, `snake_case`.
        level: String,
        /// The already-redacted line.
        line: String,
    },
    /// Something the user should be told about, with nothing to decide.
    Notice {
        /// A message key.
        message: String,
        /// The values the sentence needs.
        params: serde_json::Value,
    },
}

impl KernelEvent {
    /// The `type` a caller branches on, as the wire spells it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::DeviceCardUpdated(_) => "deviceCardUpdated",
            Self::DeviceRemoved { .. } => "deviceRemoved",
            Self::ScanUpdated(_) => "scanUpdated",
            Self::PairingRequested(_) => "pairingRequested",
            Self::PairingResolved { .. } => "pairingResolved",
            Self::IntentUpdated(_) => "intentUpdated",
            Self::IntentFinished { .. } => "intentFinished",
            Self::ConfigUpdated(_) => "configUpdated",
            Self::TransferUpdated(_) => "transferUpdated",
            Self::TransferFinished { .. } => "transferFinished",
            Self::PluginUpdated(_) => "pluginUpdated",
            Self::PluginInstallProgress { .. } => "pluginInstallProgress",
            Self::PluginUpdateAvailable { .. } => "pluginUpdateAvailable",
            Self::PluginHealthChanged { .. } => "pluginHealthChanged",
            Self::PluginConsentRequested { .. } => "pluginConsentRequested",
            Self::LogLine { .. } => "logLine",
            Self::Notice { .. } => "notice",
        }
    }

    /// Whether applying it twice would be wrong.
    ///
    /// A `remove` or a `finish` is idempotent: removing a device that is gone, or finishing a transfer that is
    /// finished, changes nothing. An `update` that carried a *count* would not be, and neither would a progress
    /// event — but those carry absolute values rather than deltas precisely so that a repeat is harmless. So this
    /// reports `false` for everything today, and exists so that a future event carrying a delta has to say so.
    #[must_use]
    pub const fn is_delta(&self) -> bool {
        false
    }
}

/// An event with its position in the sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelEventEnvelope {
    /// Monotonic, incremented by the kernel for every event it publishes.
    pub seq: u64,
    /// When it was published, in milliseconds since the epoch.
    ///
    /// For display and for a diagnostic report, not for ordering: the sequence is what orders, because two events
    /// published in the same millisecond are ordinary and a clock can move.
    pub at: i64,
    /// What changed.
    ///
    /// Flattened, so the interface reads `seq`, `at` and `type` from one object rather than nesting — which is what
    /// makes the tag reachable before the payload is parsed.
    #[serde(flatten)]
    pub event: KernelEvent,
}

/// What the interface should do with an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventVerdict {
    /// Apply it. The sequence is contiguous or this is the first event.
    Apply,
    /// Ignore it. The sequence is not greater than the last one seen, so it is a repeat.
    ///
    /// Applying it would be how a list gets a duplicated row: the channel can deliver the same event twice across a
    /// reload, and a `DeviceCardUpdated` applied twice is a device that appears once and is fetched twice.
    IgnoreRepeat,
    /// Ask for a fresh snapshot. Events were dropped and the picture is stale.
    ///
    /// The gap cannot be repaired from the events themselves — the missing ones are gone.
    RefreshSnapshot {
        /// How many events are unaccounted for, when it can be known.
        ///
        /// Known for a bounded gap and unknown for a jump so large that counting would be meaningless; the count is
        /// for a log line, not for deciding anything.
        missed: Option<u64>,
    },
    /// Apply it *and* ask for a fresh snapshot.
    ///
    /// For an event the interface does not understand. The design document's `default` branch: a kernel that added
    /// a variant should make an older interface re-read rather than crash, and applying what it can while
    /// re-reading is the safest of the two.
    ApplyAndRefresh,
}

/// Tracks the sequence so the interface can tell a gap from a repeat.
///
/// Holds no state beyond the last sequence number, and no runtime: the caller supplies each envelope and acts on
/// the verdict. That is what makes the arithmetic — which is the whole of the mechanism — testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct SequenceTracker {
    last: Option<u64>,
    /// How many gaps have been reported, for a diagnostic report.
    gaps: u32,
    /// Whether a gap has been reported and no snapshot has answered it yet.
    stale: bool,
}

impl SequenceTracker {
    /// A tracker that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None, gaps: 0, stale: false }
    }

    /// The last sequence number applied.
    #[must_use]
    pub const fn last(&self) -> Option<u64> {
        self.last
    }

    /// How many gaps have been reported.
    #[must_use]
    pub const fn gaps(&self) -> u32 {
        self.gaps
    }

    /// Whether the interface's picture is known to be stale.
    ///
    /// True between a reported gap and the snapshot that answers it. A caller that rendered anyway would be
    /// showing what it knows to be wrong.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.stale
    }

    /// Judges an envelope and records it.
    ///
    /// # The first event is not a gap
    ///
    /// A tracker that has seen nothing accepts whatever arrives first. The kernel's own counter starts at one, so
    /// an interface that started mid-stream would otherwise report a gap immediately and re-read a snapshot it had
    /// just taken.
    pub const fn observe(&mut self, seq: u64) -> EventVerdict {
        let verdict = match self.last {
            None => EventVerdict::Apply,
            Some(last) if seq <= last => EventVerdict::IgnoreRepeat,
            Some(last) => {
                let expected = last.saturating_add(1);
                if seq == expected {
                    EventVerdict::Apply
                }
                else {
                    // A gap of a few is worth counting; a jump of thousands is not, because the count would be a
                    // number nobody reads and the arithmetic could overflow on a hostile value.
                    let missed = seq.saturating_sub(expected);
                    EventVerdict::RefreshSnapshot {
                        missed: if missed <= MAX_COUNTED_GAP { Some(missed) } else { None },
                    }
                }
            }
        };

        match verdict {
            // Only an applied event advances the sequence. Advancing on a repeat would make the next contiguous
            // event look like a gap.
            EventVerdict::Apply | EventVerdict::ApplyAndRefresh => self.last = Some(seq),
            EventVerdict::IgnoreRepeat => {}
            EventVerdict::RefreshSnapshot { .. } => {
                // Recorded as seen, because the interface is about to re-read: treating the same gap as new until a
                // snapshot arrives would ask for one per event for as long as the gap lasted.
                self.last = Some(seq);
                self.gaps = self.gaps.saturating_add(1);
                // ★ The picture is now known to be wrong, and it stays wrong until a snapshot answers. Without
                // this the interface would have no way to tell "I missed something" from "I am up to date", and a
                // screen that rendered anyway would be showing what it knows to be stale.
                self.stale = true;
            }
        }
        verdict
    }

    /// Records that a snapshot was taken, so the picture is trustworthy again.
    pub const fn snapshot_taken(&mut self) {
        self.stale = false;
    }

    /// Forgets everything, for an interface that was reloaded.
    ///
    /// The sequence is not persisted across a reload: the interface that comes back takes a snapshot, and a
    /// remembered sequence would make the first event after the reload look like a gap.
    pub const fn reset(&mut self) {
        self.last = None;
        self.stale = false;
    }

    /// A snapshot of the tracker, for a diagnostic report.
    #[must_use]
    pub const fn report(&self) -> SequenceReport {
        SequenceReport { last: self.last, gaps: self.gaps }
    }
}

/// The largest gap worth counting.
///
/// A thousand. A gap larger than that is one where the count is a number nobody reads, and the arithmetic on a
/// hostile value is a subtraction that could overflow.
pub const MAX_COUNTED_GAP: u64 = 1_000;

/// What the tracker has seen, for a diagnostic report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SequenceReport {
    /// The last sequence number applied.
    pub last: Option<u64>,
    /// How many gaps were reported.
    pub gaps: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{IdentitySnapshot, ScanState};

    fn card(id: &str) -> DeviceCard {
        DeviceCard {
            device_id: DeviceId::from_str(id).expect("a valid uuid"),
            display_name: "My PC".to_owned(),
            platform: "linux".to_owned(),
            online: true,
            paired: true,
            blocked: false,
            last_seen_ms: 0,
            address: None,
            transfer: None,
        }
    }

    use core::str::FromStr;

    // ── The sequence ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_first_event_is_applied_rather_than_called_a_gap() {
        // The kernel's counter starts at one, so an interface that started mid-stream would otherwise report a gap
        // immediately and re-read the snapshot it had just taken.
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(1), EventVerdict::Apply);
        assert_eq!(tracker.last(), Some(1));
        assert_eq!(tracker.gaps(), 0);
    }

    #[test]
    fn a_contiguous_event_is_applied() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(7);
        assert_eq!(tracker.observe(8), EventVerdict::Apply);
        assert_eq!(tracker.observe(9), EventVerdict::Apply);
        assert_eq!(tracker.last(), Some(9));
        assert_eq!(tracker.gaps(), 0);
    }

    #[test]
    fn a_gap_asks_for_a_snapshot_and_counts_what_was_missed() {
        // The gap cannot be repaired from the events themselves — the missing ones are gone — so the only correct
        // response is to re-read.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        match tracker.observe(4) {
            EventVerdict::RefreshSnapshot { missed } => assert_eq!(missed, Some(2)),
            other => panic!("expected a snapshot request, got {other:?}"),
        }
        assert_eq!(tracker.gaps(), 1);
    }

    #[test]
    fn a_huge_gap_is_reported_without_a_count() {
        // A jump of thousands gives a number nobody reads, and the subtraction on a hostile value is one that could
        // overflow.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        match tracker.observe(u64::MAX) {
            EventVerdict::RefreshSnapshot { missed } => assert_eq!(missed, None),
            other => panic!("expected a snapshot request, got {other:?}"),
        }
    }

    #[test]
    fn a_repeat_is_ignored() {
        // The channel can deliver the same event twice across a reload, and a `DeviceCardUpdated` applied twice is a
        // device fetched twice.
        let mut tracker = SequenceTracker::new();
        tracker.observe(5);
        assert_eq!(tracker.observe(5), EventVerdict::IgnoreRepeat);
        assert_eq!(tracker.observe(4), EventVerdict::IgnoreRepeat);
        assert_eq!(tracker.observe(1), EventVerdict::IgnoreRepeat);
    }

    #[test]
    fn a_repeat_does_not_advance_the_sequence() {
        // Advancing on a repeat would make the next contiguous event look like a gap, which is a re-read triggered
        // by nothing.
        let mut tracker = SequenceTracker::new();
        tracker.observe(5);
        assert_eq!(tracker.observe(5), EventVerdict::IgnoreRepeat);
        assert_eq!(tracker.last(), Some(5));
        assert_eq!(tracker.observe(6), EventVerdict::Apply);
    }

    #[test]
    fn a_gap_is_counted_once_rather_than_per_event() {
        // The interface is about to re-read, so treating the same gap as new until a snapshot arrives would ask for
        // one per event for as long as the gap lasted.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        tracker.observe(10);
        assert_eq!(tracker.gaps(), 1);

        // The events after the gap are contiguous with it, so they apply.
        assert_eq!(tracker.observe(11), EventVerdict::Apply);
        assert_eq!(tracker.gaps(), 1);
    }

    #[test]
    fn resetting_forgets_the_sequence() {
        // The sequence is not persisted across a reload: the interface that comes back takes a snapshot, and a
        // remembered sequence would make the first event after the reload look like a gap.
        let mut tracker = SequenceTracker::new();
        tracker.observe(100);
        tracker.reset();
        assert_eq!(tracker.last(), None);
        assert_eq!(tracker.observe(1), EventVerdict::Apply);
    }

    #[test]
    fn a_snapshot_makes_the_picture_trustworthy_again() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        tracker.observe(5);
        tracker.snapshot_taken();
        assert_eq!(tracker.report().gaps, 1);
        assert_eq!(tracker.report().last, Some(5));
    }

    #[test]
    fn the_gap_count_saturates() {
        // A wrapping count would make an interface that had lost four billion events look like one that had lost
        // none.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        for _ in 0..3 {
            tracker.observe(tracker.last().expect("seen") + 2);
        }
        assert_eq!(tracker.gaps(), 3);
        assert!(tracker.gaps() < u32::MAX);
    }

    // ── Events ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_event_is_tagged_on_the_wire() {
        // `#[serde(tag = "type", content = "payload")]` is what makes the interface's switch possible: an externally
        // tagged enum would arrive as `{ "DeviceCardUpdated": { … } }`, and a variant name is not a stable wire
        // format.
        let event = KernelEvent::DeviceCardUpdated(Box::new(card("018f2b40-0000-7000-8000-000000000001")));
        let json = serde_json::to_string(&event).expect("serialises");
        assert!(json.contains("\"type\":\"deviceCardUpdated\""), "{json}");
        assert!(json.contains("\"payload\""), "{json}");

        let back: KernelEvent = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, event);
    }

    #[test]
    fn an_event_with_no_payload_carries_only_its_type() {
        let event = KernelEvent::DeviceRemoved {
            device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001").expect("a valid uuid"),
        };
        let json = serde_json::to_string(&event).expect("serialises");
        let back: KernelEvent = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, event);
    }

    #[test]
    fn every_event_has_a_kind_for_a_log_line() {
        for event in [
            KernelEvent::DeviceCardUpdated(Box::new(card("018f2b40-0000-7000-8000-000000000001"))),
            KernelEvent::DeviceRemoved {
                device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001").expect("a valid uuid"),
            },
            KernelEvent::ScanUpdated(Box::new(ScanState {
                scan_id: "s1".to_owned(),
                elapsed_ms: 100,
                total_ms: 2_500,
                found: 3,
            })),
            KernelEvent::PairingResolved { request_id: RequestId::new() },
            KernelEvent::TransferFinished { transfer_id: TransferId::new() },
            KernelEvent::IntentFinished { intent_id: IntentId::new() },
            KernelEvent::PluginInstallProgress {
                plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
                progress: 0.5,
                stage: "verifying".to_owned(),
            },
            KernelEvent::PluginHealthChanged {
                plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
                health: "degraded".to_owned(),
                explanation: "plugin.health.degraded".to_owned(),
            },
            KernelEvent::PluginConsentRequested {
                plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
                title: "Chat".to_owned(),
                capabilities: vec!["log:*".to_owned()],
                manifest_digest: "d".to_owned(),
            },
            KernelEvent::LogLine { level: "warn".to_owned(), line: "x".to_owned() },
            KernelEvent::Notice {
                message: "notice.something".to_owned(),
                params: serde_json::json!({}),
            },
        ] {
            let kind = event.kind();
            assert!(!kind.is_empty(), "{event:?}");
            assert!(!kind.contains('_'), "{kind} is not camelCase");
            // The kind is what the wire tag says, which is what makes it usable as the switch key.
            let json = serde_json::to_value(&event).expect("serialises");
            assert_eq!(json["type"], kind, "{event:?}");
        }
    }

    #[test]
    fn no_event_carries_a_delta() {
        // Every event today carries an absolute value, so applying one twice changes nothing. `is_delta` exists so a
        // future event carrying a delta has to say so rather than being mistaken for an idempotent one.
        let event = KernelEvent::PluginInstallProgress {
            plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
            progress: 0.5,
            stage: "downloading".to_owned(),
        };
        assert!(!event.is_delta());
        // The progress is a fraction rather than a byte count, which is what makes the repeat harmless.
        let json = serde_json::to_value(&event).expect("serialises");
        assert_eq!(json["payload"]["progress"], 0.5);
    }

    #[test]
    fn an_event_an_older_interface_does_not_know_fails_to_parse() {
        // Which is the case the interface's `default` branch handles: it catches the parse failure, re-reads a
        // snapshot and keeps working. A kernel that added a variant must not break an interface that predates it.
        let json = r#"{ "type": "somethingNew", "payload": { "x": 1 } }"#;
        assert!(serde_json::from_str::<KernelEvent>(json).is_err());
    }

    #[test]
    fn an_event_an_older_interface_does_not_know_still_has_a_readable_type() {
        // The interface reads the tag before it parses the payload, so an unknown type is a *known* unknown rather
        // than a syntax error — which is what lets the `default` branch tell "newer kernel" from "corrupt channel".
        let json: serde_json::Value = serde_json::from_str(r#"{ "type": "somethingNew" }"#).expect("valid json");
        assert_eq!(json["type"], "somethingNew");
    }

    // ── The envelope ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_envelope_flattens_the_event() {
        // `#[serde(flatten)]` so the interface reads `seq`, `at` and `type` from one object rather than nesting.
        let envelope = KernelEventEnvelope {
            seq: 1,
            at: 1_000,
            event: KernelEvent::DeviceRemoved {
                device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001").expect("a valid uuid"),
            },
        };
        let json = serde_json::to_string(&envelope).expect("serialises");
        assert!(json.contains("\"seq\":1"), "{json}");
        assert!(json.contains("\"at\":1000"), "{json}");
        assert!(json.contains("\"type\":\"deviceRemoved\""), "{json}");

        let back: KernelEventEnvelope = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, envelope);
    }

    #[test]
    fn an_envelope_can_be_judged_by_its_sequence() {
        // The shape the interface actually uses: read the sequence, decide, then apply.
        let envelope = KernelEventEnvelope {
            seq: 9,
            at: 0,
            event: KernelEvent::LogLine { level: "info".to_owned(), line: "x".to_owned() },
        };
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        assert!(matches!(tracker.observe(envelope.seq), EventVerdict::RefreshSnapshot { .. }));
    }

    #[test]
    fn a_scan_event_round_trips() {
        let event = KernelEvent::ScanUpdated(Box::new(ScanState {
            scan_id: "s1".to_owned(),
            elapsed_ms: 100,
            total_ms: 2_500,
            found: 3,
        }));
        let json = serde_json::to_string(&event).expect("serialises");
        let back: KernelEvent = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, event);
    }

    #[test]
    fn an_identity_is_not_an_event() {
        // The identity is part of the devices snapshot, not a thing that changes on its own — and an event for it
        // would be a second way for the interface to learn the same fact.
        let snapshot = IdentitySnapshot {
            device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001").expect("a valid uuid"),
            display_name: "Laptop".to_owned(),
            platform: "linux".to_owned(),
            kernel_version: "0".to_owned(),
            name_is_default: true,
        };
        let json = serde_json::to_string(&snapshot).expect("serialises");
        assert!(!json.contains("\"type\""), "{json}");
    }

    #[test]
    fn a_report_carries_what_a_diagnostic_bundle_needs() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        tracker.observe(3);
        let report = tracker.report();
        assert_eq!(report.last, Some(3));
        assert_eq!(report.gaps, 1);

        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("gaps"), "{json}");
        let back: SequenceReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Whatever sequence of numbers is observed, the last one recorded is never less than any applied one, and
        /// a repeat is never applied. The property is what stops a duplicated event from being applied twice, which
        /// is how a list gets a row it renders once and fetches twice.
        #[test]
        fn a_repeat_is_never_applied(sequences in proptest::collection::vec(0u64..50, 0..200)) {
            let mut tracker = SequenceTracker::new();
            let mut last_applied: Option<u64> = None;

            for seq in sequences {
                let verdict = tracker.observe(seq);
                match verdict {
                    EventVerdict::Apply | EventVerdict::ApplyAndRefresh => {
                        if let Some(previous) = last_applied {
                            prop_assert!(seq > previous, "applied {} after {}", seq, previous);
                        }
                        last_applied = Some(seq);
                    }
                    EventVerdict::IgnoreRepeat => {
                        if let Some(previous) = last_applied {
                            prop_assert!(seq <= previous, "called {} a repeat after {}", seq, previous);
                        }
                    }
                    EventVerdict::RefreshSnapshot { .. } => {
                        if let Some(previous) = last_applied {
                            prop_assert!(seq > previous + 1, "called {} a gap after {}", seq, previous);
                        }
                        last_applied = Some(seq);
                    }
                }
            }
        }

        /// The tracker never records a sequence lower than one it has already recorded. A tracker that went
        /// backwards would then treat every subsequent event as a repeat and the interface would stop updating.
        #[test]
        fn the_recorded_sequence_never_decreases(sequences in proptest::collection::vec(any::<u64>(), 0..100)) {
            let mut tracker = SequenceTracker::new();
            let mut previous = 0u64;
            for seq in sequences {
                let _ = tracker.observe(seq);
                if let Some(last) = tracker.last() {
                    prop_assert!(last >= previous, "went from {} to {}", previous, last);
                    previous = last;
                }
            }
        }

        /// A gap is reported once, and the next contiguous event after it applies. A tracker that kept reporting
        /// the same gap would ask for a snapshot per event for as long as the gap lasted.
        #[test]
        fn a_gap_is_not_reported_twice_for_the_same_jump(
            first in 1u64..100,
            jump in 1u64..1_000,
        ) {
            let mut tracker = SequenceTracker::new();
            prop_assert_eq!(tracker.observe(first), EventVerdict::Apply);

            let second = first.saturating_add(jump);
            // Bound first: a `matches!` with a `{ .. }` pattern cannot be a `prop_assert!` message, because proptest
            // builds the message with `format!` and the braces are read as a format argument.
            let verdict = tracker.observe(second);

            if jump == 1 {
                // Contiguous, so it applies and there is no gap to report twice.
                prop_assert_eq!(verdict, EventVerdict::Apply);
            }
            else {
                prop_assert!(matches!(verdict, EventVerdict::RefreshSnapshot { .. }), "{:?}", verdict);
                // The event after the gap is contiguous *with the gap*, so it applies rather than re-reporting.
                if let Some(next) = second.checked_add(1) {
                    let after = tracker.observe(next);
                    prop_assert_eq!(after, EventVerdict::Apply, "the gap was re-reported");
                }
            }
        }

        /// Observing is total, whatever the numbers. The sequence comes from another process, and an interface that
        /// panicked on a strange value would be one a kernel could stop with a single event.
        #[test]
        fn observing_is_total(sequences in proptest::collection::vec(any::<u64>(), 0..200)) {
            let mut tracker = SequenceTracker::new();
            for seq in sequences {
                let _ = tracker.observe(seq);
            }
            let _ = tracker.report();
            let _ = tracker.is_stale();
        }
    }
}
