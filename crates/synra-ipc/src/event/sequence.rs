use serde::{Deserialize, Serialize};

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
        Self {
            last: None,
            gaps: 0,
            stale: false,
        }
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
                } else {
                    // A gap of a few is worth counting; a jump of thousands is not, because the count would be a
                    // number nobody reads and the arithmetic could overflow on a hostile value.
                    let missed = seq.saturating_sub(expected);
                    EventVerdict::RefreshSnapshot {
                        missed: if missed <= MAX_COUNTED_GAP {
                            Some(missed)
                        } else {
                            None
                        },
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
        SequenceReport {
            last: self.last,
            gaps: self.gaps,
        }
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
