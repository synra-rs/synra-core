//! What a subscriber decided about one event's sequence number, and the tracker that decides it.

use synra_protocol::event::MAX_COUNTED_GAP;
/// What a subscriber decided about one event's sequence number.
///
/// The Rust side of the client library's tracker, and the two have to agree: the library decides what to do with an
/// event it received, and this decides what the kernel and its own diagnostics think. They are separate implementations
/// of one rule, which is why the rule is small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Judgement {
    /// The event follows the last one. Apply it.
    Apply,
    /// It has been seen. Apply nothing.
    IgnoreRepeat,
    /// Something was missed. Re-read, and the count says how much was missed when it is known.
    RefreshSnapshot {
        /// How many events are missing, capped at [`MAX_COUNTED_GAP`].
        ///
        /// `None` when the gap is unknown — a subscriber that attached in the middle of a stream cannot tell how far
        /// back the events it never saw began.
        missed: Option<u32>,
    },
}

/// Tracks sequence numbers for one subscriber.
///
/// # Why this is not the bus
///
/// The bus knows what *it* dropped. This knows what a *consumer* received, which is a different question: the consumer
/// may have received everything the bus sent and still be missing events the bus never saw — the ones from before it
/// subscribed, or from a link that reconnect dropped. A tracker over the received stream is the only thing that
/// answers "is my picture whole".
#[derive(Debug, Clone, Default)]
pub struct SequenceTracker {
    last: Option<u64>,
    gaps: u32,
    stale: bool,
}

impl SequenceTracker {
    /// A tracker that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Judges one sequence number and records it.
    ///
    /// # The three answers, and why `IgnoreRepeat` is not an error
    ///
    /// A channel delivers the same event twice around a reconnect or a reload. Applying it twice is what makes a device
    /// appear once in a list and be fetched twice — so a repeat is refused, and refused *quietly*: it is not a fault,
    /// and a caller that logged one would have a log full of the ordinary case.
    ///
    /// # Why the tracker advances on a refresh request
    ///
    /// An earlier version left the sequence where it was, so every event after a gap was another gap and the interface
    /// could not make progress without a round trip per event. Advancing is the tracker saying "I know where I am; my
    /// picture is incomplete until the snapshot arrives" — which is what the `stale` flag is for.
    pub fn observe(&mut self, seq: u64) -> Judgement {
        let Some(last) = self.last else {
            // The first event, whatever its number. A subscriber that attached mid-stream — a second window, a
            // diagnostic tool — starts here, and calling its first event a gap would make it re-read a snapshot it has
            // just taken.
            self.last = Some(seq);
            return Judgement::Apply;
        };

        if seq <= last {
            return Judgement::IgnoreRepeat;
        }

        let missed = seq - last - 1;
        if missed == 0 {
            self.last = Some(seq);
            return Judgement::Apply;
        }

        self.gaps = self.gaps.saturating_add(1);
        self.stale = true;
        self.last = Some(seq);
        // Capped, because a *reported* count of four billion says nothing and the instruction is the same either way.
        // `None` rather than a capped number when the gap is beyond the cap: reporting `1000` for a gap of four billion
        // would be a number the caller believes.
        let counted = u32::try_from(missed).ok().filter(|missed| *missed <= MAX_COUNTED_GAP);
        Judgement::RefreshSnapshot { missed: counted }
    }

    /// Records that a snapshot arrived, so the picture is whole again.
    pub const fn snapshot_taken(&mut self) {
        self.stale = false;
    }

    /// Whether the picture may be missing something.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.stale
    }

    /// The last sequence number seen.
    #[must_use]
    pub const fn last_seen(&self) -> Option<u64> {
        self.last
    }

    /// How many gaps were noticed.
    #[must_use]
    pub const fn gaps(&self) -> u32 {
        self.gaps
    }

    /// Forgets everything, for a reload.
    ///
    /// The gap count goes too: it is a count of the gaps in *this* stream, and a reloaded interface that carried the
    /// old total would report a number about a stream it is no longer reading.
    pub const fn reset(&mut self) {
        self.last = None;
        self.gaps = 0;
        self.stale = false;
    }
}
