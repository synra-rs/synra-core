//! A subscriber's identity, what it is told about its own queue, and what it reads.
/// How many events one subscriber's queue holds.
///
/// The same figure as the protocol's write queue, and for the same reason: an interface that is a quarter of a second
/// behind on a busy kernel is fine, and one that is a minute behind is one that should re-read a snapshot instead. Two
/// hundred and fifty-six events is seconds of ordinary activity and kilobytes of memory.
pub const SUBSCRIBER_QUEUE_CAPACITY: usize = 256;

/// A subscriber's identity, as the bus issued it.
///
/// Opaque and `Copy`: a caller holds it to unsubscribe and to read that subscriber's report, and a caller that
/// constructed one would be able to read another subscriber's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriberId(pub(super) u64);

impl SubscriberId {
    /// The number, for a log line or a report.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sub{}", self.0)
    }
}

/// What a subscriber is told about its own queue.
///
/// # Why `dropped` is separate from `missed`
///
/// `dropped` is what *this bus* threw away because this subscriber was slow — the bus's own decision, and one it can
/// report precisely. `missed` is the gap a subscriber computes from the sequence numbers it received, which counts
/// everything that did not arrive, whatever the reason. They are equal in the ordinary case and diverge when something
/// else lost events, and a diagnostic that conflated them would blame the queue for a socket's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscriberReport {
    /// How many events were dropped from this subscriber's queue because it was full.
    pub dropped: u64,
    /// How many events it has been handed.
    pub delivered: u64,
    /// How many are waiting.
    pub queued: usize,
    /// Whether its queue has overflowed at least once since the last reset.
    pub overflowed: bool,
}

impl SubscriberReport {
    /// Whether this subscriber is keeping up.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        !self.overflowed
    }

    /// A sentence for a log line or a diagnostic bundle.
    #[must_use]
    pub fn explain(&self) -> String {
        if self.overflowed {
            format!(
                "dropped {} of {} event(s); {} waiting — the subscriber is slower than the kernel and should re-read a \
                 snapshot",
                self.dropped,
                self.delivered + self.dropped,
                self.queued,
            )
        }
        else {
            format!("delivered {} event(s), none dropped, {} waiting", self.delivered, self.queued)
        }
    }
}

/// What a subscriber learns when it reads its queue.
///
/// # Why the gap is reported rather than the events alone
///
/// A caller that received `[7, 8, 9]` after `5` has no way to tell from those three that 6 is missing — the sequence
/// numbers are there, but checking them is exactly the bookkeeping every subscriber would have to redo. The bus knows
/// what it threw away, so it says.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery<E> {
    /// The events that were waiting, in sequence order.
    ///
    /// Empty when nothing was waiting, which is the ordinary case for a subscriber that is keeping up: it reads after
    /// each notification and finds one event.
    Events {
        /// The events that were waiting, oldest first.
        events: Vec<E>,
        /// The sequence number of the **first** of them. The rest follow it: a queue is contiguous, so `first_seq + i`
        /// is the number of `events[i]`. Zero when there are none.
        first_seq: u64,
    },
    /// Events were waiting, and the subscriber is **behind**: it has to re-read a snapshot.
    ///
    /// The events that survived are carried anyway. They are not sufficient — the subscriber cannot apply them to a
    /// picture with a hole in it — but they are what it has, and discarding them would make a diagnostic that wanted
    /// only the sequence numbers do a second round trip.
    Behind {
        /// The events that survived the overflow, oldest first.
        events: Vec<E>,
        /// The sequence number of the first survivor. The events before it are the ones that were dropped.
        first_seq: u64,
        /// How many were dropped from this subscriber's queue.
        missed: u64,
    },
}

impl<E> Delivery<E> {
    /// The events, whichever shape the delivery has.
    #[must_use]
    pub fn events(&self) -> &[E] {
        match self {
            Self::Events { events, .. } | Self::Behind { events, .. } => events,
        }
    }

    /// The sequence number of the first event in the batch.
    ///
    /// # Why this is here rather than a number per event
    ///
    /// Because a queue is contiguous: the events in a batch were emitted one after the other, so their numbers are
    /// `first_seq + i`. A per-event number would be the same information, larger, and would still need `missed` to
    /// place the gap — which is what this and [`Self::missed`] already do together.
    ///
    /// Zero only when the batch is empty, which a caller that received a delivery will not see.
    #[must_use]
    pub const fn first_seq(&self) -> u64 {
        match self {
            Self::Events { first_seq, .. } | Self::Behind { first_seq, .. } => *first_seq,
        }
    }

    /// How many events were dropped, if any.
    #[must_use]
    pub const fn missed(&self) -> u64 {
        match self {
            Self::Behind { missed, .. } => *missed,
            Self::Events { .. } => 0,
        }
    }

    /// Whether the subscriber has to re-read.
    #[must_use]
    pub const fn must_refresh(&self) -> bool {
        matches!(self, Self::Behind { .. })
    }
}
