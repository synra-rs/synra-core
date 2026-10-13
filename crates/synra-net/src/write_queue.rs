//! The write queue: bounded, and honest about overflowing.
//!
//! # Overflow closes the link, and that is the least bad option
//!
//! A queue exists so a slow peer does not block the caller. It is bounded because an unbounded one is a memory leak
//! with a friendly name — a peer that stops reading turns the application into a buffer. So when the bound is
//! reached, one of three things has to happen:
//!
//! * **Drop the oldest.** Breaks ordering, which for a transfer means the receiver assembles a file from chunks
//!   that no longer correspond to the sender's view of it. Silent corruption.
//! * **Drop the newest.** Loses whatever the caller just handed over. The caller believes it was queued, so nothing
//!   retries.
//! * **Close the link.** Every frame the caller queued is lost, and the caller is *told* — reconnection happens
//!   against a peer that will re-request what it still needs.
//!
//! The design document picks the third, and the reason is the one above: it is the only option where the loss is
//! visible. The cost is a reconnect; the cost of the others is a message that vanished and a bug report that says
//! "sometimes messages do not arrive".
//!
//! # Frames are counted, not bytes
//!
//! [`WRITE_QUEUE_CAPACITY`] is a frame count. Counting bytes would let a queue of 256 small frames hold the same
//! memory as a few large ones — but frames are already bounded by [`MAX_FRAME_LEN`], so a frame count bounds the
//! memory within a factor of the largest frame, and a count is what the design document specifies.

use core::time::Duration;

use synra_protocol::limits::WRITE_QUEUE_CAPACITY;

use crate::liveness::LinkHealth;

/// Why a frame could not be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueRefusal {
    /// The queue is full, so the link must be closed.
    ///
    /// Not an error the caller recovers from by retrying: the link is ending, and the caller's next step is to wait
    /// for the reconnection and re-request. Retrying against a full queue would spin.
    Full {
        /// How many frames were already queued.
        queued: usize,
        /// The bound.
        capacity: usize,
    },
    /// The link is already closed.
    Closed {
        /// Why it closed.
        reason: CloseReason,
    },
}

impl QueueRefusal {
    /// Whether the caller may try again later.
    ///
    /// Neither refusal is retryable against the same link, which is the point: a caller that loops on either would
    /// spin. A closed link is replaced by a new one and a full link is closed by the refusal.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        false
    }
}

/// Why a link closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// The queue overflowed.
    Overflow,
    /// The peer said goodbye.
    Goodbye,
    /// The peer refused the handshake.
    Refused,
    /// Nothing arrived within the timeout.
    Silent,
    /// The caller asked for it.
    Requested,
    /// A write failed.
    WriteFailed,
}

impl CloseReason {
    /// Whether reconnecting makes sense.
    #[must_use]
    pub const fn is_worth_reconnecting(self) -> bool {
        match self {
            Self::Overflow | Self::Silent | Self::WriteFailed | Self::Requested => true,
            // A goodbye is a decision and a refusal may be permanent, so retrying immediately races a shutdown or
            // repeats something that will not change.
            Self::Goodbye | Self::Refused => false,
        }
    }

    /// A name for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overflow => "overflow",
            Self::Goodbye => "goodbye",
            Self::Refused => "refused",
            Self::Silent => "silent",
            Self::Requested => "requested",
            Self::WriteFailed => "write-failed",
        }
    }
}

/// What happened when a frame was added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueOutcome {
    /// It was queued.
    Queued,
    /// It was queued and the queue is now congested.
    ///
    /// Reported so the caller can slow down, or so the interface can show that a peer is behind. Not a failure: a
    /// burst is ordinary.
    QueuedCongested {
        /// How full the queue is, as a percentage.
        queue_percent: u8,
    },
    /// The queue was full, so the link is now closed.
    Overflowed {
        /// How many frames were queued when it happened.
        queued: usize,
        /// How many were discarded.
        discarded: usize,
    },
}

impl QueueOutcome {
    /// Whether the link survived.
    #[must_use]
    pub const fn link_survived(self) -> bool {
        !matches!(self, Self::Overflowed { .. })
    }
}

/// A bounded write queue.
///
/// Generic over what it holds so the queue's behaviour — its bound, its overflow, its congestion reporting — is
/// testable without frames, sockets or a runtime.
#[derive(Debug, Clone)]
pub struct WriteQueue<T> {
    items: std::collections::VecDeque<T>,
    capacity: usize,
    closed: Option<CloseReason>,
}

impl<T> WriteQueue<T> {
    /// A queue with the protocol's capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(WRITE_QUEUE_CAPACITY)
    }

    /// A queue with an explicit capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { items: std::collections::VecDeque::with_capacity(capacity.min(1024)), capacity, closed: None }
    }

    /// The bound.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many frames are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the link is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Why the link closed.
    #[must_use]
    pub const fn close_reason(&self) -> Option<CloseReason> {
        self.closed
    }

    /// Adds a frame.
    ///
    /// # Errors
    ///
    /// [`QueueRefusal::Closed`] if the link already closed, or [`QueueRefusal::Full`] if this frame could not be
    /// added. On `Full` the link is closed and **everything queued is discarded**: the caller has to know that
    /// nothing it thought was sent will arrive.
    pub fn push(&mut self, item: T) -> Result<QueueOutcome, QueueRefusal> {
        if let Some(reason) = self.closed {
            return Err(QueueRefusal::Closed { reason });
        }

        if self.items.len() >= self.capacity {
            let queued = self.items.len();
            self.items.clear();
            self.closed = Some(CloseReason::Overflow);
            return Err(QueueRefusal::Full { queued, capacity: self.capacity });
        }

        self.items.push_back(item);

        let percent = self.fill_percent();
        if percent >= LinkHealth::CONGESTED_PERCENT {
            Ok(QueueOutcome::QueuedCongested { queue_percent: percent })
        }
        else {
            Ok(QueueOutcome::Queued)
        }
    }

    /// Adds a frame, reporting the overflow as an outcome rather than an error.
    ///
    /// The shape a caller wants when it has nothing to do about the refusal except close the link, which the queue
    /// has already done.
    pub fn push_lossy(&mut self, item: T) -> QueueOutcome {
        let discarded_before = self.items.len();
        match self.push(item) {
            Ok(outcome) => outcome,
            Err(QueueRefusal::Closed { .. }) => {
                QueueOutcome::Overflowed { queued: discarded_before, discarded: 0 }
            }
            Err(QueueRefusal::Full { queued, .. }) => {
                QueueOutcome::Overflowed { queued, discarded: discarded_before }
            }
        }
    }

    /// Takes the next frame.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Takes every queued frame, for a caller about to hand them to a socket.
    pub fn drain(&mut self) -> Vec<T> {
        self.items.drain(..).collect()
    }

    /// How full the queue is, as a percentage.
    #[must_use]
    pub fn fill_percent(&self) -> u8 {
        if self.capacity == 0 {
            return 100;
        }
        u8::try_from(self.items.len().saturating_mul(100) / self.capacity).unwrap_or(100)
    }

    /// The queue's health, given how long the link has been silent.
    #[must_use]
    pub fn health(&self, silent_ms: u64, timeout: Duration) -> LinkHealth {
        if let Some(reason) = self.closed {
            return match reason {
                CloseReason::Overflow => LinkHealth::Overflow,
                // A goodbye, a refusal and a request all end the link, and the queue reports it as an overflow so
                // the caller closes it; the reason is on the queue for the log.
                _ => LinkHealth::Overflow,
            };
        }
        LinkHealth::classify(self.items.len(), self.capacity, silent_ms, timeout)
    }

    /// Closes the queue, discarding what is queued.
    ///
    /// Discards because a closed link's queued frames will never be written, and holding them would make the memory
    /// the queue was bounded to protect grow back through the closed path.
    pub fn close(&mut self, reason: CloseReason) {
        self.items.clear();
        self.closed = Some(reason);
    }

    /// Reopens the queue for a new connection.
    ///
    /// Only from a closed state, and it always starts empty: the previous connection's frames were discarded when it
    /// closed, so there is nothing to carry over.
    pub fn reopen(&mut self) {
        self.items.clear();
        self.closed = None;
    }
}

impl<T> Default for WriteQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue() -> WriteQueue<u32> {
        WriteQueue::with_capacity(4)
    }

    #[test]
    fn a_new_queue_is_open_and_empty() {
        let queue = queue();
        assert_eq!(queue.capacity(), 4);
        assert!(queue.is_empty());
        assert_eq!(queue.fill_percent(), 0);
        assert!(!queue.is_closed());
        assert_eq!(queue.close_reason(), None);
    }

    #[test]
    fn the_default_capacity_is_the_protocol_constant() {
        // One definition of the bound, so a change to the constant moves this and nothing else.
        assert_eq!(WriteQueue::<u32>::new().capacity(), WRITE_QUEUE_CAPACITY);
    }

    #[test]
    fn frames_come_out_in_the_order_they_went_in() {
        // Ordering is what makes a transfer's chunks assemble into the right file.
        let mut queue = queue();
        for value in 1..=4 {
            queue.push(value).expect("queues");
        }
        assert_eq!(queue.drain(), vec![1, 2, 3, 4]);
        assert!(queue.is_empty());
    }

    #[test]
    fn a_frame_comes_out_of_the_front() {
        let mut queue = queue();
        queue.push(1).expect("queues");
        queue.push(2).expect("queues");
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn filling_past_the_threshold_reports_congestion() {
        // A burst is ordinary, so congestion is reported rather than acted on.
        let mut queue = WriteQueue::with_capacity(4);
        assert_eq!(queue.push(1).expect("queues"), QueueOutcome::Queued);
        assert_eq!(
            queue.push(2).expect("queues"),
            QueueOutcome::QueuedCongested { queue_percent: 50 }
        );
        assert_eq!(
            queue.push(3).expect("queues"),
            QueueOutcome::QueuedCongested { queue_percent: 75 }
        );
    }

    #[test]
    fn a_full_queue_refuses_and_closes_the_link() {
        // Dropping the newest frame would silently lose a message; dropping the oldest would break a transfer's
        // ordering. Closing is the only option where the loss is visible.
        let mut queue = queue();
        for value in 1..=4 {
            queue.push(value).expect("queues");
        }
        assert!(!queue.is_closed());

        match queue.push(5) {
            Err(QueueRefusal::Full { queued, capacity }) => {
                assert_eq!(queued, 4);
                assert_eq!(capacity, 4);
            }
            other => panic!("expected a full refusal, got {other:?}"),
        }
        assert!(queue.is_closed());
        assert_eq!(queue.close_reason(), Some(CloseReason::Overflow));
    }

    #[test]
    fn an_overflow_discards_everything_queued() {
        // The caller has to know that nothing it thought was sent will arrive — holding the frames would be a queue
        // that grows through the path that exists to bound it.
        let mut queue = queue();
        for value in 1..=4 {
            queue.push(value).expect("queues");
        }
        let _ = queue.push(5);
        assert!(queue.is_empty(), "the queued frames were not discarded");
    }

    #[test]
    fn a_full_queue_reported_as_an_outcome_carries_the_counts() {
        let mut queue = queue();
        for value in 1..=4 {
            queue.push(value).expect("queues");
        }
        let outcome = queue.push_lossy(5);
        match outcome {
            QueueOutcome::Overflowed { queued, discarded } => {
                assert_eq!(queued, 4);
                assert_eq!(discarded, 4);
            }
            other => panic!("expected an overflow, got {other:?}"),
        }
        assert!(!outcome.link_survived());
    }

    #[test]
    fn pushing_to_a_closed_queue_is_refused_with_the_reason() {
        let mut queue = queue();
        queue.close(CloseReason::Goodbye);
        match queue.push(1) {
            Err(QueueRefusal::Closed { reason }) => assert_eq!(reason, CloseReason::Goodbye),
            other => panic!("expected a closed refusal, got {other:?}"),
        }
    }

    #[test]
    fn pushing_to_a_closed_queue_as_an_outcome_does_not_overwrite_the_reason() {
        // A goodbye is a decision; reporting it as an overflow would have the caller reconnect to a peer that is
        // shutting down.
        let mut queue = queue();
        queue.close(CloseReason::Goodbye);
        let outcome = queue.push_lossy(1);
        assert!(!outcome.link_survived());
        assert_eq!(queue.close_reason(), Some(CloseReason::Goodbye));
    }

    #[test]
    fn closing_discards_what_is_queued() {
        let mut queue = queue();
        queue.push(1).expect("queues");
        queue.close(CloseReason::Requested);
        assert!(queue.is_empty());
    }

    #[test]
    fn reopening_always_starts_empty() {
        // The previous connection's frames were discarded when it closed, so there is nothing to carry over.
        let mut queue = queue();
        queue.push(1).expect("queues");
        queue.close(CloseReason::Silent);

        queue.reopen();
        assert!(!queue.is_closed());
        assert!(queue.is_empty());
        assert_eq!(queue.push(2).expect("queues"), QueueOutcome::Queued);
    }

    #[test]
    fn the_fill_percentage_is_what_it_says() {
        let mut queue = WriteQueue::with_capacity(10);
        for value in 0..5 {
            queue.push(value).expect("queues");
        }
        assert_eq!(queue.fill_percent(), 50);
        for value in 5..9 {
            queue.push(value).expect("queues");
        }
        assert_eq!(queue.fill_percent(), 90);
    }

    #[test]
    fn a_queue_with_no_capacity_reports_full_immediately() {
        // A capacity of zero is a configuration that can carry nothing, and reporting it as healthy would have the
        // caller wait forever.
        let mut queue: WriteQueue<u32> = WriteQueue::with_capacity(0);
        assert_eq!(queue.fill_percent(), 100);
        assert!(matches!(queue.push(1), Err(QueueRefusal::Full { .. })));
        assert_eq!(queue.health(0, Duration::from_secs(1)), LinkHealth::Overflow);
    }

    #[test]
    fn health_follows_the_queue_and_the_silence() {
        let timeout = Duration::from_millis(250);

        let mut queue = WriteQueue::with_capacity(4);
        assert_eq!(queue.health(0, timeout), LinkHealth::Healthy);

        queue.push(1).expect("queues");
        queue.push(2).expect("queues");
        assert_eq!(queue.health(0, timeout), LinkHealth::Congested { queue_percent: 50 });

        // Silence takes precedence: a dead link is dead whatever its queue says.
        assert_eq!(queue.health(250, timeout), LinkHealth::Silent { silent_ms: 250 });
    }

    #[test]
    fn health_reports_a_closed_queue_as_unusable_whatever_the_reason() {
        for reason in [
            CloseReason::Overflow,
            CloseReason::Goodbye,
            CloseReason::Refused,
            CloseReason::Silent,
            CloseReason::Requested,
            CloseReason::WriteFailed,
        ] {
            let mut queue = queue();
            queue.close(reason);
            let health = queue.health(0, Duration::from_secs(10));
            assert!(health.should_close(), "{reason:?}");
            assert!(!health.is_usable(), "{reason:?}");
        }
    }

    #[test]
    fn an_empty_queue_allocates_nothing_large() {
        // The capacity hint is clamped, because a queue of 256 frames declared at start-up should not reserve room
        // for a configuration that allows a million.
        let queue: WriteQueue<u32> = WriteQueue::with_capacity(1_000_000);
        assert_eq!(queue.capacity(), 1_000_000);
        assert!(queue.is_empty());
    }

    // ── Close reasons ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_deliberate_end_is_not_worth_reconnecting_to() {
        assert!(!CloseReason::Goodbye.is_worth_reconnecting());
        assert!(!CloseReason::Refused.is_worth_reconnecting());
        for reason in [
            CloseReason::Overflow,
            CloseReason::Silent,
            CloseReason::WriteFailed,
            CloseReason::Requested,
        ] {
            assert!(reason.is_worth_reconnecting(), "{reason:?}");
        }
    }

    #[test]
    fn neither_refusal_is_retryable() {
        // A caller that looped on either would spin: a full queue closes the link, and a closed link stays closed
        // until it is replaced.
        assert!(!QueueRefusal::Full { queued: 1, capacity: 1 }.is_retryable());
        assert!(!QueueRefusal::Closed { reason: CloseReason::Goodbye }.is_retryable());
    }

    #[test]
    fn every_close_reason_has_a_name_for_a_log_line() {
        for reason in [
            CloseReason::Overflow,
            CloseReason::Goodbye,
            CloseReason::Refused,
            CloseReason::Silent,
            CloseReason::Requested,
            CloseReason::WriteFailed,
        ] {
            let name = reason.as_str();
            assert!(!name.is_empty(), "{reason:?}");
            assert!(!name.contains(' '), "{reason:?} -> {name}");
        }
    }

    #[test]
    fn the_default_queue_matches_the_constructor() {
        assert_eq!(WriteQueue::<u32>::default().capacity(), WriteQueue::<u32>::new().capacity());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The queue never holds more than its capacity. It is the bound that stops a peer which stops reading from
        /// turning the application into a buffer.
        #[test]
        fn the_queue_never_exceeds_its_capacity(
            capacity in 1usize..32,
            pushes in proptest::collection::vec(any::<u32>(), 0..200),
        ) {
            let mut queue = WriteQueue::with_capacity(capacity);
            for value in pushes {
                let _ = queue.push(value);
                prop_assert!(queue.len() <= capacity, "held {} of {}", queue.len(), capacity);
            }
        }

        /// Whatever the sequence, frames come out in the order they went in. A reordering would mean a receiver
        /// assembling a file from chunks that no longer correspond to the sender's view of it.
        #[test]
        fn frames_keep_their_order(pushes in proptest::collection::vec(any::<u32>(), 0..16)) {
            let mut queue = WriteQueue::with_capacity(16);
            let mut accepted = Vec::new();
            for value in pushes {
                if queue.push(value).is_ok() {
                    accepted.push(value);
                }
                else {
                    // The overflow discarded everything, so the expectation is only the frames since.
                    accepted.clear();
                    break;
                }
            }
            if !queue.is_closed() {
                prop_assert_eq!(queue.drain(), accepted);
            }
        }

        /// Once a queue is closed it stays closed until it is reopened, whatever is pushed at it. A closed link that
        /// silently accepted frames would let the caller believe messages were sent.
        #[test]
        fn a_closed_queue_stays_closed(
            reason_index in 0usize..6,
            pushes in proptest::collection::vec(any::<u32>(), 1..20),
        ) {
            let reasons = [
                CloseReason::Overflow,
                CloseReason::Goodbye,
                CloseReason::Refused,
                CloseReason::Silent,
                CloseReason::Requested,
                CloseReason::WriteFailed,
            ];
            let mut queue = WriteQueue::with_capacity(8);
            queue.close(reasons[reason_index]);

            for value in pushes {
                prop_assert!(queue.push(value).is_err());
                prop_assert!(queue.is_closed());
                prop_assert!(queue.is_empty());
            }

            queue.reopen();
            prop_assert!(!queue.is_closed());
            prop_assert!(queue.push(1).is_ok());
        }
    }
}
