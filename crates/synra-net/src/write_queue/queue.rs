use core::time::Duration;

use synra_protocol::limits::WRITE_QUEUE_CAPACITY;

use crate::liveness::LinkHealth;

use super::{CloseReason, QueueOutcome, QueueRefusal};

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
