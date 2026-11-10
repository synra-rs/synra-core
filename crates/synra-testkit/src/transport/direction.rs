use bytes::Bytes;
use synra_protocol::frame::{Frame, FrameBody, FrameKind};

use super::{Fault, TransportError};

/// One direction of an in-memory link.
#[derive(Debug)]
pub(super) struct Direction {
    queue: parking_lot::Mutex<std::collections::VecDeque<Frame>>,
    capacity: usize,
    /// The next fault to apply, if any.
    pub(super) fault: parking_lot::Mutex<Option<Fault>>,
    /// How many frames have been sent, for a test asserting about a retry.
    pub(super) sent: parking_lot::Mutex<u64>,
    /// How many were dropped, so a test can assert its fault actually fired.
    pub(super) dropped: parking_lot::Mutex<u64>,
}

impl Direction {
    #[allow(clippy::missing_const_for_fn)]
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            capacity,
            fault: parking_lot::Mutex::new(None),
            sent: parking_lot::Mutex::new(0),
            dropped: parking_lot::Mutex::new(0),
        }
    }

    pub(super) fn send(&self, frame: Frame) -> Result<(), TransportError> {
        let fault = self.fault.lock().take();
        self.bump_sent();

        match fault {
            Some(Fault::DropNext) => {
                self.bump_dropped();
                return Err(TransportError::Dropped);
            }
            Some(Fault::Cut) => return Err(TransportError::Closed),
            Some(Fault::Silence(_)) => return Err(TransportError::Silent),
            Some(Fault::DuplicateNext) => {
                // Queued twice, which is what the receiving side's deduplication has to handle.
                self.push_twice(frame)?;
                return Ok(());
            }
            Some(Fault::CorruptNext) => {
                // A frame whose body is not the JSON it claims to be. The decoder's structural check is what refuses
                // it, and the point of the fault is that the *receiver* notices rather than the transport.
                let corrupt = Frame {
                    kind: FrameKind::Envelope,
                    flags: 0,
                    body: FrameBody::Envelope(Bytes::from_static(b"{\"event\":\"device.ping\"")),
                };
                self.push_one(corrupt)?;
                return Ok(());
            }
            None => {}
        }

        self.push_one(frame)
    }

    /// Adds one to the sent count.
    ///
    /// Each counter has its own method so that the guard's scope is exactly the arithmetic. Holding it across an
    /// early return is the shape `clippy::correctness` refuses, and the reason is real: a guard held longer than its
    /// critical section is a lock held while other work happens.
    fn bump_sent(&self) {
        let mut sent = self.sent.lock();
        *sent = sent.saturating_add(1);
    }

    /// Adds one to the dropped count.
    fn bump_dropped(&self) {
        let mut dropped = self.dropped.lock();
        *dropped = dropped.saturating_add(1);
    }

    /// Queues one frame, or refuses when there is no room.
    fn push_one(&self, frame: Frame) -> Result<(), TransportError> {
        // The guard's scope is exactly the critical section, ended by an explicit `drop` so both paths leave it at the
        // same point. A guard dropped early on one path and held to the end on another is what
        // `clippy::correctness` refuses, and a lock held longer than its critical section is a lock held while other
        // work happens.
        let full = {
            let mut queue = self.queue.lock();
            if queue.len() < self.capacity {
                queue.push_back(frame);
                false
            }
            else {
                true
            }
        };
        if full {
            return Err(TransportError::Full { capacity: self.capacity });
        }
        Ok(())
    }

    /// Queues the same frame twice, or refuses when there is not room for both.
    ///
    /// A duplication needs two slots, and a capacity check that only considered one would overfill the queue.
    fn push_twice(&self, frame: Frame) -> Result<(), TransportError> {
        let full = {
            let mut queue = self.queue.lock();
            if queue.len() + 2 <= self.capacity {
                queue.push_back(frame.clone());
                queue.push_back(frame);
                false
            }
            else {
                true
            }
        };
        if full {
            return Err(TransportError::Full { capacity: self.capacity });
        }
        Ok(())
    }

    pub(super) fn receive(&self) -> Option<Frame> {
        self.queue.lock().pop_front()
    }

    pub(super) fn len(&self) -> usize {
        self.queue.lock().len()
    }
}
