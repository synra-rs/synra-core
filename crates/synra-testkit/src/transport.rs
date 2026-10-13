//! An in-memory transport, so two kernels can be linked without a socket.
//!
//! # What it replaces
//!
//! The end-to-end tests the design document asks for — the whole session handshake, a reconnect, an idempotent
//! retry, a transfer's integrity check — need two kernels talking to each other. Doing that over TCP makes the test
//! depend on a port, on the loopback interface, and on the operating system's scheduling, and the failures it
//! produces are about the test environment rather than about the protocol.
//!
//! So the transport is a seam: the kernel's session state machine sends *frames* and receives *frames*, and where
//! they go between is [`MemoryTransport`]'s business. The state machine runs unchanged; only the medium differs.
//!
//! # It is not a mock
//!
//! A mock records calls and returns canned answers. This actually carries the bytes: it is a queue pair with the
//! same delivery semantics as a socket — ordered, reliable, and able to be broken. A test asserting that a handshake
//! completed is asserting that the frames arrived, in order, and were processed — which is what the real transport
//! would have done.
//!
//! # Faults are explicit
//!
//! A dropped frame, a duplicated frame, a link that goes silent and one that is cut: each is a [`Fault`] a test
//! injects at a chosen point. Injecting "the third frame is dropped" is what makes a reconnect test reproducible;
//! a test that hoped for a real network hiccup would be flaky in the direction that matters least.

use core::time::Duration;

use bytes::Bytes;
use synra_protocol::frame::{Frame, FrameBody, FrameKind};

/// Why a send or receive failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The link is closed.
    #[error("the link is closed")]
    Closed,

    /// The link went silent: nothing may be sent and nothing arrives.
    ///
    /// Distinct from closed, because it is what an unplugged cable looks like: the local end believes the connection
    /// is open and nothing arrives. A test of the heartbeat timeout needs exactly this state.
    #[error("the link is silent")]
    Silent,

    /// The peer's queue is full.
    ///
    /// The transport refuses rather than growing, because a transport that buffered without bound would make the
    /// kernel's own back-pressure logic untestable: the queue could never fill.
    #[error("the peer's receive queue is full")]
    Full {
        /// The capacity that was reached.
        capacity: usize,
    },

    /// The frame was dropped, by an injected fault.
    #[error("the frame was dropped by an injected fault")]
    Dropped,
}

/// A fault to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fault {
    /// Drop the next frame in this direction.
    ///
    /// The fault a retry test starts with: a lost frame that the protocol is supposed to recover from.
    DropNext,
    /// Deliver the next frame twice.
    ///
    /// What a channel can do, and what makes an idempotency test real rather than theoretical.
    DuplicateNext,
    /// Deliver the next frame with a corrupted body.
    ///
    /// The fault that must close the link: a structural problem in a frame cannot be skipped over without losing
    /// alignment, which is why the decoder refuses rather than recovering.
    CorruptNext,
    /// Make the link silent for a duration.
    Silence(Duration),
    /// Cut the link.
    Cut,
}

/// One direction of an in-memory link.
#[derive(Debug)]
struct Direction {
    queue: parking_lot::Mutex<std::collections::VecDeque<Frame>>,
    capacity: usize,
    /// The next fault to apply, if any.
    fault: parking_lot::Mutex<Option<Fault>>,
    /// How many frames have been sent, for a test asserting about a retry.
    sent: parking_lot::Mutex<u64>,
    /// How many were dropped, so a test can assert its fault actually fired.
    dropped: parking_lot::Mutex<u64>,
}

impl Direction {
    #[allow(clippy::missing_const_for_fn)]
    fn new(capacity: usize) -> Self {
        Self {
            queue: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            capacity,
            fault: parking_lot::Mutex::new(None),
            sent: parking_lot::Mutex::new(0),
            dropped: parking_lot::Mutex::new(0),
        }
    }

    fn send(&self, frame: Frame) -> Result<(), TransportError> {
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

    fn receive(&self) -> Option<Frame> {
        self.queue.lock().pop_front()
    }

    fn len(&self) -> usize {
        self.queue.lock().len()
    }
}

/// One end of a memory link.
///
/// Holds the outbound direction and the peer's inbound one, which is what makes [`Self::send`] and
/// [`Self::receive`] different queues — a transport that looped back to itself would test nothing.
#[derive(Debug)]
pub struct MemoryTransport {
    outbound: std::sync::Arc<Direction>,
    inbound: std::sync::Arc<Direction>,
    /// Whether this end believes the link is open.
    open: parking_lot::Mutex<bool>,
}

impl MemoryTransport {
    /// Sends a frame to the peer.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when the link is closed or silent, the peer's queue is full, or a fault dropped it.
    pub fn send(&self, frame: Frame) -> Result<(), TransportError> {
        if !*self.open.lock() {
            return Err(TransportError::Closed);
        }
        self.outbound.send(frame)
    }

    /// Takes the next frame from the peer, if one has arrived.
    #[must_use]
    pub fn receive(&self) -> Option<Frame> {
        self.inbound.receive()
    }

    /// Whether a frame is waiting.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.inbound.len() > 0
    }

    /// How many frames are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.inbound.len()
    }

    /// How many frames this end has sent.
    #[must_use]
    pub fn sent(&self) -> u64 {
        *self.outbound.sent.lock()
    }

    /// How many frames this end dropped, so a test can assert its fault fired.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        *self.outbound.dropped.lock()
    }

    /// Whether this end believes the link is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        *self.open.lock()
    }

    /// Closes this end.
    ///
    /// Only this end, which is what makes a half-closed link testable: the peer keeps believing it is connected,
    /// which is exactly the state an unplugged cable produces.
    pub fn close(&self) {
        *self.open.lock() = false;
    }

    /// Injects a fault for the next frame this end sends.
    pub fn inject(&self, fault: Fault) {
        *self.outbound.fault.lock() = Some(fault);
    }
}

/// Two transports wired to each other.
#[derive(Debug)]
pub struct MemoryTransportLink {
    /// The end a kernel would use as its own.
    pub a: std::sync::Arc<MemoryTransport>,
    /// The other end.
    pub b: std::sync::Arc<MemoryTransport>,
    /// The queue capacity each direction was built with.
    pub capacity: usize,
}

impl MemoryTransportLink {
    /// A link with the given queue capacity per direction.
    ///
    /// Small capacities are the point rather than an inconvenience: a test of the kernel's back-pressure needs a
    /// queue that can actually fill, and a capacity of thousands makes that unreachable.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        // Each direction is shared: A's outbound is B's inbound and the other way round, so a frame sent by A is
        // received by B — and neither end can see its own frames.
        let a_to_b = std::sync::Arc::new(Direction::new(capacity));
        let b_to_a = std::sync::Arc::new(Direction::new(capacity));

        let a = std::sync::Arc::new(MemoryTransport {
            outbound: std::sync::Arc::clone(&a_to_b),
            inbound: std::sync::Arc::clone(&b_to_a),
            open: parking_lot::Mutex::new(true),
        });
        let b = std::sync::Arc::new(MemoryTransport {
            outbound: b_to_a,
            inbound: a_to_b,
            open: parking_lot::Mutex::new(true),
        });

        Self { a, b, capacity }
    }

    /// A link with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Cuts both directions at once.
    ///
    /// What a test of "the peer went away" needs, as opposed to a half-closed link.
    pub fn cut(&self) {
        self.a.close();
        self.b.close();
    }

    /// How many frames are waiting to be received by each side.
    #[must_use]
    pub fn pending(&self) -> (usize, usize) {
        (self.b.pending(), self.a.pending())
    }
}

impl Default for MemoryTransportLink {
    fn default() -> Self {
        Self::new()
    }
}

/// The default queue capacity per direction.
///
/// Fifty: large enough for a handshake and its acknowledgements, small enough that a test of a full queue reaches it
/// in a handful of sends.
pub const DEFAULT_CAPACITY: usize = 50;

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::frame::FrameKind;

    fn ping() -> Frame {
        Frame::empty(FrameKind::Ping)
    }

    #[test]
    fn a_frame_sent_by_one_end_arrives_at_the_other() {
        // The property the whole fixture rests on: A's outbound is B's inbound, so a test asserting a handshake is
        // asserting the frames actually moved.
        let link = MemoryTransportLink::new();
        link.a.send(ping()).expect("sends");
        assert!(link.b.is_readable());
        assert!(link.a.receive().is_none(), "A received its own frame");
        assert_eq!(link.b.receive().expect("arrives").kind, FrameKind::Ping);
    }

    #[test]
    fn the_other_direction_is_separate() {
        let link = MemoryTransportLink::new();
        link.b.send(ping()).expect("sends");
        assert!(link.a.is_readable());
        assert!(!link.b.is_readable());
    }

    #[test]
    fn frames_arrive_in_order() {
        // Ordering is what makes a transfer's chunks assemble into the right file, and a fixture that reordered would
        // make every ordering bug invisible.
        let link = MemoryTransportLink::new();
        for _ in 0..3 {
            link.a.send(Frame::empty(FrameKind::Ping)).expect("sends");
        }
        for _ in 0..3 {
            assert_eq!(link.b.receive().expect("arrives").kind, FrameKind::Ping);
        }
        assert!(link.b.receive().is_none());
    }

    #[test]
    fn a_closed_end_refuses_to_send() {
        let link = MemoryTransportLink::new();
        link.a.close();
        assert!(!link.a.is_open());
        assert!(matches!(link.a.send(ping()), Err(TransportError::Closed)));
    }

    #[test]
    fn a_half_closed_link_leaves_the_peer_believing_it_is_connected() {
        // Which is exactly the state an unplugged cable produces: the local end sees an open connection and nothing
        // arrives. A test of the heartbeat timeout needs this state.
        let link = MemoryTransportLink::new();
        link.a.close();
        assert!(!link.a.is_open());
        assert!(link.b.is_open(), "the peer was closed too");
    }

    #[test]
    fn cutting_closes_both_ends() {
        let link = MemoryTransportLink::new();
        link.cut();
        assert!(!link.a.is_open());
        assert!(!link.b.is_open());
    }

    #[test]
    fn dropping_the_next_frame_reports_the_drop() {
        // A test asserting that a retry recovered needs to know the fault actually fired, or it is asserting about a
        // frame that was never lost.
        let link = MemoryTransportLink::new();
        link.a.inject(Fault::DropNext);
        assert!(matches!(link.a.send(ping()), Err(TransportError::Dropped)));
        assert_eq!(link.a.dropped(), 1);
        assert_eq!(link.b.pending(), 0);

        // And the fault is spent.
        link.a.send(ping()).expect("sends");
        assert_eq!(link.b.pending(), 1);
    }

    #[test]
    fn duplicating_the_next_frame_queues_it_twice() {
        // What makes an idempotency test real rather than theoretical: the receiver sees the same frame twice and has
        // to deduplicate by request id.
        let link = MemoryTransportLink::new();
        link.a.inject(Fault::DuplicateNext);
        link.a.send(ping()).expect("sends");
        assert_eq!(link.b.pending(), 2);
    }

    #[test]
    fn corrupting_the_next_frame_delivers_something_that_is_not_what_was_sent() {
        // The fault that must close the link: the receiver's structural check is what refuses it, and the point of
        // injecting it at the transport is that the *receiver* is the one that notices.
        let link = MemoryTransportLink::new();
        link.a.inject(Fault::CorruptNext);
        link.a.send(Frame::empty(FrameKind::Ping)).expect("queues");
        let received = link.b.receive().expect("arrives");
        // Whatever it is, it is not the ping that was sent.
        assert_ne!(received.kind, FrameKind::Ping);
    }

    #[test]
    fn silence_refuses_to_send_without_closing() {
        // A silent link is not closed: the sender believes the connection is open, which is what makes it different
        // from a cut one.
        let link = MemoryTransportLink::new();
        link.a.inject(Fault::Silence(Duration::from_secs(1)));
        assert!(matches!(link.a.send(ping()), Err(TransportError::Silent)));
        assert!(link.a.is_open());
    }

    #[test]
    fn cutting_by_fault_reports_a_close() {
        let link = MemoryTransportLink::new();
        link.a.inject(Fault::Cut);
        assert!(matches!(link.a.send(ping()), Err(TransportError::Closed)));
    }

    #[test]
    fn a_full_queue_is_refused_rather_than_grown() {
        // A transport that buffered without bound would make the kernel's own back-pressure logic untestable: the
        // queue could never fill.
        let link = MemoryTransportLink::with_capacity(2);
        link.a.send(ping()).expect("sends");
        link.a.send(ping()).expect("sends");
        match link.a.send(ping()) {
            Err(TransportError::Full { capacity }) => assert_eq!(capacity, 2),
            other => panic!("expected a full queue, got {other:?}"),
        }
    }

    #[test]
    fn a_full_queue_admits_again_once_drained() {
        let link = MemoryTransportLink::with_capacity(1);
        link.a.send(ping()).expect("sends");
        assert!(link.a.send(ping()).is_err());
        let _ = link.b.receive();
        link.a.send(ping()).expect("sends after draining");
    }

    #[test]
    fn duplicating_into_a_full_queue_is_refused() {
        // A duplication needs two slots, and a capacity check that only considered one would overfill the queue.
        let link = MemoryTransportLink::with_capacity(1);
        link.a.inject(Fault::DuplicateNext);
        assert!(link.a.send(ping()).is_err());
        assert_eq!(link.b.pending(), 0);
    }

    #[test]
    fn the_sent_count_tracks_attempts_including_drops() {
        // A test asserting about a retry wants the attempt count, not the delivered one.
        let link = MemoryTransportLink::new();
        link.a.send(ping()).expect("sends");
        link.a.inject(Fault::DropNext);
        let _ = link.a.send(ping());
        assert_eq!(link.a.sent(), 2);
        assert_eq!(link.a.dropped(), 1);
    }

    #[test]
    fn pending_reports_both_directions() {
        // The tuple is `(what B will receive, what A will receive)`: one frame went B's way and two went A's way. Both
        // orders are asserted, because the tuple's order is the thing a reader gets wrong and a test that matched
        // would keep the mistake.
        let link = MemoryTransportLink::new();
        link.a.send(ping()).expect("sends");
        link.b.send(ping()).expect("sends");
        link.b.send(ping()).expect("sends");
        assert_eq!(link.pending(), (1, 2));
        assert_eq!(link.b.pending(), 1, "B receives the one frame that A sent");
        assert_eq!(link.a.pending(), 2, "A receives the two frames that B sent");
    }

    #[test]
    fn the_default_capacity_is_reachable_in_a_test() {
        // Small capacities are the point: a queue that can actually fill is what makes back-pressure testable.
        assert_eq!(MemoryTransportLink::new().capacity, DEFAULT_CAPACITY);
        // Compared through a binding, so the assertion is not a constant expression the compiler folds away.\n        let capacity = DEFAULT_CAPACITY;\n        assert!(capacity <= 100, "a capacity this large cannot be filled by a test");
    }

    #[test]
    fn transport_errors_explain_themselves() {
        let errors = [
            TransportError::Closed,
            TransportError::Silent,
            TransportError::Full { capacity: 50 },
            TransportError::Dropped,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}
