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

use synra_protocol::frame::Frame;

mod direction;

use direction::Direction;

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
mod tests;
