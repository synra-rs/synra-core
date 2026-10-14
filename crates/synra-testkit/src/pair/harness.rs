//! Two kernels wired to each other in memory.

use core::time::Duration;

use synra_protocol::frame::{Frame, FrameKind};

use crate::clock::{Clock, MockClock};
use crate::transport::{Fault, MemoryTransport, MemoryTransportLink};

use super::record::{ExpectationError, Record, Side};

/// Two ends of a memory link, over one clock.
///
/// Generic over the kernel each side runs, so this crate does not depend on the kernel's aggregates — the fixture's
/// job is the connection. A test constructs the pair with its own kernels.
#[derive(Debug)]
pub struct KernelPair<K> {
    /// The end a test acts as.
    pub near: K,
    /// The end it talks to.
    pub far: K,
    /// The link both ends use.
    pub link: MemoryTransportLink,
    /// The clock both ends read.
    clock: std::sync::Arc<MockClock>,
    /// What the near end sent.
    near_sent: Record,
    /// What the far end sent.
    far_sent: Record,
    /// How many frames have crossed in each direction, including any that were dropped.
    near_attempts: parking_lot::Mutex<u64>,
    far_attempts: parking_lot::Mutex<u64>,
}

impl<K> KernelPair<K> {
    #[allow(clippy::missing_const_for_fn)]
    /// Builds a pair from two kernels and a link.
    ///
    /// # The kernels have to be built over the pair's clock
    ///
    /// [`Self::clock`] is what [`Self::advance`] moves, so a kernel built over its own clock would not move — which
    /// is the failure this constructor cannot prevent and the reason the docs say so. [`Self::with_clock`] is the
    /// shape that makes it checkable: the caller builds the kernels from the clock the pair will hold.
    #[must_use]
    pub fn new(near: K, far: K, link: MemoryTransportLink, clock: std::sync::Arc<MockClock>) -> Self {
        Self {
            near,
            far,
            link,
            clock,
            near_sent: Record::new(),
            far_sent: Record::new(),
            near_attempts: parking_lot::Mutex::new(0),
            far_attempts: parking_lot::Mutex::new(0),
        }
    }

    /// Builds a pair, handing the clock to a closure that builds both kernels.
    ///
    /// This is the constructor to use: the closure receives the clock the pair holds, so a kernel built inside it
    /// cannot accidentally get a different one.
    #[must_use]
    pub fn with_clock(
        build: impl FnOnce(&std::sync::Arc<MockClock>, &MemoryTransportLink) -> (K, K),
    ) -> Self {
        let clock = std::sync::Arc::new(MockClock::new());
        let link = MemoryTransportLink::new();
        let (near, far) = build(&clock, &link);
        Self::new(near, far, link, clock)
    }

    /// The clock both ends read.
    #[must_use]
    pub const fn clock(&self) -> &std::sync::Arc<MockClock> {
        &self.clock
    }

    /// Moves the clock forward.
    ///
    /// # Errors
    ///
    /// [`ExpectationError::Clock`] if the move would overflow or pass a limit the test set.
    pub fn advance(&self, by: Duration) -> Result<u64, ExpectationError> {
        Ok(self.clock.advance(by)?)
    }

    /// The current reading.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Sends a frame from one side, recording it.
    ///
    /// # Errors
    ///
    /// [`ExpectationError::Refused`] when the link refuses it, which includes a fault a test injected.
    pub fn send(&self, from: Side, frame: Frame) -> Result<(), ExpectationError> {
        let transport = self.transport(from);
        // One lock acquisition, then the arithmetic on the guard. See `MockClock::now_ms` for why: taking the same
        // lock twice in one expression deadlocks, because `parking_lot`'s mutex is not reentrant.
        {
            let counter = match from {
                Side::Near => &self.near_attempts,
                Side::Far => &self.far_attempts,
            };
            let mut attempts = counter.lock();
            *attempts = attempts.saturating_add(1);
        }
        // Recorded before the send, so a dropped frame is still in the record — a test asserting "it was sent" is
        // asserting about the attempt, and the drop count is what says whether it arrived.
        self.record(from).push(frame.clone());
        transport.send(frame).map_err(ExpectationError::Refused)
    }

    /// Takes the next frame one side has received.
    #[must_use]
    pub fn receive(&self, at: Side) -> Option<Frame> {
        self.transport(at).receive()
    }

    /// Drains everything one side has received.
    #[must_use]
    pub fn drain(&self, at: Side) -> Vec<Frame> {
        let transport = self.transport(at);
        let mut frames = Vec::new();
        while let Some(frame) = transport.receive() {
            frames.push(frame);
        }
        frames
    }

    /// Every frame of a kind one side sent.
    #[must_use]
    pub fn sent_of_kind(&self, from: Side, kind: FrameKind) -> Vec<Frame> {
        self.record(from)
            .frames
            .lock()
            .iter()
            .filter(|frame| frame.kind == kind)
            .cloned()
            .collect()
    }

    /// How many frames one side sent, including any that were dropped.
    #[must_use]
    pub fn attempts(&self, from: Side) -> u64 {
        match from {
            Side::Near => *self.near_attempts.lock(),
            Side::Far => *self.far_attempts.lock(),
        }
    }

    /// How many frames one side has sent, as the transport counts them.
    #[must_use]
    pub fn transport_sent(&self, from: Side) -> u64 {
        self.transport(from).sent()
    }

    /// How many frames one side dropped.
    #[must_use]
    pub fn dropped(&self, from: Side) -> u64 {
        self.transport(from).dropped()
    }

    /// Injects a fault for the next frame one side sends.
    pub fn inject(&self, from: Side, fault: Fault) {
        self.transport(from).inject(fault);
    }

    /// Cuts both directions.
    pub fn cut(&self) {
        self.link.cut();
    }

    /// Whether a frame of a kind is waiting at a side.
    #[must_use]
    pub fn is_readable(&self, at: Side) -> bool {
        self.transport(at).is_readable()
    }

    /// Forgets what was recorded, so a test can assert about a phase.
    pub fn clear_records(&self) {
        self.near_sent.clear();
        self.far_sent.clear();
    }

    /// How many frames are recorded for a side.
    #[must_use]
    pub fn recorded(&self, from: Side) -> usize {
        self.record(from).len()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// The transport one side sends on.
    fn transport(&self, side: Side) -> &std::sync::Arc<MemoryTransport> {
        match side {
            Side::Near => &self.link.a,
            Side::Far => &self.link.b,
        }
    }
#[allow(clippy::missing_const_for_fn)]
    /// The record of what one side sent.
    pub(crate) fn record(&self, side: Side) -> &Record {
        match side {
            Side::Near => &self.near_sent,
            Side::Far => &self.far_sent,
        }
    }
}
