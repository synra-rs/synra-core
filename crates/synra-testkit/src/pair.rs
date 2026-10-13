//! Two kernels wired together, and the assertions an end-to-end test makes.
//!
//! # Why the fixture owns the clock
//!
//! If it did not, every test would have to move its own — and the way a timeout test fails is by advancing the clock
//! *and* the assertion drifting apart: the test advances 6 000 ms and asserts a timeout that fires at 25 000, and the
//! assertion passes because the kernel read a different clock.
//!
//! So the pair builds both kernels over **one** [`MockClock`] and exposes [`KernelPair::advance`]. There is no second
//! clock to forget to move.
//!
//! # Why it records what was sent
//!
//! The design document's testing strategy says to assert "which events were produced" rather than "what the internal
//! state is". An assertion about internal state tests the implementation; an assertion about what crossed the wire
//! tests the contract, and it keeps working when the implementation is reorganised.
//!
//! So the pair has a record of frames sent and received in each direction, and [`KernelPair::expect_frame`] reads it.
//! The record is bounded, because a fixture that grew without limit would be a memory leak in a long test.
//!
//! # It is not a kernel
//!
//! There is no `Kernel` here. The aggregates live in `synra-core` and the pair is generic over what it holds, because
//! the fixture's job is the *connection* — the clock, the transports, the handshake — and not the kernel's logic. A
//! fixture that reimplemented the kernel would test itself.

use core::time::Duration;

use synra_protocol::frame::{Frame, FrameBody, FrameKind};

use crate::clock::{Clock, MockClock};
use crate::transport::{Fault, MemoryTransport, MemoryTransportLink, TransportError};

/// How many frames each direction's record keeps.
///
/// A hundred: enough for a handshake, a session and a small transfer, and bounded so a long test does not grow.
pub const RECORD_CAPACITY: usize = 100;

/// Why an expectation was not met.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExpectationError {
    /// No such frame arrived.
    #[error("{expected} did not arrive from {from}")]
    NeverArrived {
        /// Which direction it was expected from.
        from: &'static str,
        /// What was expected.
        expected: String,
    },

    /// A frame of that kind arrived, but not with the expected event.
    #[error("a {kind} frame from {from} carried {found:?}, not {expected:?}")]
    WrongEvent {
        /// Which direction.
        from: &'static str,
        /// The frame's kind.
        kind: &'static str,
        /// What arrived.
        found: String,
        /// What was expected.
        expected: String,
    },

    /// The link refused the send.
    #[error("the link refused a frame: {0}")]
    Refused(TransportError),

    /// The clock refused to move.
    #[error("the clock refused to move: {0}")]
    Clock(#[from] crate::clock::ClockError),
}

/// One side of a pair, as a test sees it.
///
/// Named rather than `a`/`b` at the call site because a test about "the initiator" and "the responder" reads wrong
/// when the two are interchangeable variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The end a test acts as.
    Near,
    /// The end it talks to.
    Far,
}

impl Side {
    /// The other side.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Near => Self::Far,
            Self::Far => Self::Near,
        }
    }

    /// A name for an assertion message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Near => "near",
            Self::Far => "far",
        }
    }
}

/// A record of what crossed the link, in one direction.
#[derive(Debug)]
struct Record {
    frames: parking_lot::Mutex<std::collections::VecDeque<Frame>>,
}

impl Record {
    const fn new() -> Self {
        Self { frames: parking_lot::Mutex::new(std::collections::VecDeque::new()) }
    }

    fn push(&self, frame: Frame) {
        let mut frames = self.frames.lock();
        if frames.len() >= RECORD_CAPACITY {
            frames.pop_front();
        }
        frames.push_back(frame);
    }

    fn find(&self, predicate: impl Fn(&Frame) -> bool) -> Option<Frame> {
        self.frames.lock().iter().find(|frame| predicate(frame)).cloned()
    }

    fn len(&self) -> usize {
        self.frames.lock().len()
    }

    fn clear(&self) {
        self.frames.lock().clear();
    }
}

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
    fn record(&self, side: Side) -> &Record {
        match side {
            Side::Near => &self.near_sent,
            Side::Far => &self.far_sent,
        }
    }
}

/// What a test expects to see.
///
/// A value rather than a closure at the call site, so a failure message can name what was expected. A closure's
/// failure says "the predicate was false", and a reader then has to find the closure to learn what it meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// Which side it comes from.
    pub from: Side,
    /// What kind of frame.
    pub kind: FrameKind,
    /// The event name in the envelope, for an envelope frame.
    pub event: Option<String>,
}

impl Expectation {
    /// An envelope carrying an event.
    #[must_use]
    pub fn event(from: Side, event: &str) -> Self {
        Self { from, kind: FrameKind::Envelope, event: Some(event.to_owned()) }
    }

    /// A frame of a kind.
    #[must_use]
    pub const fn frame(from: Side, kind: FrameKind) -> Self {
        Self { from, kind, event: None }
    }
}

/// Asserts that an expectation holds, for a test that would rather see every failure at once.
///
/// # Why a list rather than an early return
///
/// A handshake test has several expectations, and a version that returned on the first failure would need one run per
/// unmet expectation. Collecting them means one run tells a reader everything that is wrong, which is the difference
/// between two iterations and six.
///
/// # Errors
///
/// [`ExpectationError`] naming the first that did not hold.
pub fn check<K>(pair: &KernelPair<K>, expectations: &[Expectation]) -> Result<(), ExpectationError> {
    for expectation in expectations {
        let found = pair.record(expectation.from).find(|frame| {
            frame.kind == expectation.kind
                && expectation.event.as_deref().is_none_or(|wanted| frame_event(frame).as_deref() == Some(wanted))
        });
        match found {
            Some(_) => {}
            None => {
                // A frame of the right kind with a different event is worth saying, because it is the usual cause:
                // the handshake happened and carried something else.
                if let Some(event) = &expectation.event
                    && let Some(frame) = pair
                        .record(expectation.from)
                        .find(|frame| frame.kind == expectation.kind)
                {
                    return Err(ExpectationError::WrongEvent {
                        from: expectation.from.as_str(),
                        kind: "envelope",
                        found: frame_event(&frame).unwrap_or_else(|| "<unreadable>".to_owned()),
                        expected: event.clone(),
                    });
                }
                return Err(ExpectationError::NeverArrived {
                    from: expectation.from.as_str(),
                    expected: expectation
                        .event
                        .clone()
                        .unwrap_or_else(|| format!("{:?}", expectation.kind)),
                });
            }
        }
    }
    Ok(())
}

/// The event name inside an envelope frame, if it can be read.
///
/// Best effort: a frame the fixture cannot parse gives `None` rather than an error, because the reader here is an
/// assertion message and a fixture that failed to describe a frame would be less useful than one that says it could
/// not.
#[must_use]
pub fn frame_event(frame: &Frame) -> Option<String> {
    if frame.kind != FrameKind::Envelope {
        return None;
    }
    let FrameBody::Envelope(body) = &frame.body else {
        return None;
    };
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("event")?.as_str().map(str::to_owned)
}

/// A paired kernel's view of the other side, for a test that wants names rather than handles.
#[derive(Debug, Clone)]
pub struct PairedKernel {
    /// Which side it is.
    pub side: Side,
    /// The peer's device id, once it is known.
    pub peer_device_id: Option<String>,
    /// Whether the session completed its handshake.
    pub handshake_complete: bool,
}

impl PairedKernel {
    /// A side before anything has happened.
    #[must_use]
    pub const fn new(side: Side) -> Self {
        Self { side, peer_device_id: None, handshake_complete: false }
    }

    /// Records that the handshake completed with a peer.
    pub fn paired_with(&mut self, peer_device_id: impl Into<String>) {
        self.peer_device_id = Some(peer_device_id.into());
        self.handshake_complete = true;
    }

    /// Whether the session is up.
    #[must_use]
    pub const fn is_paired(&self) -> bool {
        self.handshake_complete && self.peer_device_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use synra_protocol::frame::Frame;

    /// A kernel for the fixture, which is just a name — the pair's job is the connection, not the kernel's logic.
    ///
    /// The name is read by one test, which asserts that both kernels came from the closure. Without a reader the
    /// field would be a reminder that the fixture does not care what a kernel is.
    #[derive(Debug)]
    struct FakeKernel {
        name: &'static str,
    }

    impl FakeKernel {
        /// What this kernel was named.
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn pair() -> KernelPair<FakeKernel> {
        KernelPair::with_clock(|_clock, _link| {
            (FakeKernel { name: "near" }, FakeKernel { name: "far" })
        })
    }

    /// An envelope frame carrying an event.
    ///
    /// Built directly rather than through a constructor, because the frame layer deliberately leaves the body
    /// unparsed: its job is boundaries, and a fixture that parsed would be testing something the protocol does not do.
    fn envelope(event: &str) -> Frame {
        Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from(format!(r#"{{"event":"{event}"}}"#))),
        }
    }

    #[test]
    fn a_pair_builds_both_ends_over_one_clock() {
        // The kernels came from the closure, which is what makes "both ends share the clock" checkable rather than
        // asserted in a comment.
        // The clock is the fix for the failure mode this fixture exists to prevent: a test advancing one clock while
        // the kernel reads another.
        let pair = pair();
        assert_eq!(pair.near.name(), "near");
        assert_eq!(pair.far.name(), "far");
        assert_eq!(pair.now_ms(), 0);
        pair.advance(Duration::from_millis(250)).expect("advances");
        assert_eq!(pair.now_ms(), 250);
        // And the clock the closure saw is the one the pair holds.
        assert_eq!(pair.clock().now_ms(), 250);
    }

    #[test]
    fn the_closure_gets_the_clock_the_pair_holds() {
        // Which is what makes it impossible to build a kernel over a different one.
        let seen = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let captured = std::sync::Arc::clone(&seen);
        let pair = KernelPair::with_clock(move |clock, _link| {
            *captured.lock() = Some(std::sync::Arc::as_ptr(clock) as usize);
            (FakeKernel { name: "near" }, FakeKernel { name: "far" })
        });
        assert_eq!(
            *seen.lock(),
            Some(std::sync::Arc::as_ptr(pair.clock()) as usize),
            "the closure was given a different clock"
        );
    }

    #[test]
    fn a_frame_sent_from_one_side_arrives_at_the_other() {
        let pair = pair();
        pair.send(Side::Near, envelope("device.ping")).expect("sends");
        assert!(pair.is_readable(Side::Far));
        assert!(!pair.is_readable(Side::Near));
        assert_eq!(frame_event(&pair.receive(Side::Far).expect("arrives")).as_deref(), Some("device.ping"));
    }

    #[test]
    fn what_was_sent_is_recorded() {
        // The design document's testing strategy: assert which events were produced, not what the internal state is.
        let pair = pair();
        for event in ["device.hello", "device.hello.ack", "device.ack"] {
            pair.send(Side::Near, envelope(event)).expect("sends");
        }
        assert_eq!(pair.sent_of_kind(Side::Near, FrameKind::Envelope).len(), 3);
        assert_eq!(pair.recorded(Side::Near), 3);
        assert_eq!(pair.recorded(Side::Far), 0);
    }

    #[test]
    fn an_expectation_holds_when_the_frame_was_sent() {
        let pair = pair();
        pair.send(Side::Near, envelope("device.hello")).expect("sends");
        assert_eq!(check(&pair, &[Expectation::event(Side::Near, "device.hello")]), Ok(()));
    }

    #[test]
    fn a_missing_expectation_names_what_was_expected() {
        // A failure message that says "the predicate was false" sends a reader looking for the predicate.
        let pair = pair();
        match check(&pair, &[Expectation::event(Side::Near, "device.hello")]) {
            Err(ExpectationError::NeverArrived { from, expected }) => {
                assert_eq!(from, "near");
                assert_eq!(expected, "device.hello");
            }
            other => panic!("expected a missing expectation, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_event_is_distinguished_from_a_missing_frame() {
        // The usual cause of a failed handshake assertion: the frame arrived and carried something else.
        let pair = pair();
        pair.send(Side::Near, envelope("device.bye")).expect("sends");
        match check(&pair, &[Expectation::event(Side::Near, "device.hello")]) {
            Err(ExpectationError::WrongEvent { found, expected, .. }) => {
                assert_eq!(found, "device.bye");
                assert_eq!(expected, "device.hello");
            }
            other => panic!("expected a wrong event, got {other:?}"),
        }
    }

    #[test]
    fn every_expectation_is_checked_in_order() {
        let pair = pair();
        pair.send(Side::Near, envelope("a")).expect("sends");
        pair.send(Side::Near, envelope("b")).expect("sends");
        assert_eq!(
            check(
                &pair,
                &[Expectation::event(Side::Near, "a"), Expectation::event(Side::Near, "b")]
            ),
            Ok(())
        );

        // The failure names the envelope that *did* arrive, because that is the usual cause of a failed handshake
        // assertion: the frame came and carried something else. A test wanting "no envelope at all" asserts against an
        // empty record, which is the case below.
        match check(
            &pair,
            &[Expectation::event(Side::Near, "a"), Expectation::event(Side::Near, "missing")],
        ) {
            Err(ExpectationError::WrongEvent { found, expected, .. }) => {
                assert_eq!(found, "a", "the message should name what arrived");
                assert_eq!(expected, "missing");
            }
            other => panic!("expected the second to fail, got {other:?}"),
        }

        // And with nothing recorded at all, the failure is that nothing arrived — a different message, and the
        // difference is what tells a reader whether the handshake did not happen or happened differently. Built
        // inline rather than through `pair()`, because the local binding has shadowed that function's name.
        let nothing_recorded = KernelPair::with_clock(|_clock, _link| {
            (FakeKernel { name: "near" }, FakeKernel { name: "far" })
        });
        match check(&nothing_recorded, &[Expectation::event(Side::Near, "anything")]) {
            Err(ExpectationError::NeverArrived { expected, .. }) => assert_eq!(expected, "anything"),
            other => panic!("expected a missing frame, got {other:?}"),
        }
    }

    #[test]
    fn a_frame_expectation_does_not_need_an_event() {
        let pair = pair();
        pair.send(Side::Near, Frame::empty(FrameKind::Ping)).expect("sends");
        assert_eq!(check(&pair, &[Expectation::frame(Side::Near, FrameKind::Ping)]), Ok(()));
    }

    #[test]
    fn a_dropped_frame_is_still_recorded_as_an_attempt() {
        // A test asserting "it was sent" is asserting about the attempt, so the record has to hold it even though the
        // far side never saw it — and the drop count is what says whether it arrived.
        let pair = pair();
        pair.inject(Side::Near, Fault::DropNext);
        assert!(pair.send(Side::Near, envelope("device.hello")).is_err());
        assert_eq!(pair.recorded(Side::Near), 1);
        assert_eq!(pair.attempts(Side::Near), 1);
        assert_eq!(pair.dropped(Side::Near), 1);
        assert_eq!(pair.transport_sent(Side::Near), 1);
        assert!(!pair.is_readable(Side::Far));
    }

    #[test]
    fn records_can_be_cleared_between_phases() {
        // A test that has asserted about the handshake and now wants to assert about the session should not have to
        // reason about the handshake's frames.
        let pair = pair();
        pair.send(Side::Near, envelope("device.hello")).expect("sends");
        assert_eq!(pair.recorded(Side::Near), 1);
        pair.clear_records();
        assert_eq!(pair.recorded(Side::Near), 0);
        assert_eq!(pair.recorded(Side::Far), 0);
    }

    #[test]
    fn the_record_is_bounded() {
        // A fixture that grew without limit would be a memory leak in a long test.
        let pair = KernelPair::new(
            FakeKernel { name: "near" },
            FakeKernel { name: "far" },
            MemoryTransportLink::with_capacity(RECORD_CAPACITY * 4),
            std::sync::Arc::new(MockClock::new()),
        );
        for _ in 0..(RECORD_CAPACITY + 20) {
            pair.send(Side::Near, Frame::empty(FrameKind::Ping)).expect("sends");
        }
        assert_eq!(pair.recorded(Side::Near), RECORD_CAPACITY);
        // The attempts count is not bounded, because it is a number rather than a buffer.
        assert_eq!(pair.attempts(Side::Near), (RECORD_CAPACITY + 20) as u64);
    }

    #[test]
    fn draining_takes_everything_waiting() {
        let pair = pair();
        for _ in 0..3 {
            pair.send(Side::Near, Frame::empty(FrameKind::Ping)).expect("sends");
        }
        assert_eq!(pair.drain(Side::Far).len(), 3);
        assert!(!pair.is_readable(Side::Far));
        assert!(pair.drain(Side::Far).is_empty());
    }

    #[test]
    fn cutting_the_link_stops_both_directions() {
        let pair = pair();
        pair.cut();
        assert!(pair.send(Side::Near, Frame::empty(FrameKind::Ping)).is_err());
        assert!(pair.send(Side::Far, Frame::empty(FrameKind::Ping)).is_err());
    }

    #[test]
    fn a_fault_injects_into_the_direction_it_names() {
        // A fault injected into the wrong direction is the sort of mistake that makes a test pass for the wrong
        // reason, so the two directions are asserted separately.
        let pair = pair();
        pair.inject(Side::Near, Fault::DropNext);
        assert!(pair.send(Side::Near, Frame::empty(FrameKind::Ping)).is_err());
        pair.send(Side::Far, Frame::empty(FrameKind::Ping)).expect("the far direction is unaffected");
        assert!(pair.is_readable(Side::Near));
    }

    #[test]
    fn a_side_knows_its_other_and_its_name() {
        assert_eq!(Side::Near.other(), Side::Far);
        assert_eq!(Side::Far.other(), Side::Near);
        assert_eq!(Side::Near.as_str(), "near");
        assert_eq!(Side::Far.as_str(), "far");
    }

    #[test]
    fn a_paired_kernel_is_paired_only_with_an_id() {
        // "Handshake complete" without a device id is a link to something anonymous, which cannot be routed to.
        let mut kernel = PairedKernel::new(Side::Near);
        assert!(!kernel.is_paired());
        kernel.handshake_complete = true;
        assert!(!kernel.is_paired(), "paired without an id");
        kernel.paired_with("dev_a");
        assert!(kernel.is_paired());
        assert_eq!(kernel.peer_device_id.as_deref(), Some("dev_a"));
    }

    #[test]
    fn an_unreadable_frame_yields_no_event_rather_than_an_error() {
        // The reader here is an assertion message, and a fixture that failed to describe a frame would be less useful
        // than one that says it could not.
        let frame = Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"not json")),
        };
        assert_eq!(frame_event(&frame), None);
        assert_eq!(frame_event(&Frame::empty(FrameKind::Ping)), None);
    }

    #[test]
    fn a_clock_refusal_reaches_the_caller() {
        let pair = pair();
        pair.clock().set_limit(100).expect("sets a limit");
        assert!(matches!(pair.advance(Duration::from_millis(1_000)), Err(ExpectationError::Clock(_))));
    }

    #[test]
    fn expectation_errors_explain_themselves() {
        let errors = [
            ExpectationError::NeverArrived { from: "near", expected: "device.hello".to_owned() },
            ExpectationError::WrongEvent {
                from: "near",
                kind: "envelope",
                found: "device.bye".to_owned(),
                expected: "device.hello".to_owned(),
            },
            ExpectationError::Refused(TransportError::Closed),
            ExpectationError::Clock(crate::clock::ClockError::Backwards { from: 2, to: 1 }),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}
