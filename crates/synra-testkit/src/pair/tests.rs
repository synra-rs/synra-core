//! The paired-kernel harness's tests.

use super::*;
use bytes::Bytes;
use synra_protocol::frame::Frame;

use core::time::Duration;

use crate::clock::MockClock;
use crate::transport::{Fault, MemoryTransportLink};

use synra_protocol::frame::{FrameBody, FrameKind};
use crate::transport::TransportError;
use crate::clock::Clock;

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
