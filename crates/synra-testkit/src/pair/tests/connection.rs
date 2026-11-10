use super::*;

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
