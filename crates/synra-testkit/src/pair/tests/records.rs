use super::*;

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
