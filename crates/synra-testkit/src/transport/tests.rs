use core::time::Duration;

use synra_protocol::frame::{Frame, FrameKind};

use super::{DEFAULT_CAPACITY, Fault, MemoryTransportLink, TransportError};

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
    // Compared through a binding, so the assertion is not a constant expression the compiler folds away.
    let capacity = DEFAULT_CAPACITY;
    assert!(capacity <= 100, "a capacity this large cannot be filled by a test");
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
