use std::sync::Arc;

use super::super::{EventBus, SubscriberId, SubscriberReport};
use super::{Tick, bus};

#[test]
fn an_event_reaches_every_subscriber() {
    let bus = bus();
    let first = bus.subscribe();
    let second = bus.subscribe();
    assert_eq!(bus.subscriber_count(), 2);

    bus.emit(Tick(7));
    assert_eq!(bus.take(first).expect("first").events(), &[Tick(7)]);
    assert_eq!(bus.take(second).expect("second").events(), &[Tick(7)]);
}

#[test]
fn an_event_emitted_before_a_subscriber_existed_does_not_reach_it() {
    // A subscriber sees the stream from where it attached. A bus that replayed its history would give a diagnostic
    // tool the whole past unbounded, and a second window every event since the kernel started.
    let bus = bus();
    bus.emit(Tick(1));
    let late = bus.subscribe();
    bus.emit(Tick(2));
    assert_eq!(bus.take(late).expect("late").events(), &[Tick(2)]);
}

#[test]
fn taking_empties_the_queue() {
    // A `take` that left the events would hand the same event to a caller twice, which is what the sequence tracker
    // then refuses — so the mistake would be invisible except as a stalled queue.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(1)]);
    // ★ And the second read answers `None` rather than an empty batch, which is what makes a drain terminate: a `while
    // let Some(..)` around a call that answered `Some(vec![])` would loop for ever rather than fail.
    assert!(bus.take(id).is_none(), "an empty queue is nothing to hand over");
}

#[test]
fn peeking_does_not_consume() {
    // For a caller that has to decide whether to read before reading. The events are still there afterwards.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));
    assert_eq!(bus.peek(id).expect("id").events(), &[Tick(1)]);
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(1)]);
}

#[test]
fn unsubscribing_removes_the_queue() {
    // ★ A subscriber that went away without unsubscribing is memory held for the life of the kernel, and a caller
    // that opened a window per device would leak one per window.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));

    assert!(bus.unsubscribe(id));
    assert_eq!(bus.subscriber_count(), 0);
    // And a second unsubscribe is `false` rather than an error: an interface torn down twice is ordinary.
    assert!(!bus.unsubscribe(id));
    assert!(bus.take(id).is_none());
    assert!(bus.report(id).is_none());
}

#[test]
fn an_unknown_subscriber_reads_nothing_rather_than_panicking() {
    // A stale identity is ordinary — a window closed while a timer was in flight — and a panic there would take the
    // kernel down for a UI mistake.
    let bus: EventBus<Tick> = bus();
    let ghost = SubscriberId(9_999);
    assert!(bus.take(ghost).is_none());
    assert!(bus.peek(ghost).is_none());
    assert!(bus.report(ghost).is_none());
    assert!(!bus.reset_counters(ghost));
}

#[test]
fn the_emitter_does_not_learn_whether_anyone_was_listening() {
    // ★ A kernel that blocked when an interface was slow would be one where a resizing window pauses device
    // discovery. The contract is `emit` and nothing else, and what it returns is the sequence number rather than a
    // subscriber count.
    let bus: EventBus<Tick> = bus();
    assert_eq!(bus.emit(Tick(1)), 1);
    assert_eq!(bus.emit(Tick(2)), 2);
}

#[test]
fn the_bus_can_be_shared_between_threads() {
    // ★ Where the bus is used: one kernel task emits and several interfaces read, so the bus crosses threads by
    // construction. A compile-time assertion with a runtime witness — a bus that was not `Send + Sync` would not
    // compile here, and the failure would otherwise appear wherever it was first put behind an `Arc`.
    fn assert_shareable<T: Send + Sync>() {}
    assert_shareable::<EventBus<Tick>>();
    assert_shareable::<SubscriberId>();
    assert_shareable::<SubscriberReport>();

    // And it works from another thread, which is the property the assertion is a proxy for.
    let bus = Arc::new(bus());
    let id = bus.subscribe();
    let emitted = Arc::clone(&bus);
    let handle = std::thread::spawn(move || emitted.emit(Tick(42)));
    let seq = handle.join().expect("the thread finished");
    assert_eq!(seq, 1);
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(42)]);
}

#[test]
fn a_subscriber_identity_is_readable_in_a_report() {
    // A diagnostic bundle names the subscriber it is complaining about, and an opaque tuple would give it a number
    // with no way to refer to it.
    let bus = bus();
    let id = bus.subscribe();
    assert_eq!(id.to_string(), format!("sub{}", id.get()));
    assert!(id.get() >= 1);
}
