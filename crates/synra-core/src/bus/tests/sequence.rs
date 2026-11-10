use super::super::{EventBus, SUBSCRIBER_QUEUE_CAPACITY};
use super::{Tick, bus};

#[test]
fn the_first_event_is_numbered_one() {
    // ★ The client library's tracker treats a sequence at or below the last as a repeat, so a bus that started at
    // zero would make every subscriber see its first event as one it had already had. The numbering is part of the
    // wire contract, asserted rather than left to `0` being the natural default.
    let bus = bus();
    assert_eq!(bus.next_sequence(), 1);
    assert_eq!(bus.emit(Tick(1)), 1);
    assert_eq!(bus.emit(Tick(2)), 2);
}

#[test]
fn a_delivery_names_the_sequence_of_its_first_event() {
    // ★ The number was assigned by the bus and then thrown away: a subscriber received the events and could not say
    // which numbers they were, so the interface's gap detector — the reason the bus numbers anything — had nothing to
    // compare against. `first_seq + index` is the number of every event in the batch, because a queue is contiguous.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));
    bus.emit(Tick(2));

    let delivery = bus.take(id).expect("two events");
    assert_eq!(delivery.first_seq(), 1);
    assert_eq!(delivery.events(), &[Tick(1), Tick(2)]);

    bus.emit(Tick(3));
    assert_eq!(bus.take(id).expect("one event").first_seq(), 3);
}

#[test]
fn a_delivery_after_an_overflow_says_where_the_gap_is() {
    // The survivors keep their numbers, and `missed` says how many came before the first of them — so a consumer can
    // reconstruct the break rather than guessing from a shorter batch.
    let bus = bus();
    let id = bus.subscribe();
    let total = SUBSCRIBER_QUEUE_CAPACITY + 5;
    for seq in 1..=total {
        bus.emit(Tick(u64::try_from(seq).expect("a count that fits")));
    }

    let delivery = bus.take(id).expect("a delivery");
    assert!(delivery.must_refresh(), "the queue overflowed");
    assert_eq!(delivery.missed(), 5);
    let first = delivery.first_seq();
    assert_eq!(first, delivery.missed() + 1, "the gap sits immediately before the first survivor");
    assert_eq!(delivery.events().len(), SUBSCRIBER_QUEUE_CAPACITY);
}


#[test]
fn the_sequence_is_the_bus_is_not_the_subscribers() {
    // Two subscribers see the same numbers, because the numbers are a property of the stream. A bus per subscriber
    // would give each its own, and two interfaces comparing what they saw would disagree about which event came
    // first.
    let bus = bus();
    let first = bus.subscribe();
    let second = bus.subscribe();

    bus.emit(Tick(1));
    bus.emit(Tick(2));

    assert_eq!(bus.take(first).expect("first").events(), &[Tick(1), Tick(2)]);
    assert_eq!(bus.take(second).expect("second").events(), &[Tick(1), Tick(2)]);
}

#[test]
fn last_sequence_is_none_before_anything_is_emitted() {
    // `next - 1` would be zero, and zero is not a sequence number this bus hands out — a caller comparing it would
    // be comparing against a number that never appears.
    let bus = bus();
    assert_eq!(bus.last_sequence(), None);
    bus.emit(Tick(1));
    assert_eq!(bus.last_sequence(), Some(1));
}

#[test]
fn a_bus_with_no_subscribers_still_numbers_its_events() {
    // The numbering is the kernel's, not a subscriber's. A kernel that only counted when someone was listening
    // would restart its numbering when the last window closed, and an interface that reconnected would see numbers
    // it had already seen.
    let bus: EventBus<Tick> = bus();
    assert_eq!(bus.emit(Tick(1)), 1);
    assert_eq!(bus.emit(Tick(2)), 2);
    let id = bus.subscribe();
    bus.emit(Tick(3));
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(3)]);
    assert_eq!(bus.last_sequence(), Some(3));
}

#[test]
fn the_default_bus_is_empty_and_numbered_from_one() {
    let bus: EventBus<Tick> = EventBus::default();
    assert_eq!(bus.subscriber_count(), 0);
    assert_eq!(bus.next_sequence(), 1);
}
