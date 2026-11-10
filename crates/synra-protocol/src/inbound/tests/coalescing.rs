use crate::event::{builtin, EventName};
use crate::ids::DeviceId;
use super::super::{BuiltinEvent, Inbound, CoalesceBuffer, coalescable_names};
use super::envelope;

#[test]
fn only_high_frequency_events_are_coalescable() {
    assert_eq!(
        coalescable_names(),
        &[builtin::TRANSFER_PROGRESS, builtin::NETWORK_CHANGED]
    );

    let progress = BuiltinEvent::parse(
        &EventName::parse(builtin::TRANSFER_PROGRESS).expect("valid"),
        None,
    )
    .expect("a known built-in");
    assert!(progress.is_coalescable());
    assert_eq!(progress.name(), builtin::TRANSFER_PROGRESS);

    // A business event must never be coalesced: dropping one silently is not the same as
    // dropping a stale progress report.
    let completed = BuiltinEvent::parse(
        &EventName::parse(builtin::TRANSFER_COMPLETED).expect("valid"),
        None,
    )
    .expect("a known built-in");
    assert!(!completed.is_coalescable());

    for name in coalescable_names() {
        assert!(
            name.starts_with("_synra."),
            "{name} is coalescable but is not a host progress event",
        );
    }
}

#[test]
fn a_progress_report_replaces_its_predecessor() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let mut buffer = CoalesceBuffer::new();

    assert!(!buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b))));
    assert_eq!(buffer.len(), 1);

    // The second one is coalesced, so a slow consumer sees the current state rather than a
    // queue of history.
    assert!(buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b))));
    assert_eq!(buffer.len(), 1);
}

#[test]
fn a_coalesced_entry_keeps_its_place_in_the_queue() {
    // Moving it to the end would reorder it behind events that arrived later but matter less.
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let mut buffer = CoalesceBuffer::new();

    buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b)));
    buffer.push(Inbound::classify(envelope(builtin::DEVICE_CHANGED, a, b)));
    buffer.push(Inbound::classify(envelope(builtin::NETWORK_CHANGED, a, b)));
    buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b)));

    let drained = buffer.drain();
    assert_eq!(drained.len(), 3);
    assert_eq!(drained[0].event.as_str(), builtin::TRANSFER_PROGRESS);
    assert_eq!(drained[1].event.as_str(), builtin::DEVICE_CHANGED);
    assert_eq!(drained[2].event.as_str(), builtin::NETWORK_CHANGED);
    assert!(buffer.is_empty());
}

#[test]
fn ordinary_events_are_never_dropped_by_coalescing() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let mut buffer = CoalesceBuffer::new();

    for _ in 0..5 {
        buffer.push(Inbound::classify(envelope(builtin::PLUGIN_INSTALLED, a, b)));
    }
    // Five distinct events, five entries: a business event is not superseded by the next one.
    assert_eq!(buffer.len(), 5);
}

#[test]
fn draining_empties_the_buffer() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let mut buffer = CoalesceBuffer::new();
    buffer.push(Inbound::classify(envelope(builtin::HOST_FOREGROUND, a, b)));

    assert_eq!(buffer.drain().len(), 1);
    assert!(buffer.is_empty());
    assert!(buffer.drain().is_empty());
}
