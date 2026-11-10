use crate::error::ErrorCode;
use crate::event::{builtin, events, DataPlaneEvent, EventName};
use crate::ids::DeviceId;
use super::super::{Inbound, UnknownReason, inbound_error_to_synra};
use super::{slug, envelope};

#[test]
fn transport_events_are_never_plugin_visible() {
    // A plugin that could observe or inject these would be inside the transport rather than on
    // top of it.
    let (a, b) = (DeviceId::new(), DeviceId::new());
    for name in [
        events::HELLO,
        events::HELLO_ACK,
        events::ACK,
        events::PING,
        events::PONG,
        events::BYE,
        events::ERROR,
    ] {
        let inbound = Inbound::classify(envelope(name, a, b));
        assert!(matches!(inbound, Inbound::Transport { .. }), "{name}");
        assert!(!inbound.is_plugin_visible(), "{name}");
        assert!(!inbound.is_ignorable(), "{name}");
    }
}

#[test]
fn kernel_events_are_never_plugin_visible() {
    // These drive the kernel's own sessions. A plugin able to see them could observe every
    // intent the user dispatches.
    let (a, b) = (DeviceId::new(), DeviceId::new());
    for name in [
        events::INTENT_INVOKE,
        events::INTENT_RESULT,
        events::INTENT_CANCEL,
        events::PLUGIN_QUERY,
        events::PLUGIN_QUERY_REPLY,
        events::PLUGIN_SYNC_RESULT,
    ] {
        let inbound = Inbound::classify(envelope(name, a, b));
        assert!(matches!(inbound, Inbound::Kernel { .. }), "{name}");
        assert!(!inbound.is_plugin_visible(), "{name}");
    }
}

#[test]
fn builtin_events_are_plugin_visible() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    for name in builtin::ALL {
        let inbound = Inbound::classify(envelope(name, a, b));
        assert!(matches!(inbound, Inbound::Builtin { .. }), "{name}");
        assert!(inbound.is_plugin_visible(), "{name}");
    }
}

#[test]
fn data_plane_events_are_classified_as_such() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    for event in [
        DataPlaneEvent::FileTransferRequest,
        DataPlaneEvent::FileTransferChunk,
        DataPlaneEvent::FileTransferComplete,
        DataPlaneEvent::FileTransferAbort,
        DataPlaneEvent::FileTransferProgress,
    ] {
        let inbound = Inbound::classify(envelope(event.as_str(), a, b));
        match inbound {
            Inbound::DataPlane { event: got, .. } => assert_eq!(got, event),
            other => panic!("expected a data-plane event, got {other:?}"),
        }
        assert!(inbound.is_plugin_visible());
    }
}

#[test]
fn plugin_events_report_their_owner() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let inbound = Inbound::classify(envelope("_plugin.@acme/chat.text", a, b));
    match inbound {
        Inbound::Plugin { owner, .. } => assert_eq!(owner, slug("chat")),
        other => panic!("expected a plugin event, got {other:?}"),
    }
}

#[test]
fn an_unknown_builtin_is_recorded_and_ignored() {
    // A newer peer may send an event this version has never heard of. The frames are perfectly
    // readable, so refusing the link would make a version difference look like corruption.
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let inbound = Inbound::classify(envelope("_synra.device.teleported", a, b));

    match &inbound {
        Inbound::Unknown { reason, .. } => {
            assert_eq!(*reason, UnknownReason::NotInCatalogue);
        }
        other => panic!("expected an unknown event, got {other:?}"),
    }
    assert!(inbound.is_ignorable(), "an unknown built-in must not break the link");
    assert!(!inbound.is_plugin_visible(), "nobody can have subscribed to it");
}

#[test]
fn an_unknown_data_plane_event_is_not_ignorable() {
    // Data-plane events drive a transfer state machine. Silently ignoring one leaves the
    // transfer stuck with no error anywhere, which is worse than a clear refusal.
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let inbound = Inbound::classify(envelope("file.transfer.teleport", a, b));

    match &inbound {
        Inbound::Unknown { reason, .. } => {
            assert_eq!(*reason, UnknownReason::UnrecognisedDataPlane);
        }
        other => panic!("expected an unknown data-plane event, got {other:?}"),
    }
    assert!(!inbound.is_ignorable());

    let error = inbound_error_to_synra(UnknownReason::UnrecognisedDataPlane, inbound.event());
    assert_eq!(error.code, ErrorCode::ProtocolViolation);
}

#[test]
fn an_unknown_builtin_maps_to_not_found() {
    let name = EventName::parse("_synra.device.teleported").expect("valid");
    let error = inbound_error_to_synra(UnknownReason::NotInCatalogue, &name);
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn every_classified_message_keeps_its_envelope() {
    let (a, b) = (DeviceId::new(), DeviceId::new());
    let original = envelope("_plugin.@acme/chat.text", a, b);
    let request_id = original.request_id;

    for inbound in [
        Inbound::classify(envelope("device.ping", a, b)),
        Inbound::classify(envelope(builtin::DEVICE_CHANGED, a, b)),
        Inbound::classify(envelope("file.transfer.chunk", a, b)),
        Inbound::classify(original),
        Inbound::classify(envelope("_synra.unknown.thing", a, b)),
    ] {
        assert_eq!(inbound.envelope().from, a);
        assert_eq!(inbound.envelope().target, b);
        // And the message can be taken back out without losing anything.
        let recovered = inbound.into_envelope();
        assert_eq!(recovered.from, a);
    }

    assert_ne!(request_id, crate::ids::RequestId::new());
}
