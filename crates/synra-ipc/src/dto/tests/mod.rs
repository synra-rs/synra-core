//! Interface DTO wire format and privacy tests.

use core::str::FromStr;

use synra_protocol::{DeviceId, IntentId, PluginId, TransferId};

/// A device id from a fixed string.
///
/// Fixed so a round-trip test compares the *same* value rather than two fresh ones: a test that generated a new
/// id on each side would fail while proving nothing. Built by parsing rather than from a raw UUID because the
/// newtypes keep their inner value private, which is the point of them.
fn fixed_device_id(text: &str) -> DeviceId {
    DeviceId::from_str(text).expect("a valid uuid")
}

/// A transfer id from a fixed string.
fn fixed_transfer_id(text: &str) -> TransferId {
    TransferId::from_str(text).expect("a valid uuid")
}

/// A plugin id.
///
/// The protocol validates a plugin id rather than accepting a bare string, so a test that wants one has to
/// build a valid one — which is the same constraint the manifest loader has.
fn plugin_id() -> PluginId {
    PluginId::parse("@synra-plugin/chat").expect("a valid plugin id")
}

/// A transfer id.
fn transfer_id() -> TransferId {
    TransferId::new()
}

/// An intent id.
fn intent_id() -> IntentId {
    IntentId::new()
}

mod devices;
mod intents;
mod transfers;
mod plugins;
mod configuration;
mod diagnostics;
mod privacy;
