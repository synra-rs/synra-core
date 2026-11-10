//! Sync, driven from both devices.
//!
//! The comparison tests are written as the *conversation*: what this device has, what the other one said, and what the
//! sender should do about it. The receiver's tests are written as the attack: a chunk from another round, a package
//! whose bytes are not the ones promised, a transfer declared complete with a hole in it.

use synra_protocol::ids::{DeviceId, PluginId, TransferId};

use super::{RemoteState, SyncSession, SyncSessionId};

mod chunks;
mod decision_policy;
mod inbox;
mod outcome;
mod peer_query;
mod persisted_state;
mod received_bundle;
mod receiver;
mod record;
mod remote_result;
mod remote_state;

fn plugin(name: &str) -> PluginId {
    PluginId::parse(name).expect("a valid plugin id")
}

fn session(name: &str) -> SyncSessionId {
    SyncSessionId::new(name)
}

/// What a device that has the plugin at a version and digest reports.
fn theirs(version: &str, digest: &str) -> RemoteState {
    RemoteState {
        plugin_id: plugin("@acme/chat"),
        version: Some(version.to_owned()),
        digest: Some(digest.to_owned()),
        active: true,
    }
}

/// A session with four chunks.
fn opened() -> SyncSession {
    SyncSession::open(
        session("round-1"),
        plugin("@acme/chat"),
        DeviceId::new(),
        TransferId::new(),
        "1.0.0",
        "sha256-declared",
        4,
    )
    .expect("a session")
}
