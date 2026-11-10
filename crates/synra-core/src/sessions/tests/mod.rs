use synra_protocol::handshake::{Agreed, Feature};
use synra_protocol::ids::{DeviceId, SessionId};
use synra_protocol::session::PlatformKind;

use super::identity::SessionKey;
use super::registry::SessionRegistry;

mod accounting;
mod heartbeat;
mod opening;
mod reporting;
mod retention;
mod transitions;

/// Two stable UUIDs, so a test can name the same device twice.
const DEV_A: &str = "11111111-1111-4111-8111-111111111111";
const DEV_B: &str = "22222222-2222-4222-8222-222222222222";
const DEV_C: &str = "33333333-3333-4333-8333-333333333333";
const SESSION_ONE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION_TWO: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn device(name: &str) -> DeviceId {
    // `DeviceId` is a UUID, so the tests name devices by parsing a UUID derived from a short name — which is what
    // the wire does and keeps the fixtures readable.
    name.parse().expect("a valid device id")
}

fn session_id(name: &str) -> SessionId {
    name.parse().expect("a valid session id")
}

/// Opens a session for a device no other fixture uses.
///
/// The identities are freshly generated, because `DeviceId` and `SessionId` are UUIDs and a test that wants to name
/// the same device twice uses [`opened_for`] with one of the constants above.
fn opened(registry: &mut SessionRegistry, name: &str, at: u64) -> SessionKey {
    // The name is kept as a label for the call site's readability; the identity is the registry's.
    let _ = name;
    opened_random(registry, at)
}

/// Opens a session for a device whose identity is fresh.
fn opened_random(registry: &mut SessionRegistry, at: u64) -> SessionKey {
    let (key, _) = registry.open(
        SessionId::new(),
        DeviceId::new(),
        PlatformKind::Desktop,
        at,
    );
    key
}

/// Opens a session for a *named* device, so a test can open a second and see what replaced the first.
fn opened_for(registry: &mut SessionRegistry, device_id: DeviceId, at: u64) -> SessionKey {
    let (key, _) = registry.open(
        SessionId::new(),
        device_id,
        PlatformKind::Desktop,
        at,
    );
    key
}

fn agreed() -> Agreed {
    Agreed { common: vec![Feature::EventStream], missing_required: Vec::new() }
}
