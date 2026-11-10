//! Host fixtures shared by network and state scenarios.

use std::net::{Ipv4Addr, SocketAddr};

use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

use crate::identity::Identity;
use crate::link::PeerLink;
use crate::peer::{Flags, LocalPeer};

use super::{Host, reading_millis};

mod endpoint;
mod discovery;
mod handshake;
mod lifecycle;
mod messaging;
mod naming;
mod resolution;

const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";

fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

/// A host with an identity and a local peer, and a migrated database behind the identity.
fn host(id: &str, name: &str) -> (Host, synra_testkit::fixtures::NetworkFixture) {
    let db = synra_testkit::fixtures::NetworkFixture::unpaired(device(id), name).expect("fixture");
    let identity = Identity::load(&db, "test", 1_000).expect("identity");
    let local = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        PlatformKind::Desktop,
        "0.1.0-test",
    );
    let host = Host::with_flags(identity, local, Flags::no_timeout());
    (host, db)
}

fn network_now() -> u64 {
    reading_millis(synra_store::sqlite::now_ms())
}

/// A host that is listening, with its address.
fn listening(id: &str, name: &str) -> (Host, synra_testkit::fixtures::NetworkFixture, SocketAddr) {
    let (mut host, db) = host(id, name);
    let address = host
        .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binds");
    (host, db, address)
}

fn client_link_peer(link: &PeerLink) -> DeviceId {
    link.peer()
}

fn client_link_local(link: &PeerLink) -> DeviceId {
    link.local()
}
