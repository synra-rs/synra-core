use std::net::Ipv4Addr;

use synra_protocol::envelope::OutboundSpec;
use synra_protocol::event::EventName;
use synra_protocol::ids::TraceId;

use super::{DeviceId, Envelope, Flags, LinkStream, PeerLink, TcpStream};

mod blocks;
mod connection;
mod deadlines;
mod envelopes;
mod memory;
mod refusals;

const LOCAL: &str = "11111111-1111-4111-8111-111111111111";
const PEER: &str = "22222222-2222-4222-8222-222222222222";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";

fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

/// A pair of connected sockets, as an established link would have.
fn connected() -> (TcpStream, TcpStream) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds");
    let address = listener.local_addr().expect("an address");
    let dialer = TcpStream::connect(address).expect("connects");
    let (accepted, _) = listener.accept().expect("accepts");
    (dialer, accepted)
}

fn agreed() -> synra_protocol::handshake::Agreed {
    synra_protocol::handshake::Agreed {
        common: vec![synra_protocol::handshake::Feature::EventStream],
        missing_required: Vec::new(),
    }
}

fn link_with_timeout(
    stream: TcpStream,
    local: &str,
    peer: &str,
    timeout: std::time::Duration,
) -> PeerLink {
    PeerLink::new(
        stream,
        device(local),
        device(peer),
        agreed(),
        Flags {
            timeout: Some(timeout),
        },
    )
}

/// A link over anything that carries bytes.
fn link_with_stream(stream: impl LinkStream + 'static, local: &str, peer: &str) -> PeerLink {
    PeerLink::new(
        stream,
        device(local),
        device(peer),
        agreed(),
        Flags::no_timeout(),
    )
}

fn link(stream: TcpStream, local: &str, peer: &str) -> PeerLink {
    link_with_stream(stream, local, peer)
}

/// An envelope from `from` to `target`.
fn envelope(from: &str, target: &str, event: &str) -> Envelope {
    Envelope::outbound(
        OutboundSpec {
            event: EventName::parse(event).expect("a valid event name"),
            target: device(target),
            from: device(from),
            trace_id: TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: Some(60_000),
        },
        None::<&serde_json::Value>,
    )
    .expect("builds")
}
