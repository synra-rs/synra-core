//! Transfers over a real link, with both peers driven together.

use synra_protocol::envelope::Envelope;
use synra_protocol::ids::{DeviceId, TraceId};

use crate::link::PeerLink;
use crate::peer::Flags;

use super::wire::{Message, envelope_for};

const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";

fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

/// Two connected links, as a session would have.
///
/// ★ Over memory rather than over a socket, and that is the point of the signature above it.
///
/// These tests used to open a `TcpListener`, connect, and accept — three system calls per test to move bytes between two
/// halves of one process — because `PeerLink` held a concrete `TcpStream` and there was nothing else to build one from.
/// `04 §11` records what that cost: the design's end-to-end tests were unwritable, since the only link that existed
/// needed a socket and `synra-testkit`'s transport moves frames rather than bytes.
///
/// The suite is the proof that the seam carries real work: everything below this helper — proposing a transfer, writing
/// blocks through a window, reading reports, confirming — now runs with no socket at all.
fn connected() -> (PeerLink, PeerLink) {
    let (dialer, accepted) = crate::link::memory::MemoryStream::pair();
    let agreed = synra_protocol::handshake::Agreed {
        common: Vec::new(),
        missing_required: Vec::new(),
    };
    (
        PeerLink::new(dialer, device(A), device(B), agreed.clone(), Flags::no_timeout()),
        PeerLink::new(accepted, device(B), device(A), agreed, Flags::no_timeout()),
    )
}

fn later() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(10)
}

/// An envelope carrying a throwaway payload of the right event.
fn envelope_of(message: Message) -> Envelope {
    envelope_for(message, device(A), device(B), TraceId::new(), 0, &serde_json::json!({}))
        .expect("builds")
}

mod wire;
mod exchange;
mod retransmission;
mod round_trip;
mod receiving;
