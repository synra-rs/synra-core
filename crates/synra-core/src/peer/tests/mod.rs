//! The peer layer's tests: a real dialer against a real acceptor, over a real loopback socket.
//!
//! The types here are the ones that cross the wire, so a test that stubbed the transport would be a test of the stub
//! - and the bug this layer can have is a mismatch between what one side writes and the other reads.

use std::net::{Ipv4Addr, TcpListener};

use synra_protocol::session::PlatformKind;

use crate::test_support::device;

use super::LocalPeer;

const DIALER: &str = "11111111-1111-4111-8111-111111111111";
const ACCEPTOR: &str = "22222222-2222-4222-8222-222222222222";

fn peer(id: &str, name: &str, platform: PlatformKind) -> LocalPeer {
    LocalPeer::new(device(id), name, platform, "0.1.0-test")
}

/// A listener on a free loopback port.
fn listener() -> TcpListener {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds a loopback port")
}

mod exchange;
mod features;
mod outcomes;
