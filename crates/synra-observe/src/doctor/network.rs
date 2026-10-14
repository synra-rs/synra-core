//! The probes the network stack answers: TCP, discovery, loopback, and the firewall hint.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};

use super::{HostFacts, ProbeResult};

/// Whether a TCP port can be bound.
///
/// Binding is the only honest test: asking the operating system whether a port is free and then binding it
/// leaves a window in which another process takes it, and the answer arrives before the question was really
/// asked.
#[must_use]
pub fn probe_port_available(name: &str, port: u16) -> ProbeResult {
    match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)) {
        Ok(listener) => {
            // Released immediately, so the real listener can take it.
            drop(listener);
            ProbeResult::ok(name, format!("port {port} is free"))
        }
        Err(error) => ProbeResult::fail(
            name,
            format!("port {port} cannot be bound: {error}"),
            format!(
                "close whatever else is using port {port}, or choose another port in \
                 Settings → Network"
            ),
        ),
    }
}

/// Whether the discovery socket can be bound.
///
/// Checked separately from TCP because they are different protocols: a process holding the UDP port does not
/// appear in the TCP probe, and discovery is the feature that breaks when it is taken.
#[must_use]
pub fn probe_udp_port_available(port: u16) -> ProbeResult {
    match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)) {
        Ok(socket) => {
            drop(socket);
            ProbeResult::ok("discovery_udp_available", format!("UDP port {port} is free"))
        }
        Err(error) => ProbeResult::fail(
            "discovery_udp_available",
            format!("UDP port {port} cannot be bound: {error}"),
            "another discovery service may be running; close it, or turn off local discovery",
        ),
    }
}

/// Whether there is a usable network interface.
///
/// Standard library only, so this cannot enumerate interfaces on every platform. What it can do — and what
/// catches the case users actually hit — is check whether a loopback connection works at all. A machine with
/// no network stack fails here.
#[must_use]
pub fn probe_network_interfaces() -> ProbeResult {
    // A loopback TCP bind proves the stack is present. Enumerating interfaces needs a platform API, which is
    // the application layer's business; this is the part that is portable and still catches the real failure.
    match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
        Ok(listener) => {
            let port = listener.local_addr().map(|addr| addr.port()).unwrap_or(0);
            drop(listener);
            ProbeResult::ok("network_stack", format!("loopback works (bound port {port})"))
        }
        Err(error) => ProbeResult::fail(
            "network_stack",
            format!("loopback binding failed: {error}"),
            "the network stack looks unavailable; a firewall or a sandbox may be blocking it",
        ),
    }
}

/// A platform-specific firewall note, when the host has one.
#[must_use]
pub fn probe_firewall_hint(host: &HostFacts) -> ProbeResult {
    match &host.firewall_hint {
        Some(hint) => ProbeResult::warn(
            "firewall",
            hint.clone(),
            "allow Synra through the firewall so your other devices can reach it",
        ),
        None => ProbeResult::ok("firewall", "no firewall advice for this platform"),
    }
}
