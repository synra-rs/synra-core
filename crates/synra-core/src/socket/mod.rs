//! The UDP socket discovery runs on.
//!
//! # What this layer is, and what it is not
//!
//! `synra-protocol`'s discovery module owns the wire format — the two magic prefixes, the JSON, the validation — and is
//! exhaustively tested against it. [`crate::discovery`] owns what to *do* with a datagram once it has been parsed: whether
//! a device is new, whether it moved, how long a candidate stays. Neither of them opens a socket.
//!
//! This is the third piece, and it is deliberately the thinnest of the three: it binds, it sends, it receives, and it
//! hands bytes to one of the other two. Almost everything that could be wrong is already covered elsewhere, and what is
//! left is the part that only a real socket can be wrong about.
//!
//! # The port, and why it is fixed
//!
//! Queries go to [`limits::DISCOVERY_PORT`]. Responses return to the query's UDP source address; the announcement's
//! port is the independent TCP listening endpoint. The responder uses the fixed port and the querier an ephemeral one.
//!
//! One process owns the well-known responder port. Tests bind separate ephemeral ports.
//!
//! # Why a socket that fails to receive is still a usable socket
//!
//! A machine with no network, a firewall, and a sandbox all produce the same thing: sends fail. Discovery is how peers
//! are *found*, not how they are reached, and a kernel that could not start without it would be one that cannot run on a
//! machine with its wireless switched off. Every send here returns its error to the caller, and no caller in this module
//! treats one as fatal — the caller that wants to log them is the one that knows whether they matter.
//!
//! # What is tested
//!
//! A real loopback socket, because the thing that can be wrong is the part only a socket does: that a datagram written
//! by the encoder arrives as the bytes the parser expects, and that the address a reply goes to is the one the query
//! came from. The tests bind port zero rather than the discovery port, so they do not collide with a kernel that happens
//! to be running on the machine.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use synra_protocol::discovery::{
    DeviceAnnouncement, DiscoveryDatagram, OfflineAnnouncement, encode_offline, encode_query,
    encode_response,
};
use synra_protocol::limits;

use crate::discovery::Absorbed;
use crate::host::Host;

/// Why a discovery socket operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SocketError {
    /// The socket could not be created or bound.
    #[error("could not listen on {address}: {why}")]
    Bind {
        /// Where it tried.
        address: SocketAddr,
        /// What the operating system said.
        why: String,
    },

    /// A datagram could not be sent.
    #[error("could not send to {address}: {why}")]
    Send {
        /// Where it was going.
        address: SocketAddr,
        /// What the operating system said.
        why: String,
    },

    /// A datagram could not be received.
    #[error("could not receive: {why}")]
    Receive {
        /// What the operating system said.
        why: String,
    },

    /// The datagram was not one this protocol recognises.
    ///
    /// # Why an unrecognised datagram is an error and not a variant
    ///
    /// Because this socket is on a well-known port that anything on the network may send to — a port scan, another
    /// product's discovery, a stray packet. The protocol's parser is written the same way, and for the same reason: a
    /// datagram this build does not understand is *reported* so a caller can count it or ignore it, and it must not be
    /// confused with a device that said something wrong.
    #[error("the datagram is not a synra announcement: {why}")]
    Malformed {
        /// What the parser said.
        why: String,
    },

    /// A datagram could not be encoded.
    #[error("the announcement could not be encoded: {why}")]
    Encode {
        /// What the encoder said.
        why: String,
    },
}

/// A socket discovery runs on.
#[derive(Debug)]
pub struct DiscoverySocket {
    socket: UdpSocket,
}

impl DiscoverySocket {
    /// Binds the discovery port on every interface.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when the address is taken or unusable.
    pub fn bind_default() -> Result<Self, SocketError> {
        Self::bind(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            limits::DISCOVERY_PORT,
        )))
    }

    /// Binds a chosen address.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when the address is taken or unusable.
    pub fn bind(address: SocketAddr) -> Result<Self, SocketError> {
        let socket = bind_reusable(address)?;
        // ★ Broadcast is off by default on every platform, and `send_to` to a broadcast address fails without it. Set
        // here rather than at each send, because a socket that has to remember to enable it is one that will forget.
        socket
            .set_broadcast(true)
            .map_err(|error| SocketError::Bind {
                address,
                why: format!("broadcast could not be enabled: {error}"),
            })?;
        Ok(Self { socket })
    }

    /// The address actually bound.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when it cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, SocketError> {
        self.socket.local_addr().map_err(|error| SocketError::Bind {
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            why: error.to_string(),
        })
    }

    /// How long a receive waits before reporting that nothing came.
    ///
    /// # Errors
    ///
    /// [`SocketError::Receive`] when the option cannot be set.
    pub fn set_read_timeout(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> Result<(), SocketError> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|error| SocketError::Receive {
                why: error.to_string(),
            })
    }

    /// Sends a query, asking whoever is listening to answer.
    ///
    /// # Errors
    ///
    /// [`SocketError::Encode`] for an unusable announcement, and [`SocketError::Send`] when the send fails.
    pub fn send_query(
        &self,
        ours: &DeviceAnnouncement,
        to: SocketAddr,
    ) -> Result<usize, SocketError> {
        let bytes = encode_query(ours).map_err(|error| SocketError::Encode {
            why: error.to_string(),
        })?;
        self.send_bytes(&bytes, to)
    }

    /// Answers a query, which the protocol says is unicast back to where the query came from.
    ///
    /// # Errors
    ///
    /// As [`DiscoverySocket::send_query`].
    pub fn send_response(
        &self,
        ours: &DeviceAnnouncement,
        to: SocketAddr,
    ) -> Result<usize, SocketError> {
        let bytes = encode_response(ours).map_err(|error| SocketError::Encode {
            why: error.to_string(),
        })?;
        self.send_bytes(&bytes, to)
    }

    /// Announces that this device is leaving.
    ///
    /// # Errors
    ///
    /// As [`DiscoverySocket::send_query`].
    pub fn send_offline(
        &self,
        offline: &OfflineAnnouncement,
        to: SocketAddr,
    ) -> Result<usize, SocketError> {
        let bytes = encode_offline(offline).map_err(|error| SocketError::Encode {
            why: error.to_string(),
        })?;
        self.send_bytes(&bytes, to)
    }

    /// Sends raw bytes, counting them.
    fn send_bytes(&self, bytes: &[u8], to: SocketAddr) -> Result<usize, SocketError> {
        self.socket
            .send_to(bytes, to)
            .map_err(|error| SocketError::Send {
                address: to,
                why: error.to_string(),
            })
    }

    /// Sends a query to every broadcast address this machine has.
    ///
    /// # Why this returns a count of what it reached
    ///
    /// Because "nothing was found" and "nothing could be asked" are different answers, and a caller that showed the user
    /// an empty list for both would be one that cannot tell them their firewall is the problem. A failure to send to one
    /// interface is not a failure of the scan: a machine with a loopback and a wireless card may reach only one.
    #[must_use]
    pub fn broadcast_query(
        &self,
        ours: &DeviceAnnouncement,
    ) -> Vec<(SocketAddr, Result<usize, SocketError>)> {
        self.broadcast_targets()
            .into_iter()
            .map(|address| (address, self.send_query(ours, address)))
            .collect()
    }

    /// Sends an offline announcement to every broadcast address.
    #[must_use]
    pub fn broadcast_offline(
        &self,
        offline: &OfflineAnnouncement,
    ) -> Vec<(SocketAddr, Result<usize, SocketError>)> {
        self.broadcast_targets()
            .into_iter()
            .map(|address| (address, self.send_offline(offline, address)))
            .collect()
    }

    fn broadcast_targets(&self) -> Vec<SocketAddr> {
        let bound = self
            .local_addr()
            .ok()
            .and_then(|address| match address.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        interfaces::addresses_for(bound)
    }
}

mod receive;
pub use receive::{absorb, is_about};
mod interfaces;
pub use interfaces::broadcast_addresses;

/// Binds a socket.
///
/// # Why there is no `SO_REUSEPORT` here
///
/// The first version of this reached for `socket2` to set it, on the reasoning that two kernels on one machine both want
/// the discovery port. That reasoning was wrong, and checking the design rather than assuming is what showed it: the
/// port is a **singleton per host**. Two kernels on one machine do not both discover — they would both answer every
/// query, and a peer would receive two responses from one address with different device identifiers.
///
/// So the plain bind is the correct behaviour, and it is why the second kernel on a machine *should* fail here: it is
/// already running, or it is a second profile that has to be given a different port. The dependency this avoids would
/// have bought the ability to do the wrong thing.
///
/// On Unix, `std` sets `SO_REUSEADDR` on a UDP socket already, which is what lets a socket rebind an address whose
/// previous owner has closed. That is a restart, not a second kernel, and it is exactly the behaviour that is wanted.
fn bind_reusable(address: SocketAddr) -> Result<UdpSocket, SocketError> {
    if !matches!(address, SocketAddr::V4(_)) {
        return Err(SocketError::Bind {
            address,
            why: "discovery is IPv4 only".to_owned(),
        });
    }
    UdpSocket::bind(address).map_err(|error| SocketError::Bind {
        address,
        why: error.to_string(),
    })
}

#[cfg(test)]
mod tests;
