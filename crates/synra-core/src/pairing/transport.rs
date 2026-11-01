//! The sockets the two halves of a first pairing run on.
//!
//! # What sits here, and what deliberately does not
//!
//! The decisions live in [`super::outbound`] and [`super::desk`]; this module only carries them over a connection that is
//! not yet trusted. Keeping it that thin is what lets both halves be tested without a network: a test drives `desk` and
//! `outbound` directly, and only this file needs two sockets.
//!
//! # Why neither side pins the other's certificate
//!
//! Because first pairing is the exchange that *produces* the pin. Both sides present a certificate, both keep the one
//! they saw, and the six digits each screen shows are derived from the two device ids — so the digits only agree when
//! both are talking about the same pair. A person compares them; only then does either side write the other down.
//! `IntroducedStream` is that unpinned connection, and it is a separate type so no ordinary connection can be mistaken
//! for one.
//!
//! # Why the address is recorded from the socket rather than from the request
//!
//! A request carries a profile the asker chose. The address a later link should be dialled at is a fact about where this
//! connection actually came from, so it is read from the socket — taking it from the message would let a device ask to be
//! recorded at an address it does not live at.

use std::net::TcpStream;
use std::time::Duration;

use synra_net::authentication::DeviceCredentials;
use synra_net::authentication::pairing::PAIRING_ALPN;
use synra_net::authentication::IntroducedStream;
use synra_protocol::ids::{DeviceId, RequestId};
use synra_protocol::session::{PairRequest, PairResponse};

use super::{Offer, PairingDesk, wire};

/// How long a first-pairing exchange is given, in both directions.
///
/// Long enough for a person to read six digits on one screen and compare them with another, short enough that a device
/// left in "waiting for an answer" does not hold a socket for a session. The dialer's own clock is the same number, so
/// neither side can be waiting on an answer the other has already given up on by more than a moment.
pub const PATIENCE: Duration = Duration::from_secs(90);

/// What one answered dial produced.
pub struct Answered {
    /// Whether the person this device belongs to agreed.
    pub accepted: bool,
    /// The device that asked, as the connection proved it — not as the message claimed.
    pub peer: DeviceId,
    /// The certificate that device presented, to be written down only if `accepted`.
    pub peer_certificate: Vec<u8>,
    /// The address it is reachable at, for a later link.
    pub address: String,
}

/// Answers one first-pairing dial: read the ask, put it in front of the person, send back what they said.
///
/// # Errors
///
/// [`wire::WireError`] when the handshake or the message fails. A refusal is **not** an error: the peer said no, which is
/// an answer, and reporting it as a failure would tell the caller to tear down a connection that behaved correctly.
pub fn answer(
    stream: TcpStream,
    credentials: &DeviceCredentials,
    desk: &PairingDesk,
    now_ms: i64,
) -> Result<Answered, wire::WireError> {
    let address = stream
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_default();
    let mut session =
        IntroducedStream::accept(stream, credentials, PATIENCE, PAIRING_ALPN, None)
            .map_err(|_| wire::WireError::Io)?;
    let request: PairRequest = wire::read(&mut session)?;
    let peer = request.profile.device_id;
    // The certificate is read *before* the answer is awaited: the handshake is the only moment it is available, and a
    // waiter that returns after the answer must not need the connection to report what it saw.
    let peer_certificate = session.peer_certificate().to_vec();
    let response = match desk.offer_with_certificate(RequestId::new(), request, Some(peer_certificate.clone()), &address, now_ms) {
        Offer::Refused(response) => response,
        Offer::Waiting(waiter) => waiter.wait(PATIENCE),
    };
    wire::write(&mut session, &response)?;
    Ok(Answered {
        accepted: response.accepted,
        peer,
        peer_certificate,
        address,
    })
}

/// Puts one request to a device and reports what it said.
///
/// # Errors
///
/// [`wire::WireError`] when the connection, the handshake or either message fails.
pub fn ask(
    stream: TcpStream,
    credentials: &DeviceCredentials,
    target: DeviceId,
    request: &PairRequest,
) -> Result<PairResponse, wire::WireError> {
    let mut session = IntroducedStream::connect(stream, credentials, target, PATIENCE, PAIRING_ALPN, None)
        .map_err(|_| wire::WireError::Io)?;
    wire::write(&mut session, request)?;
    wire::read(&mut session)
}