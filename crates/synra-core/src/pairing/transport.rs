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
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_net::authentication::DeviceCredentials;
use synra_net::authentication::IntroducedStream;
use synra_net::authentication::pairing::{PAIRING_ALPN, PairingChannel};
use synra_protocol::ids::{DeviceId, RequestId};
use synra_protocol::session::{PairRequest, PairResponse};
use synra_store::SynraDb;

use super::{Offer, PairingDesk, wire};
use crate::peer_trust::PairingTask;

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
    db: &Arc<Mutex<SynraDb>>,
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
    // ★ The answer above is this protocol's reply, not permission. The grant is what a later connection checks, so it is
    // written here, on the connection the person actually approved — and a refusal to record it is reported, because a
    // pairing that only looked successful would leave two devices refusing each other with nothing to show for it.
    if response.accepted {
        grant(db, credentials, session, peer, now_ms)?;
    }
    Ok(Answered {
        accepted: response.accepted,
        peer,
        peer_certificate,
        address,
    })
}

/// Records the pair both people just agreed to, on the connection they agreed over.
///
/// # Errors
///
/// [`wire::WireError::Trust`] when the certificate cannot be adopted, the task slot is taken, or the durable grant fails.
fn grant(
    db: &Arc<Mutex<SynraDb>>,
    credentials: &DeviceCredentials,
    session: IntroducedStream,
    peer: DeviceId,
    now_ms: i64,
) -> Result<(), wire::WireError> {
    let now_seconds = u64::try_from(now_ms / 1000).unwrap_or_default();
    let channel = PairingChannel::adopt(session, credentials, peer, now_seconds)
        .map_err(|_| wire::WireError::Trust)?;
    let task = PairingTask::begin(Arc::clone(db), channel, now_ms).map_err(|_| wire::WireError::Trust)?;
    task.finish(true, PATIENCE, || synra_store::sqlite::now_ms())
        .map_err(|_| wire::WireError::Trust)?;
    Ok(())
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
    db: &Arc<Mutex<SynraDb>>,
    now_ms: i64,
) -> Result<PairResponse, wire::WireError> {
    let mut session = IntroducedStream::connect(stream, credentials, target, PATIENCE, PAIRING_ALPN, None)
        .map_err(|_| wire::WireError::Io)?;
    wire::write(&mut session, request)?;
    let response: PairResponse = wire::read(&mut session)?;
    // ★ The asker records the pair too. Both sides run the same exchange on the same connection, so a grant that only one
    // of them wrote would be a half pair — trusted by the device that decided and refused by the device that asked.
    if response.accepted {
        grant(db, credentials, session, target, now_ms)?;
    }
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Instant;
    use synra_protocol::session::{PeerProfile, PlatformKind};
    use synra_testkit::authentication::NetworkFixture;

    /// A profile for one fixture, the way a real dialer fills it in.
    fn profile(fixture: &NetworkFixture, name: &str) -> PeerProfile {
        PeerProfile {
            device_id: fixture.credentials.public_identity().device_id(),
            display_name: name.to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "test".to_owned(),
        }
    }

    /// Both devices must be trusted afterwards, or "paired" means nothing.
    ///
    /// # Why this test exists
    ///
    /// The screen showing two devices as paired is drawn from `paired_devices`; every later connection is allowed by
    /// `trusted_peer_records`. A first pairing that wrote only the first table would look finished and behave as if it had
    /// never happened, and nothing else in the suite would notice — the invitation tests write both tables through
    /// `PairingService`, which is exactly the code the first-pairing path does not go through.
    #[test]
    fn a_first_pairing_leaves_both_sides_trusted() {
        let a = NetworkFixture::unpaired(DeviceId::new(), "A").unwrap();
        let b = NetworkFixture::unpaired(DeviceId::new(), "B").unwrap();
        let b_id = b.credentials.public_identity().device_id();
        let now_ms = i64::try_from(a.now_ms).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let desk = Arc::new(PairingDesk::new(b_id, PATIENCE));
        let b_db = Arc::clone(&b.shared_db);
        let b_credentials = Arc::clone(&b.credentials);
        let server_desk = Arc::clone(&desk);
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            answer(socket, &b_credentials, &server_desk, &b_db, now_ms)
        });

        // The person on the asking device is looking at six digits and the person on the other one says yes.
        let clicker = Arc::clone(&desk);
        let clicking = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some((_, request)) = clicker.pending().first().copied() {
                    assert!(clicker.answer(request, true, |_| Ok(())).is_some());
                    return;
                }
                assert!(Instant::now() < deadline, "no prompt was ever raised");
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let a_db = Arc::clone(&a.shared_db);
        let request = PairRequest {
            profile: profile(&a, "A"),
            user_hint: None,
        };
        let socket = TcpStream::connect(address).unwrap();
        let response = ask(socket, &a.credentials, b_id, &request, &a_db, now_ms).unwrap();
        assert!(response.accepted);
        server.join().unwrap().unwrap();
        clicking.join().unwrap();

        for (fixture, name) in [(&a, "A"), (&b, "B")] {
            let approved = crate::peer_trust::approved_peers(
                &fixture.shared_db,
                &fixture.credentials,
                fixture.now_ms / 1000,
            )
            .unwrap();
            assert_eq!(approved.len(), 1, "{name} did not record the pair");
        }
    }
}
