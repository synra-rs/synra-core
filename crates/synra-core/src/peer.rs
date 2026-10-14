//! The first conversation two devices have.
//!
//! # What the handshake buys
//!
//! Before any work crosses a link, both ends agree on four things:
//!
//! * **Which protocol version.** A peer speaking a different one is refused, rather than failing on the third message
//!   with a decode error about a field neither end can name.
//! * **Which device is on the other end.** The identifier is what a pairing is recorded against, so learning it here is
//!   what makes every later message attributable.
//! * **Which features both have.** Negotiated once so that a transfer does not discover mid-way that the peer cannot
//!   resume it.
//! * **Whether this is a reconnection.** A presented token is checked against the pairings this device holds, and the
//!   answer distinguishes "still paired" from "I have no record of you" — which is not the same as a refusal, because the
//!   other device may have been reset.
//!
//! # Why the exchange is two messages and not a stream of them
//!
//! A dialer sends `Hello`, an acceptor answers `HelloAck`, and the link is ready. The protocol's own frames carry the
//! payloads, so there is nothing to negotiate step by step: an acceptor that needed a second round trip would be one
//! where a peer's features are unknown to the other end until after it has already decided something.
//!
//! # Why the socket is blocking
//!
//! Because the work on this channel is one exchange and then frames in both directions, and a kernel's peer link is one
//! connection per peer — a handful. An async runtime here would be a runtime, a task per link and a `Send` bound on
//! everything the peer layer touches, paid for concurrency a handful of links does not need. The daemon already runs
//! threads.
//!
//! # What is tested, and how
//!
//! The integration tests open a **real loopback socket** and run a real dialer against a real acceptor. The types here
//! are the ones that cross the wire, so a test that stubbed the transport would be a test of the stub — and the bug this
//! layer can have is a mismatch between what one side writes and the other reads.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use bytes::Bytes;
use synra_protocol::frame::{
    Frame, FrameBody, FrameDecoder, FrameEncoder, FrameError, FrameKind,
};
use synra_protocol::handshake::{
    Agreed, Feature, Hello, HelloAck, LinkToken, PROTOCOL_VERSION, PairingState, SessionNonce,
};
use synra_protocol::ids::DeviceId;
use synra_protocol::limits;
use synra_protocol::session::PlatformKind;

/// What a device says about itself during a handshake.
///
/// # Why this is not `synra_core::Identity`
///
/// The identity is the kernel's and lives with the database; this is what the **wire** needs, which is the identity plus
/// the features this build has. Depending on the kernel from here would put a database behind a network layer, and a test
/// of an exchange would need one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPeer {
    /// Which device this is.
    pub device_id: DeviceId,
    /// The name to show the other user.
    pub display_name: String,
    /// Which platform.
    pub platform: PlatformKind,
    /// This build, for support conversations.
    pub app_version: String,
    /// What this build can do.
    pub features: Vec<Feature>,
    /// The features without which it would rather not connect.
    pub requires: Vec<Feature>,
}

impl LocalPeer {
    /// The features every build of this kernel has.
    ///
    /// A hand-written list with a test that checks it against the protocol's own catalogue, because the failure is
    /// silent: a build that forgot to announce a feature it implements would be one whose peers decline to use it, and
    /// nothing would say why.
    #[must_use]
    pub fn default_features() -> Vec<Feature> {
        // `Feature::ALL` is the protocol's catalogue, and announcing all of it is the honest answer for a build that has
        // no feature gate of its own. A build that gained one would subtract here rather than list from scratch.
        Feature::ALL.to_vec()
    }

    /// Builds one with the default features.
    #[must_use]
    pub fn new(
        device_id: DeviceId,
        display_name: impl Into<String>,
        platform: PlatformKind,
        app_version: impl Into<String>,
    ) -> Self {
        Self {
            device_id,
            display_name: display_name.into(),
            platform,
            app_version: app_version.into(),
            features: Self::default_features(),
            requires: Vec::new(),
        }
    }

    /// What this device announces to the network.
    ///
    /// # Why the port is an argument
    ///
    /// Because it is the **connection** port — where a peer opens a TCP link — and this type does not hold it: the
    /// listener is bound by the daemon, after the local peer is built. A `LocalPeer` that guessed would announce a port
    /// nothing is listening on, which is a device that appears in every list and cannot be connected to.
    ///
    /// # Why not every feature is announced
    ///
    /// `DeviceAnnouncement`'s feature list is a *hint*, and the protocol says so: discovery is unauthenticated, and the
    /// handshake is where ability is established. Announcing them anyway is what lets a peer skip an obviously
    /// incompatible candidate without a connection attempt.
    #[must_use]
    pub fn announcement(&self, port: u16) -> synra_protocol::discovery::DeviceAnnouncement {
        synra_protocol::discovery::DeviceAnnouncement {
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            protocol: PROTOCOL_VERSION,
            port,
            platform: Some(self.platform),
            app_version: Some(self.app_version.clone()),
            features: self.features.clone(),
        }
    }

    /// The `Hello` this device sends.
    #[must_use]
    pub fn hello(&self, nonce: SessionNonce, sequence: u64) -> Hello {
        Hello {
            protocol: PROTOCOL_VERSION,
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            platform: self.platform,
            app_version: self.app_version.clone(),
            nonce,
            features: self.features.clone(),
            requires: self.requires.clone(),
            token: None,
            sequence,
            endpoints: Vec::new(),
        }
    }

    /// The `HelloAck` this device sends in answer.
    ///
    /// # Why the pairing state is an argument
    ///
    /// Because deciding it needs the pairing store, which this layer does not have. An acceptor that guessed would be one
    /// that told a peer it was still paired when it was not — and the peer would then send work the other end cannot
    /// attribute.
    #[must_use]
    pub fn hello_ack(&self, nonce: SessionNonce, pairing: PairingState, sequence: u64) -> HelloAck {
        HelloAck {
            protocol: PROTOCOL_VERSION,
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            platform: self.platform,
            app_version: self.app_version.clone(),
            nonce,
            features: self.features.clone(),
            requires: self.requires.clone(),
            pairing,
            refusal: None,
            sequence,
            endpoints: Vec::new(),
        }
    }
}

/// Why a handshake failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The stream failed.
    #[error("the connection failed: {why}")]
    Transport {
        /// What the operating system said.
        why: String,
    },

    /// The connection was closed before the handshake finished.
    ///
    /// # Why this is its own variant
    ///
    /// Because it is the ordinary shape of a peer that gave up, a scan that probed a port and left, and a user who
    /// closed a laptop — and a caller that had to tell it apart from a decode error would be one that logged a fault for
    /// every port scan.
    #[error("the peer closed the connection before the handshake finished")]
    Closed,

    /// A frame could not be encoded or decoded.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// The first frame was not the one the handshake expected.
    #[error("expected a {expected} frame and received a {found} frame")]
    Unexpected {
        /// What the exchange was waiting for.
        expected: &'static str,
        /// What arrived.
        found: String,
    },

    /// The payload was not the message it should be.
    #[error("the {message} payload could not be read: {why}")]
    Payload {
        /// Which message.
        message: &'static str,
        /// What the parser said.
        why: String,
    },

    /// The peer speaks a protocol this build does not.
    #[error("the peer speaks protocol {theirs} and this build speaks {ours}")]
    VersionMismatch {
        /// What the peer sent.
        theirs: u16,
        /// What this build speaks.
        ours: u16,
    },

    /// The peer refused the link, and said why.
    #[error("the peer refused the connection: {reason}")]
    Refused {
        /// The peer's own reason, as a string for a log line.
        reason: String,
    },

    /// The peer's `HelloAck` echoed a different nonce.
    ///
    /// # Why this is fatal
    ///
    /// The nonce is what ties an answer to the attempt that asked for it. An answer carrying a different one is a
    /// recorded or mis-routed message, and continuing would build a session on a reply to somebody else's question.
    #[error("the peer answered with a different nonce, so this is not a reply to our attempt")]
    NonceMismatch,

    /// The peer's announcement did not validate.
    #[error("the peer's announcement was refused: {why}")]
    Invalid {
        /// What the validator said.
        why: String,
    },
}

/// The result of a completed handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The peer's identifier.
    pub device_id: DeviceId,
    /// What the peer calls itself.
    pub display_name: String,
    /// What the peer is.
    pub platform: PlatformKind,
    /// The peer's build.
    pub app_version: String,
    /// The features both ends announced.
    pub agreed: Agreed,
    /// How the peer read our token, from our side of the exchange.
    ///
    /// `None` when we were the acceptor, because it is the dialer that presented a token.
    pub pairing: Option<PairingState>,
}

impl Negotiated {
    /// Whether the link can carry work.
    ///
    /// A refusal with no missing required features is still unusable: the peer said no, and continuing would be doing
    /// work on a link the other end has already declined.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.agreed.is_usable()
    }
}

/// Flags a handshake runs under.
///
/// # Why a parameter rather than reading the environment
///
/// A test must be able to drive a timeout without waiting for one, and `TcpStream` has no way to make a loopback read
/// time out. Passing the flags makes the timeout a *value* a test chooses rather than a property of the operating
/// system — which is the only way the branch that reports one can be exercised at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// How long a read may wait before the handshake is abandoned.
    pub timeout: Option<Duration>,
}

impl Flags {
    /// The settings a real connection uses.
    #[must_use]
    pub const fn production() -> Self {
        Self { timeout: Some(limits::HELLO_TIMEOUT) }
    }

    /// No timeout, for a test that must not depend on the clock.
    #[must_use]
    pub const fn no_timeout() -> Self {
        Self { timeout: None }
    }
}

impl Default for Flags {
    fn default() -> Self {
        Self::production()
    }
}

/// Agrees on features from both announcements.
///
/// # Why this is a free function
///
/// Because it is the same computation on both sides of the exchange, and a dialer and an acceptor that disagreed would
/// be two devices that each believe a different set of features is available — with the failure landing at the first
/// transfer that used one of them.
#[must_use]
pub fn agree(ours: &LocalPeer, theirs_features: &[Feature], theirs_requires: &[Feature]) -> Agreed {
    // Common: what both announced.
    let common: Vec<Feature> = ours
        .features
        .iter()
        .copied()
        .filter(|feature| theirs_features.contains(feature))
        .collect();

    // Missing required: what either side needs and the other does not have. Both directions, because a link where the
    // peer requires something we lack is as unusable as the reverse — and a check that looked only at our own list
    // would let us start work the peer will refuse.
    let mut missing_required: Vec<Feature> = ours
        .requires
        .iter()
        .copied()
        .filter(|feature| !theirs_features.contains(feature))
        .collect();
    for required in theirs_requires {
        if !ours.features.contains(required) && !missing_required.contains(required) {
            missing_required.push(*required);
        }
    }

    Agreed { common, missing_required }
}

/// Reads one frame into a buffer, or reports why it could not.
///
/// # Why a chunked read rather than `read_exact`
///
/// A frame's length is in its header, so the body length is only known after the header arrives. A `read_exact` of the
/// whole frame would need the length first, and a decoder that peeked at four bytes would be one that has to handle a
/// partial header anyway. So the loop reads what is there and lets the decoder decide when it has a whole frame —
/// which is the same shape a socket always requires.
fn read_frame(
    stream: &mut TcpStream,
    decoder: &mut FrameDecoder,
    flags: Flags,
) -> Result<Frame, HandshakeError> {
    if let Some(timeout) = flags.timeout {
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
    }

    let mut buffer = [0u8; 8 * 1024];
    loop {
        if let Some(frame) = decoder.next_frame()? {
            return Ok(frame);
        }
        let read = match stream.read(&mut buffer) {
            Ok(0) => return Err(HandshakeError::Closed),
            Ok(read) => read,
            // ★ A peer that went away is one condition, and the platform decides how many ways it spells it. Classifying
            // only the clean end-of-file made this report a transport fault for an ordinary hang-up on Windows.
            Err(error) if peer_went_away(&error) => return Err(HandshakeError::Closed),
            Err(error) => return Err(transport(&error)),
        };
        let chunk = buffer.get(..read).ok_or_else(|| transport_message(
            "a read reported more bytes than the buffer",
        ))?;
        // ★ The result is propagated, and dropping it was the first version: a poisoned decoder then reported "no frame
        // yet" for ever, so a peer that sent a malformed frame produced a read loop that never ended rather than a
        // refused connection. `?` is what turns it into the refusal it is.
        decoder.push_slice(chunk)?;
    }
}

/// Writes one frame.
fn write_frame(stream: &mut TcpStream, frame: &Frame) -> Result<(), HandshakeError> {
    let bytes = FrameEncoder::encode_to_vec(frame)?;
    stream
        .write_all(&bytes)
        .and_then(|()| stream.flush())
        .map_err(|error| transport(&error))
}

/// A `Hello` frame carrying its JSON.
///
/// # Why the body is `Hello` and not `Envelope`
///
/// The protocol pairs each frame kind with its own body variant, and a mismatch is refused by the encoder with
/// `BodyKindMismatch` — which is what the first version of this did. The two are distinct on purpose: a frame's kind is
/// checked without parsing its body, so a peer that had to read the JSON to know it was a hello would be one that
/// allocated for every frame it intended to route.
fn hello_frame(hello: &Hello) -> Result<Frame, HandshakeError> {
    let bytes = encode_json(hello)?;
    Ok(Frame { kind: FrameKind::Hello, flags: 0, body: FrameBody::Hello(Bytes::from(bytes)) })
}

/// A `HelloAck` frame carrying its JSON.
fn hello_ack_frame(ack: &HelloAck) -> Result<Frame, HandshakeError> {
    let bytes = encode_json(ack)?;
    Ok(Frame {
        kind: FrameKind::HelloAck,
        flags: 0,
        body: FrameBody::HelloAck(Bytes::from(bytes)),
    })
}

/// Serialises a handshake message.
fn encode_json(value: &impl serde::Serialize) -> Result<Vec<u8>, HandshakeError> {
    serde_json::to_vec(value).map_err(|error| HandshakeError::Payload {
        message: "handshake",
        why: error.to_string(),
    })
}

/// The JSON in a handshake frame, whichever of the two bodies it is.
///
/// # Why this accepts both variants
///
/// The dialer reads a `HelloAck` and the acceptor reads a `Hello`, and each is a different body variant. One reader for
/// both keeps the exchange in one place; a reader per direction would be two places the JSON is parsed, and the second
/// is where a field added to one message and not the other goes unnoticed.
fn json_payload<T: for<'de> serde::Deserialize<'de>>(
    frame: &Frame,
    message: &'static str,
) -> Result<T, HandshakeError> {
    let bytes = match &frame.body {
        FrameBody::Hello(bytes) | FrameBody::HelloAck(bytes) => bytes,
        other => {
            return Err(HandshakeError::Unexpected {
                expected: message,
                found: format!("{other:?}"),
            });
        }
    };
    serde_json::from_slice(bytes).map_err(|error| HandshakeError::Payload {
        message,
        why: error.to_string(),
    })
}

/// Checks the frame is the kind the exchange expects.
fn expect(frame: &Frame, kind: FrameKind, expected: &'static str) -> Result<(), HandshakeError> {
    if frame.kind == kind {
        return Ok(());
    }
    Err(HandshakeError::Unexpected { expected, found: frame.kind.to_string() })
}

/// Dials a peer and completes the handshake.
///
/// # Errors
///
/// [`HandshakeError`] for a stream failure, a malformed exchange, a version this build does not speak, a refusal, or a
/// nonce that does not match the attempt.
pub fn dial(
    address: SocketAddr,
    ours: &LocalPeer,
    token: Option<LinkToken>,
    sequence: u64,
    flags: Flags,
) -> Result<(TcpStream, Negotiated), HandshakeError> {
    let mut stream = TcpStream::connect(address).map_err(|error| transport(&error))?;
    if let Some(timeout) = flags.timeout {
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
    }

    // ★ A fresh nonce per attempt. It is what ties the answer to this question: an answer carrying a different one is a
    // recorded or mis-routed message, and a dialer that accepted it would build a session on a reply to somebody else's
    // attempt.
    let nonce = SessionNonce::random();
    let mut hello = ours.hello(nonce, sequence);
    hello.token = token;

    write_frame(&mut stream, &hello_frame(&hello)?)?;

    let mut decoder = FrameDecoder::new();
    let frame = read_frame(&mut stream, &mut decoder, flags)?;
    expect(&frame, FrameKind::HelloAck, "HelloAck")?;
    let ack: HelloAck = json_payload(&frame, "HelloAck")?;

    if let Some(refusal) = ack.refusal {
        return Err(HandshakeError::Refused { reason: format!("{refusal:?}") });
    }
    if ack.protocol != PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            theirs: ack.protocol,
            ours: PROTOCOL_VERSION,
        });
    }
    if ack.nonce != nonce {
        return Err(HandshakeError::NonceMismatch);
    }

    Ok((
        stream,
        Negotiated {
            device_id: ack.device_id,
            display_name: ack.display_name,
            platform: ack.platform,
            app_version: ack.app_version,
            agreed: agree(ours, &ack.features, &ack.requires),
            pairing: Some(ack.pairing),
        },
    ))
}

/// Accepts one connection and completes the handshake.
///
/// # Why the pairing decision is a callback
///
/// Because it needs the pairing store, which this layer does not have — and the answer is what the dialer learns about
/// whether its token is still good. A closure keeps that decision where the store is while the exchange stays here,
/// where it can be tested.
///
/// # Errors
///
/// As [`dial`], plus [`HandshakeError::Invalid`] when the peer's announcement does not validate.
pub fn accept(
    listener: &TcpListener,
    ours: &LocalPeer,
    sequence: u64,
    flags: Flags,
    read_token: impl FnOnce(Option<&LinkToken>, DeviceId) -> PairingState,
) -> Result<(TcpStream, Negotiated), HandshakeError> {
    let (stream, _) = listener.accept().map_err(|error| transport(&error))?;
    accept_stream(stream, ours, sequence, flags, read_token)
}

/// Completes a handshake on a connection that was already taken.
///
/// # Why this is separate from [`accept`]
///
/// Because taking a connection is a queue pop and a handshake is a read with a timeout on it. A caller that has to hold
/// something across the second — a lock, a loop — cannot express the difference if the two are one function.
///
/// # Errors
///
/// As [`accept`].
pub fn accept_stream(
    mut stream: TcpStream,
    ours: &LocalPeer,
    sequence: u64,
    flags: Flags,
    read_token: impl FnOnce(Option<&LinkToken>, DeviceId) -> PairingState,
) -> Result<(TcpStream, Negotiated), HandshakeError> {
    if let Some(timeout) = flags.timeout {
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
    }

    let mut decoder = FrameDecoder::new();
    let frame = read_frame(&mut stream, &mut decoder, flags)?;
    expect(&frame, FrameKind::Hello, "Hello")?;
    let hello: Hello = json_payload(&frame, "Hello")?;

    // ★ The announcement is validated before anything is built from it. It is attacker-controlled input: an unbounded
    // endpoint list would be an unbounded amount of dialling on this device's behalf, and a display name is rendered.
    hello.validate().map_err(|error| HandshakeError::Invalid { why: error.to_string() })?;

    let pairing = read_token(hello.token.as_ref(), hello.device_id);
    let ack = ours.hello_ack(hello.nonce, pairing, sequence);
    write_frame(&mut stream, &hello_ack_frame(&ack)?)?;

    Ok((
        stream,
        Negotiated {
            device_id: hello.device_id,
            display_name: hello.display_name,
            platform: hello.platform,
            app_version: hello.app_version,
            agreed: agree(ours, &hello.features, &hello.requires),
            // The dialer presented the token, so this side has no read of it to report.
            pairing: None,
        },
    ))
}

/// Whether an error means the peer went away rather than that something is wrong.
///
/// # Why the error *kind* is not enough
///
/// Windows reports an abortive close as `WSAECONNABORTED` (10053) and a reset as `WSAECONNRESET` (10054), and the two do
/// not map to the same [`std::io::ErrorKind`] — which is what the first version of this matched on, so one of them came
/// through as a transport fault. A hang-up is one condition; how many codes a platform spells it with is the platform's
/// business, so the codes are named here and the kinds are checked as well for the platforms where they carry it.
pub(crate) fn peer_went_away(error: &std::io::Error) -> bool {
    // 10053 and 10054 are Winsock's, and the codes are stable. Named rather than imported, because naming them makes the
    // reason visible — and a reader who does not know them can look them up.
    const WSAECONNABORTED: i32 = 10053;
    const WSAECONNRESET: i32 = 10054;

    if error
        .raw_os_error()
        .is_some_and(|code| code == WSAECONNABORTED || code == WSAECONNRESET)
    {
        return true;
    }
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// An operating-system error, as a transport failure.
fn transport(error: &std::io::Error) -> HandshakeError {
    transport_message(&error.to_string())
}

/// A message, as a transport failure.
fn transport_message(why: &str) -> HandshakeError {
    HandshakeError::Transport { why: why.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    /// Two identifiers, so a test can name both ends.
    const DIALER: &str = "11111111-1111-4111-8111-111111111111";
    const ACCEPTOR: &str = "22222222-2222-4222-8222-222222222222";

    fn peer(id: &str, name: &str, platform: PlatformKind) -> LocalPeer {
        LocalPeer::new(device(id), name, platform, "0.1.0-test")
    }

    /// A listener on a free loopback port.
    fn listener() -> TcpListener {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds a loopback port")
    }

    // ── The two ends together ─────────────────────────────────────────────────────────────────────

    #[test]
    fn a_dialer_and_an_acceptor_complete_a_handshake() {
        // ★ The end-to-end test, on a real loopback socket. The types here are the ones that cross the wire, so a test
        // that stubbed the transport would be a test of the stub — and the bug this layer can have is a mismatch between
        // what one side writes and what the other reads.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
        });

        let (stream, negotiated) =
            dial(address, &theirs, None, 1, Flags::no_timeout()).expect("completes");
        drop(stream);
        let (_, accepted) = serving.join().expect("the thread finished").expect("accepts");

        // Each side learned the other.
        assert_eq!(negotiated.device_id, device(ACCEPTOR));
        assert_eq!(negotiated.display_name, "Laptop");
        assert_eq!(negotiated.platform, PlatformKind::Desktop);
        assert_eq!(accepted.device_id, device(DIALER));
        assert_eq!(accepted.display_name, "Phone");
        assert_eq!(accepted.platform, PlatformKind::Android);
    }

    #[test]
    fn both_ends_agree_on_the_same_features() {
        // ★ The computation is the same on both sides, and a dialer and an acceptor that disagreed would each believe a
        // different set is available — with the failure landing at the first transfer that used one of them.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
        });
        let (stream, mine) = dial(address, &theirs, None, 1, Flags::no_timeout()).expect("completes");
        drop(stream);
        let (_, theirs_side) = serving.join().expect("finished").expect("accepts");

        assert_eq!(mine.agreed, theirs_side.agreed);
        assert!(mine.is_usable());
        assert!(!mine.agreed.common.is_empty(), "no features in common");
    }

    #[test]
    fn the_dialers_token_is_offered_to_the_acceptor() {
        // ★ The pairing decision is the acceptor's, and it is made from the token the dialer presented. A layer that
        // dropped the token would make every reconnection look like a first connection, and every pairing would be
        // re-prompted.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);
        let token = LinkToken::from_bytes([7u8; LinkToken::LEN]);
        let offered = token.clone();

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), move |seen, _| {
                // The assertion is inside the acceptor, because the token only exists there.
                assert_eq!(seen, Some(&offered), "the token did not arrive");
                PairingState::Current
            })
        });
        let (stream, negotiated) =
            dial(address, &theirs, Some(token), 1, Flags::no_timeout()).expect("completes");
        drop(stream);
        serving.join().expect("finished").expect("accepts");

        // And the dialer learns how its token was read, which is what tells it whether the pairing survived.
        assert_eq!(negotiated.pairing, Some(PairingState::Current));
    }

    #[test]
    fn an_acceptor_reports_no_pairing_state_because_it_decided_it() {
        // The `pairing` field is the dialer's to read: the acceptor made the decision, so it has nothing to learn.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
        });
        let (stream, _) = dial(address, &theirs, None, 1, Flags::no_timeout()).expect("completes");
        drop(stream);
        let (_, accepted) = serving.join().expect("finished").expect("accepts");
        assert_eq!(accepted.pairing, None);
    }

    #[test]
    fn a_peer_that_hangs_up_before_saying_hello_is_reported_as_closed() {
        // ★ The ordinary shape of a port scan and of a user who closed a laptop. A caller that could not tell it from a
        // decode error would log a fault for every scan.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
        });

        // A connection that sends nothing and closes.
        let probe = TcpStream::connect(address).expect("connects");
        drop(probe);

        match serving.join().expect("finished") {
            Err(HandshakeError::Closed) => {}
            other => panic!("expected a closed connection, got {other:?}"),
        }
    }

    #[test]
    fn a_dialer_that_reaches_a_socket_that_says_nothing_reports_closed_rather_than_waiting() {
        // The other direction: a listener that accepts and does nothing. With a timeout the dialer gives up; the
        // assertion here uses the closed path, because `TcpStream` on a loopback cannot be made to time out reliably.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            // Say nothing, then close.
            drop(stream);
        });

        match dial(address, &theirs, None, 1, Flags::no_timeout()) {
            Err(HandshakeError::Closed) => {}
            other => panic!("expected a closed connection, got {other:?}"),
        }
        serving.join().expect("finished");
    }

    #[test]
    fn a_hello_that_is_not_a_hello_is_refused() {
        // A peer that opens with the wrong frame is one this exchange cannot continue with, and the message names what
        // was expected.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
        });

        let mut stream = TcpStream::connect(address).expect("connects");
        write_frame(&mut stream, &Frame::empty(FrameKind::Ping)).expect("writes");

        match serving.join().expect("finished") {
            Err(HandshakeError::Unexpected { expected, .. }) => assert_eq!(expected, "Hello"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_hello_carrying_an_unreasonable_endpoint_list_is_refused() {
        // ★ The announcement is attacker-controlled input, and an unbounded endpoint list would be an unbounded amount
        // of dialling on this device's behalf. The validation is what bounds it.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

        let serving = std::thread::spawn(move || {
            accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
        });

        let mut stream = TcpStream::connect(address).expect("connects");
        let mut hello = peer(DIALER, "Phone", PlatformKind::Android).hello(SessionNonce::random(), 1);
        hello.endpoints = (0..Hello::MAX_ENDPOINTS + 4).map(|i| format!("10.0.0.{i}:47100")).collect();
        write_frame(&mut stream, &hello_frame(&hello).expect("encodes"))
            .expect("writes");

        match serving.join().expect("finished") {
            Err(HandshakeError::Invalid { why }) => assert!(!why.is_empty()),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_from_the_acceptor_reaches_the_dialer() {
        // A refusal is a complete answer, and the dialer reports it rather than building a session on a declined link.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut decoder = FrameDecoder::new();
            let _ = read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello");
            // A refusal, which the protocol says is a complete answer in itself.
            let ack = HelloAck::refuse(
                device(ACCEPTOR),
                "Laptop",
                PlatformKind::Desktop,
                "0.1.0-test",
                SessionNonce::random(),
                synra_protocol::handshake::RefusalReason::Malformed,
            );
            write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
                .expect("writes");
        });

        match dial(address, &theirs, None, 1, Flags::no_timeout()) {
            Err(HandshakeError::Refused { reason }) => assert!(!reason.is_empty()),
            other => panic!("expected a refusal, got {other:?}"),
        }
        serving.join().expect("finished");
    }

    #[test]
    fn an_ack_echoing_a_different_nonce_is_refused() {
        // ★ The nonce ties an answer to the attempt that asked for it. An answer carrying a different one is a recorded
        // or mis-routed message, and continuing would build a session on a reply to somebody else's question.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut decoder = FrameDecoder::new();
            let _ = read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello");
            // A fresh nonce rather than the one that arrived.
            let ack = ours.hello_ack(SessionNonce::random(), PairingState::Unknown, 1);
            write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
                .expect("writes");
        });

        match dial(address, &theirs, None, 1, Flags::no_timeout()) {
            Err(HandshakeError::NonceMismatch) => {}
            other => panic!("expected a nonce mismatch, got {other:?}"),
        }
        serving.join().expect("finished");
    }

    #[test]
    fn an_ack_naming_a_different_protocol_is_refused() {
        // A peer speaking another version is refused here rather than failing on the third message with a decode error
        // about a field neither end can name.
        let listener = listener();
        let address = listener.local_addr().expect("an address");
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let theirs = peer(DIALER, "Phone", PlatformKind::Android);

        let serving = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut decoder = FrameDecoder::new();
            let hello: Hello =
                json_payload(&read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello"), "Hello")
                    .expect("reads");
            let mut ack = ours.hello_ack(hello.nonce, PairingState::Unknown, 1);
            ack.protocol = PROTOCOL_VERSION + 1;
            write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
                .expect("writes");
        });

        match dial(address, &theirs, None, 1, Flags::no_timeout()) {
            Err(HandshakeError::VersionMismatch { theirs, ours }) => {
                assert_eq!(theirs, PROTOCOL_VERSION + 1);
                assert_eq!(ours, PROTOCOL_VERSION);
            }
            other => panic!("expected a version mismatch, got {other:?}"),
        }
        serving.join().expect("finished");
    }

    // ── Feature agreement ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn features_in_common_are_the_intersection() {
        let ours = LocalPeer {
            features: vec![Feature::EventStream, Feature::ClipboardSync],
            requires: Vec::new(),
            ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
        };
        let agreed = agree(&ours, &[Feature::EventStream], &[]);
        assert_eq!(agreed.common, vec![Feature::EventStream]);
        assert!(agreed.is_usable());
    }

    #[test]
    fn a_required_feature_the_peer_lacks_is_reported() {
        // Our own requirement.
        let ours = LocalPeer {
            requires: vec![Feature::TransferResume],
            ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
        };
        let agreed = agree(&ours, &[], &[]);
        assert_eq!(agreed.missing_required, vec![Feature::TransferResume]);
        assert!(!agreed.is_usable());
    }

    #[test]
    fn a_required_feature_the_peer_needs_and_we_lack_is_reported_too() {
        // ★ Both directions. A link where the peer requires something we lack is as unusable as the reverse — and a
        // check that looked only at our own list would let us start work the peer will refuse.
        let ours = LocalPeer {
            features: vec![Feature::EventStream],
            requires: Vec::new(),
            ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
        };
        let agreed = agree(&ours, &[Feature::EventStream], &[Feature::PluginMirroring]);
        assert_eq!(agreed.missing_required, vec![Feature::PluginMirroring]);
        assert!(!agreed.is_usable());
    }

    #[test]
    fn a_requirement_both_sides_meet_is_not_missing() {
        let ours = LocalPeer {
            features: vec![Feature::EventStream],
            requires: vec![Feature::EventStream],
            ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
        };
        let agreed = agree(&ours, &[Feature::EventStream], &[Feature::EventStream]);
        assert!(agreed.missing_required.is_empty());
        assert!(agreed.is_usable());
    }

    #[test]
    fn a_requirement_is_reported_once_even_when_both_sides_name_it() {
        // Two entries for one feature would make a report say a link is missing two things when it is missing one.
        let ours = LocalPeer {
            features: vec![Feature::EventStream],
            requires: vec![Feature::PluginMirroring],
            ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
        };
        let agreed = agree(&ours, &[Feature::EventStream], &[Feature::PluginMirroring]);
        assert_eq!(agreed.missing_required, vec![Feature::PluginMirroring]);
    }

    #[test]
    fn an_announcement_carries_the_port_it_was_given() {
        // ★ The port is the **connection** port, and this type does not hold it. A `LocalPeer` that guessed would
        // announce a port nothing is listening on — a device that appears in every list and cannot be connected to.
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let announcement = ours.announcement(47_100);
        assert_eq!(announcement.port, 47_100);
        assert_eq!(announcement.device_id, device(ACCEPTOR));
        assert_eq!(announcement.display_name, "Laptop");
        assert_eq!(announcement.platform, Some(PlatformKind::Desktop));
        assert_eq!(announcement.protocol, PROTOCOL_VERSION);
    }

    #[test]
    fn an_announcement_passes_the_protocols_own_validation() {
        // The announcement is encoded and broadcast, and the receiving end validates it. One this build produces that
        // its own parser refuses would be a device that can never be found.
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        assert!(ours.announcement(47_100).validate().is_ok());
    }

    #[test]
    fn the_default_features_are_the_protocols_own_catalogue() {
        // ★ A build that forgot to announce a feature it implements would be one whose peers decline to use it, and
        // nothing would say why. Asserted against the catalogue so the two cannot drift.
        assert_eq!(LocalPeer::default_features(), Feature::ALL.to_vec());
        assert!(!LocalPeer::default_features().is_empty());
    }

    #[test]
    fn a_local_peer_builds_a_hello_and_an_ack_that_agree_with_each_other() {
        // The two messages carry the same facts, so a field set in one and not the other is a peer that looks different
        // depending on which end dialled.
        let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
        let nonce = SessionNonce::random();
        let hello = ours.hello(nonce, 3);
        let ack = ours.hello_ack(nonce, PairingState::Unknown, 3);

        assert_eq!(hello.device_id, ack.device_id);
        assert_eq!(hello.display_name, ack.display_name);
        assert_eq!(hello.platform, ack.platform);
        assert_eq!(hello.app_version, ack.app_version);
        assert_eq!(hello.protocol, ack.protocol);
        assert_eq!(hello.nonce, ack.nonce);
        assert_eq!(hello.sequence, ack.sequence);
        assert_eq!(hello.features, ack.features);
    }

    // ── Flags ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_production_flags_use_the_protocols_hello_timeout() {
        // The timeout is the protocol's constant rather than a figure chosen here, so a link is abandoned at the moment
        // every other part of the kernel believes it should be.
        assert_eq!(Flags::production().timeout, Some(limits::HELLO_TIMEOUT));
        assert_eq!(Flags::no_timeout().timeout, None);
        assert_eq!(Flags::default(), Flags::production());
    }

    // ── Errors ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            HandshakeError::Transport { why: "reset".to_owned() },
            HandshakeError::Closed,
            HandshakeError::Frame(FrameError::Poisoned),
            HandshakeError::Unexpected {
                expected: "Hello",
                found: "Ping".to_owned(),
            },
            HandshakeError::Payload { message: "Hello", why: "missing field".to_owned() },
            HandshakeError::VersionMismatch { theirs: 9, ours: 1 },
            HandshakeError::Refused { reason: "busy".to_owned() },
            HandshakeError::NonceMismatch,
            HandshakeError::Invalid { why: "too many endpoints".to_owned() },
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
        // And the version mismatch names both, because "incompatible" alone leaves a user with nothing.
        let text = errors[5].to_string();
        assert!(text.contains('9') && text.contains('1'), "{text}");
    }

    #[test]
    fn a_negotiated_link_knows_whether_it_is_usable() {
        let usable = Negotiated {
            device_id: device(DIALER),
            display_name: "P".to_owned(),
            platform: PlatformKind::Android,
            app_version: "0.1.0".to_owned(),
            agreed: Agreed { common: vec![Feature::EventStream], missing_required: Vec::new() },
            pairing: None,
        };
        assert!(usable.is_usable());

        let unusable = Negotiated {
            agreed: Agreed { common: Vec::new(), missing_required: vec![Feature::TransferResume] },
            ..usable
        };
        assert!(!unusable.is_usable());
    }
}
