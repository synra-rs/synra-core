//! The two directions of the exchange: a dialer that opens a connection, and an acceptor that answers one.

use std::net::{SocketAddr, TcpListener, TcpStream};

use synra_protocol::frame::{FrameDecoder, FrameKind};
use synra_protocol::handshake::{
    Hello, HelloAck, LinkToken, PROTOCOL_VERSION, PairingState, SessionNonce,
};
use synra_protocol::ids::DeviceId;

use super::config::Flags;
use super::errors::HandshakeError;
use super::host::LocalPeer;
use super::negotiate::{Negotiated, agree};
use super::wire::{expect, hello_ack_frame, hello_frame, json_payload, read_frame, transport, write_frame};

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
