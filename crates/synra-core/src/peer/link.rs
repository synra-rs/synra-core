//! The two directions of the exchange: a dialer that opens a connection, and an acceptor that answers one.

use std::net::{SocketAddr, TcpListener, TcpStream};

use crate::link::LinkStream;
use synra_protocol::frame::{FrameDecoder, FrameKind};
use synra_protocol::handshake::{
    Hello, HelloAck, PROTOCOL_VERSION, SessionNonce,
};

use super::config::Flags;
use super::errors::HandshakeError;
use super::host::LocalPeer;
use super::negotiate::{Negotiated, agree};
use super::wire::{
    expect, hello_ack_frame, hello_frame, json_payload, read_frame, transport, write_frame,
};

/// Dials a peer and completes the handshake.
///
/// # Errors
///
/// [`HandshakeError`] for a stream failure, a malformed exchange, a version this build does not speak, a refusal, or a
/// nonce that does not match the attempt.
pub fn dial(
    address: SocketAddr,
    ours: &LocalPeer,
    sequence: u64,
    flags: Flags,
) -> Result<(TcpStream, Negotiated), HandshakeError> {
    let mut stream = TcpStream::connect(address).map_err(|error| transport(&error))?;
    if let Some(timeout) = flags.timeout {
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
    }

    let (negotiated, _decoder) = dial_stream(&mut stream, ours, sequence, flags)?;
    Ok((stream, negotiated))
}

pub(super) fn dial_stream(
    stream: &mut impl LinkStream,
    ours: &LocalPeer,
    sequence: u64,
    flags: Flags,
) -> Result<(Negotiated, FrameDecoder), HandshakeError> {
    // ★ A fresh nonce per attempt. It is what ties the answer to this question: an answer carrying a different one is a
    // recorded or mis-routed message, and a dialer that accepted it would build a session on a reply to somebody else's
    // attempt.
    let nonce = SessionNonce::random();
    let hello = ours.hello(nonce, sequence);

    write_frame(stream, &hello_frame(&hello)?)?;
    if synra_observe::wire::is_installed() {
        synra_observe::wire::emit(synra_observe::wire::WireEvent::sent(
            "pending".to_owned(),
            "hello",
            0,
        ));
    }

    let mut decoder = FrameDecoder::new();
    let frame = read_frame(stream, &mut decoder, flags)?;
    expect(&frame, FrameKind::HelloAck, "HelloAck")?;
    let ack: HelloAck = json_payload(&frame, "HelloAck")?;
    if synra_observe::wire::is_installed() {
        synra_observe::wire::emit(synra_observe::wire::WireEvent::received(
            ack.device_id.to_string(),
            "hello ack",
            0,
        ));
    }

    if let Some(refusal) = ack.refusal {
        return Err(HandshakeError::Refused {
            reason: format!("{refusal:?}"),
        });
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
    ack.validate(nonce)
        .map_err(|error| HandshakeError::Invalid {
            why: error.to_string(),
        })?;
    if ack.endpoints.len() > Hello::MAX_ENDPOINTS {
        return Err(HandshakeError::Invalid {
            why: "too many endpoints advertised".to_owned(),
        });
    }
    synra_protocol::session::PeerProfile {
        device_id: ack.device_id,
        display_name: ack.display_name.clone(),
        platform: ack.platform,
        app_version: ack.app_version.clone(),
    }
    .validate()
    .map_err(|why| HandshakeError::Invalid {
        why: why.to_owned(),
    })?;
    stream
        .authorize(ours.device_id, ack.device_id)
        .map_err(|error| super::wire::link_error(&error))?;

    Ok((
        Negotiated {
            device_id: ack.device_id,
            display_name: ack.display_name,
            platform: ack.platform,
            app_version: ack.app_version,
            agreed: agree(ours, &ack.features, &ack.requires),
        },
        decoder,
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
) -> Result<(TcpStream, Negotiated), HandshakeError> {
    let (stream, _) = listener.accept().map_err(|error| transport(&error))?;
    accept_stream(stream, ours, sequence, flags)
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
) -> Result<(TcpStream, Negotiated), HandshakeError> {
    if let Some(timeout) = flags.timeout {
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
    }

    let (negotiated, _decoder) = accept_on(&mut stream, ours, sequence, flags)?;
    Ok((stream, negotiated))
}

pub(super) fn accept_on(
    stream: &mut impl LinkStream,
    ours: &LocalPeer,
    sequence: u64,
    flags: Flags,
) -> Result<(Negotiated, FrameDecoder), HandshakeError> {
    let mut decoder = FrameDecoder::new();
    let frame = read_frame(stream, &mut decoder, flags)?;
    expect(&frame, FrameKind::Hello, "Hello")?;
    let hello: Hello = json_payload(&frame, "Hello")?;
    if synra_observe::wire::is_installed() {
        synra_observe::wire::emit(synra_observe::wire::WireEvent::received(
            hello.device_id.to_string(),
            "hello",
            0,
        ));
    }

    // ★ The announcement is validated before anything is built from it. It is attacker-controlled input: an unbounded
    // endpoint list would be an unbounded amount of dialling on this device's behalf, and a display name is rendered.
    hello.validate().map_err(|error| HandshakeError::Invalid {
        why: error.to_string(),
    })?;
    stream
        .authorize(ours.device_id, hello.device_id)
        .map_err(|error| super::wire::link_error(&error))?;
    let ack = ours.hello_ack(hello.nonce, sequence);
    write_frame(stream, &hello_ack_frame(&ack)?)?;
    if synra_observe::wire::is_installed() {
        synra_observe::wire::emit(synra_observe::wire::WireEvent::sent(
            hello.device_id.to_string(),
            "hello ack",
            0,
        ));
    }

    Ok((
        Negotiated {
            device_id: hello.device_id,
            display_name: hello.display_name,
            platform: hello.platform,
            app_version: hello.app_version,
            agreed: agree(ours, &hello.features, &hello.requires),
        },
        decoder,
    ))
}
