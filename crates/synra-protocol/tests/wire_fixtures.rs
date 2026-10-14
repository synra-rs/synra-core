//! The wire format, locked byte for byte.
//!
//! # What this is for
//!
//! The protocol is a fresh design with two implementations planned, so the risk is not "does it match someone else's
//! format" — it is that a change to the encoder quietly moves the bytes. A test that only round-trips cannot see that:
//! an encoder and decoder changed together still agree with each other, and every peer in the field stops understanding
//! both.
//!
//! So every fixture here is written as **the bytes, split into named parts**, and asserted three ways:
//!
//! 1. the parts add up to the documented layout (`u32 BE length`, kind, flags, body);
//! 2. the encoder produces exactly those bytes;
//! 3. the decoder turns exactly those bytes back into the same frame.
//!
//! The bytes are written by hand from the format rather than recorded from the encoder, because a recording proves only
//! that the code equals itself.
//!
//! # The layout
//!
//! ```text
//! ┌──────────────┬─────────┬─────────┬──────────────────────────┐
//! │ u32 BE length│ u8 kind │ u8 flags│ body (length - 2) bytes  │
//! └──────────────┴─────────┴─────────┴──────────────────────────┘
//! ```
//!
//! `length` counts the kind and flags bytes as well as the body, so a heartbeat declares `2` and the total on the wire
//! is `6 + body`. The length is big-endian and the header is fixed at six bytes; nothing is variable-length, so a
//! receiver always knows how far to read.
//!
//! # Changing a fixture
//!
//! A failure here means the bytes moved. Fixing it requires saying **why** the format changed, updating the protocol
//! document, and deciding whether the version number must move — the same rule as any other published interface. Editing
//! the expected bytes until the test passes is the one thing that must not happen, because the test exists precisely to
//! make that visible.

// This is an integration test, so it is its own crate and does not inherit the relaxation the library sets for its
// `#[cfg(test)]` modules. The same reasoning applies here: a test that indexes a fixture array or unwraps an encode
// result is reporting a broken expectation, which is what a test is for.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_const_for_fn,
)]

use bytes::Bytes;

use synra_protocol::frame::{ChunkFrame, Frame, FrameBody, FrameDecoder, FrameEncoder, FrameKind};

/// A fixture: what it is called, the frame, and the bytes it must be on the wire.
struct Fixture {
    name: &'static str,
    frame: Frame,
    bytes: &'static [u8],
}

/// A frame with the reserved flags byte clear, which is every frame this version sends.
fn frame(kind: FrameKind, body: FrameBody) -> Frame {
    Frame { kind, flags: 0, body }
}

/// A frame with no body, such as a heartbeat.
fn heartbeat(kind: FrameKind) -> Frame {
    Frame::empty(kind)
}

/// Every fixture, in the order the wire document lists them.
fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "ping",
            frame: heartbeat(FrameKind::Ping),
            // length 2 (kind + flags), kind 0x03, flags 0x00.
            bytes: &[0x00, 0x00, 0x00, 0x02, 0x03, 0x00],
        },
        Fixture {
            name: "pong",
            frame: heartbeat(FrameKind::Pong),
            bytes: &[0x00, 0x00, 0x00, 0x02, 0x04, 0x00],
        },
        Fixture {
            name: "bye without a reason",
            frame: frame(FrameKind::Bye, FrameBody::Bye { code: 0, reason: Bytes::new() }),
            // length 3: kind + flags + the one reason-code byte.
            bytes: &[0x00, 0x00, 0x00, 0x03, 0x07, 0x00, 0x00],
        },
        Fixture {
            name: "bye with a reason",
            frame: frame(
                FrameKind::Bye,
                FrameBody::Bye { code: 3, reason: Bytes::from_static(b"bye") },
            ),
            // length 6: kind + flags + code + three bytes of text.
            bytes: &[0x00, 0x00, 0x00, 0x06, 0x07, 0x00, 0x03, 0x62, 0x79, 0x65],
        },
        Fixture {
            name: "hello with an empty json body",
            frame: frame(FrameKind::Hello, FrameBody::Hello(Bytes::from_static(b"{}"))),
            // length 4: kind + flags + `{}`.
            bytes: &[0x00, 0x00, 0x00, 0x04, 0x05, 0x00, 0x7b, 0x7d],
        },
        Fixture {
            name: "hello ack with an empty json body",
            frame: frame(FrameKind::HelloAck, FrameBody::HelloAck(Bytes::from_static(b"{}"))),
            bytes: &[0x00, 0x00, 0x00, 0x04, 0x06, 0x00, 0x7b, 0x7d],
        },
        Fixture {
            name: "envelope with an empty json body",
            frame: frame(FrameKind::Envelope, FrameBody::Envelope(Bytes::from_static(b"{}"))),
            bytes: &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x7b, 0x7d],
        },
        Fixture {
            name: "chunk with one byte",
            frame: frame(
                FrameKind::Chunk,
                FrameBody::Chunk(ChunkFrame { chunk_id: 1, data: Bytes::from_static(&[0xab]) }),
            ),
            // length 7: kind + flags + the u32 chunk id + the one data byte.
            bytes: &[0x00, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0xab],
        },
        Fixture {
            name: "chunk with no data",
            frame: frame(
                FrameKind::Chunk,
                FrameBody::Chunk(ChunkFrame { chunk_id: 0, data: Bytes::new() }),
            ),
            // length 6: kind + flags + the u32 chunk id, and no data at all.
            bytes: &[0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
        },
    ]
}

/// The header every fixture shares: a length, a kind byte, and a flags byte.
fn declared_length(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[test]
fn every_fixture_matches_the_documented_layout() {
    for fixture in fixtures() {
        let bytes = fixture.bytes;

        assert_eq!(
            declared_length(bytes) as usize,
            bytes.len() - 4,
            "{}: the declared length must count the flags, the kind and the body",
            fixture.name
        );
        assert_eq!(
            bytes[4],
            fixture.frame.kind.as_u8(),
            "{}: the kind byte is at offset 4",
            fixture.name
        );
        assert_eq!(
            bytes[5],
            fixture.frame.flags,
            "{}: the flags byte is at offset 5",
            fixture.name
        );
        assert_eq!(
            bytes.len(),
            synra_protocol::limits::FRAME_HEADER_LEN + fixture.frame.body.len(),
            "{}: the total length is the six-byte header plus the body",
            fixture.name
        );
    }
}

#[test]
fn the_encoder_produces_exactly_these_bytes() {
    for fixture in fixtures() {
        let encoded = FrameEncoder::encode_to_vec(&fixture.frame)
            .unwrap_or_else(|error| panic!("{}: does not encode: {error}", fixture.name));
        assert_eq!(
            encoded.as_ref(),
            fixture.bytes,
            "{}: the encoder moved the bytes; see this file's header before changing the expectation",
            fixture.name
        );
    }
}

#[test]
fn the_decoder_accepts_exactly_these_bytes() {
    for fixture in fixtures() {
        let mut decoder = FrameDecoder::new();
        decoder
            .push_slice(fixture.bytes)
            .unwrap_or_else(|error| panic!("{}: rejected as input: {error}", fixture.name));
        let decoded = decoder
            .next_frame()
            .unwrap_or_else(|error| panic!("{}: does not decode: {error}", fixture.name))
            .unwrap_or_else(|| panic!("{}: decoded to nothing and did not error", fixture.name));

        assert_eq!(decoded, fixture.frame, "{}: decoded to a different frame", fixture.name);
        assert_eq!(decoder.buffered(), 0, "{}: left bytes behind", fixture.name);
    }
}

/// A frame split across reads must decode the same as one that arrived whole.
///
/// This is the case a round trip within a single process never exercises: TCP hands over whatever it has, so every
/// length boundary in this file is a boundary a real peer can land on.
#[test]
fn every_fixture_decodes_when_split_at_every_boundary() {
    for fixture in fixtures() {
        let bytes = fixture.bytes;
        for split in 1..bytes.len() {
            let mut decoder = FrameDecoder::new();
            // Nothing must come out of the first part, whatever the boundary happens to be.
            decoder
                .push_slice(&bytes[..split])
                .unwrap_or_else(|error| panic!("{}: split at {split} rejected: {error}", fixture.name));
            let early = decoder
                .next_frame()
                .unwrap_or_else(|error| panic!("{}: split at {split} errored: {error}", fixture.name));
            assert!(
                early.is_none(),
                "{}: split at {split} produced a frame before the last byte",
                fixture.name
            );

            decoder
                .push_slice(&bytes[split..])
                .unwrap_or_else(|error| panic!("{}: rest after {split} rejected: {error}", fixture.name));
            let decoded = decoder
                .next_frame()
                .unwrap_or_else(|error| panic!("{}: rest after {split} errored: {error}", fixture.name))
                .unwrap_or_else(|| panic!("{}: nothing decoded after splitting at {split}", fixture.name));
            assert_eq!(decoded, fixture.frame, "{}: split at {split}", fixture.name);
        }
    }
}

/// Two frames in one read must both come out, in order.
#[test]
fn frames_that_arrive_together_are_returned_in_order() {
    let all = fixtures();
    let mut stream = Vec::new();
    for fixture in &all {
        stream.extend_from_slice(fixture.bytes);
    }

    let mut decoder = FrameDecoder::new();
    decoder.push_slice(&stream).expect("the concatenation is valid input");
    for fixture in &all {
        let decoded = decoder
            .next_frame()
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name))
            .unwrap_or_else(|| panic!("{}: ran out of frames", fixture.name));
        assert_eq!(decoded, fixture.frame, "{}: out of order or altered", fixture.name);
    }
    assert!(
        decoder.next_frame().expect("no error after the last frame").is_none(),
        "the decoder produced a frame nobody wrote"
    );
}
