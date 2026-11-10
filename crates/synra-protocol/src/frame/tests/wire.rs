use bytes::Bytes;
use rstest::rstest;
use crate::limits::FRAME_HEADER_LEN;
use super::super::{ChunkFrame, Frame, FrameBody, FrameError, FrameKind};
use super::{decode_one, encode};

#[test]
fn every_kind_round_trips_through_a_byte() {
    for kind in [
        FrameKind::Envelope,
        FrameKind::Chunk,
        FrameKind::Ping,
        FrameKind::Pong,
        FrameKind::Hello,
        FrameKind::HelloAck,
        FrameKind::Bye,
    ] {
        assert_eq!(FrameKind::from_u8(kind.as_u8()), Ok(kind), "{kind}");
    }
}

#[rstest]
#[case(0x00)]
#[case(0x08)]
#[case(0xFF)]
fn unknown_kind_bytes_are_rejected(#[case] byte: u8) {
    assert!(matches!(
        FrameKind::from_u8(byte),
        Err(FrameError::UnknownKind { kind }) if kind == byte
    ));
}

#[test]
fn ping_encodes_to_exactly_the_header() {
    let bytes = encode(&Frame::empty(FrameKind::Ping));
    assert_eq!(bytes.len(), FRAME_HEADER_LEN);
    // The length field counts the kind and flags bytes too, so a body-less frame declares 2.
    assert_eq!(&bytes[..4], &[0, 0, 0, 2]);
    assert_eq!(bytes[4], FrameKind::Ping.as_u8());
}

#[test]
fn envelope_round_trips() {
    let payload = Bytes::from_static(br#"{"event":"device.ping"}"#);
    let bytes = encode(&Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(payload.clone()),
    });

    let frame = decode_one(bytes).expect("decodes").expect("one frame");
    assert_eq!(frame.kind, FrameKind::Envelope);
    assert_eq!(frame.body, FrameBody::Envelope(payload));
}

#[test]
fn chunk_round_trips_with_its_id() {
    let bytes = encode(&Frame {
        kind: FrameKind::Chunk,
        flags: 0,
        body: FrameBody::Chunk(ChunkFrame {
            chunk_id: 0xDEAD_BEEF,
            data: Bytes::from_static(b"hello"),
        }),
    });

    let frame = decode_one(bytes).expect("decodes").expect("one frame");
    match frame.body {
        FrameBody::Chunk(chunk) => {
            assert_eq!(chunk.chunk_id, 0xDEAD_BEEF);
            assert_eq!(&chunk.data[..], b"hello");
        }
        other => panic!("expected a chunk, got {other:?}"),
    }
}

#[test]
fn flags_are_preserved_for_future_use() {
    let bytes = encode(&Frame { kind: FrameKind::Ping, flags: 0xAB, body: FrameBody::Empty });
    let frame = decode_one(bytes).expect("decodes").expect("one frame");
    assert_eq!(frame.flags, 0xAB);
}

#[test]
fn encoded_len_matches_what_was_written() {
    let frame = Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from_static(b"{}")),
    };
    assert_eq!(encode(&frame).len(), frame.encoded_len());
}

#[test]
fn a_chunk_with_empty_data_is_legal() {
    // Zero-length data is unusual but not a violation: a session may legitimately send an empty
    // final chunk.
    let bytes = encode(&Frame {
        kind: FrameKind::Chunk,
        flags: 0,
        body: FrameBody::Chunk(ChunkFrame { chunk_id: 9, data: Bytes::new() }),
    });
    let frame = decode_one(bytes).expect("decodes").expect("one frame");
    assert_eq!(frame.body, FrameBody::Chunk(ChunkFrame { chunk_id: 9, data: Bytes::new() }));
}
