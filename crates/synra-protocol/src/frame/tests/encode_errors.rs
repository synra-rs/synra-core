use bytes::{Bytes, BytesMut};
use rstest::rstest;
use crate::limits::MAX_FRAME_LEN;
use super::super::{ChunkFrame, Frame, FrameBody, FrameEncoder, FrameError, FrameKind};

#[rstest]
#[case(Frame { kind: FrameKind::Ping, flags: 0, body: FrameBody::Envelope(Bytes::from_static(b"{}")) }, "envelope")]
#[case(Frame { kind: FrameKind::Envelope, flags: 0, body: FrameBody::Empty }, "empty")]
#[case(Frame { kind: FrameKind::Chunk, flags: 0, body: FrameBody::Empty }, "empty")]
#[case(Frame { kind: FrameKind::Bye, flags: 0, body: FrameBody::Empty }, "empty")]
#[case(Frame { kind: FrameKind::Hello, flags: 0, body: FrameBody::Chunk(ChunkFrame { chunk_id: 1, data: Bytes::new() }) }, "chunk")]
fn mismatched_body_shapes_cannot_be_encoded(#[case] frame: Frame, #[case] body: &str) {
    // Rejecting at encode time means a caller cannot put an unparseable frame on the wire.
    let mut out = BytesMut::new();
    match FrameEncoder::encode(&frame, &mut out) {
        Err(FrameError::BodyKindMismatch { kind, body: actual }) => {
            assert_eq!(kind, frame.kind);
            assert_eq!(actual, body);
        }
        Err(FrameError::MissingBody { kind }) => assert_eq!(kind, frame.kind),
        other => panic!("expected a shape error, got {other:?}"),
    }
    assert!(out.is_empty(), "a failed encode must leave the buffer untouched");
}

#[test]
fn encode_refuses_an_oversized_envelope() {
    let frame = Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from(vec![b'{'; MAX_FRAME_LEN as usize])),
    };
    let mut out = BytesMut::new();
    assert!(matches!(
        FrameEncoder::encode(&frame, &mut out),
        Err(FrameError::EncodeTooLarge { .. })
    ));
    assert!(out.is_empty());
}
