use bytes::Bytes;
use crate::limits::{FRAME_HEADER_LEN, MAX_CHUNK_LEN};
use super::super::{Frame, FrameBody, FrameDecoder, FrameError, FrameKind};
use super::encode;

#[test]
fn length_below_the_minimum_is_rejected() {
    for len in 0u32..2 {
        let mut decoder = FrameDecoder::new();
        let mut header = Vec::from(len.to_be_bytes());
        header.extend_from_slice(&[FrameKind::Ping.as_u8(), 0]);
        decoder.push_slice(&header).expect("push");
        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::Truncated { len: got, min: 2 }) if got == len
        ));
        assert!(decoder.is_poisoned());
    }
}

#[test]
fn length_above_the_ceiling_is_rejected_rather_than_buffered() {
    let mut decoder = FrameDecoder::with_max_frame(1024);
    // Header only: the body never arrives, and must never be waited for.
    let mut header = Vec::from(2048u32.to_be_bytes());
    header.extend_from_slice(&[FrameKind::Envelope.as_u8(), 0]);
    decoder.push_slice(&header).expect("push");

    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::TooLarge { len: 2048, max: 1024 })
    ));
    assert!(decoder.is_poisoned());
}

#[test]
fn a_ceiling_breach_inside_scratch_is_also_rejected() {
    // Same property, reached through the partial-frame path: a split read must not let an
    // over-large claim through. Enough bytes are supplied for a header but not for the body, so
    // the decoder is holding a partial frame when it reads the length.
    let mut decoder = FrameDecoder::with_max_frame(64);
    let declared = 1000u32;
    let mut first = Vec::from(declared.to_be_bytes());
    first.extend_from_slice(&[FrameKind::Envelope.as_u8(), 0, b'{']);
    decoder.push_slice(&first).expect("push");

    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::TooLarge { len: 1000, max: 64 })
    ));
    assert!(decoder.is_poisoned());
}

#[test]
fn incomplete_frame_returns_none_and_does_not_poison() {
    // A real frame, split so that only the header and part of the body have arrived.
    let whole = encode(&Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}")),
    });

    let mut decoder = FrameDecoder::new();
    decoder.push_slice(&whole[..8]).expect("push head");
    assert_eq!(decoder.next_frame(), Ok(None));
    assert!(!decoder.is_poisoned());

    // And it becomes decodable once the rest arrives — with no byte lost in between.
    decoder.push_slice(&whole[8..]).expect("push rest");
    let frame = decoder.next_frame().expect("decodes").expect("one frame");
    assert_eq!(
        frame.body,
        FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}"))
    );
}

#[test]
fn unknown_kind_poisons_the_decoder() {
    let mut decoder = FrameDecoder::new();
    decoder.push_slice(&[0, 0, 0, 2, 0xFF, 0x00]).expect("push");
    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::UnknownKind { kind: 0xFF })
    ));
    assert!(decoder.is_poisoned());
}

#[test]
fn a_body_on_a_control_frame_is_rejected() {
    let mut decoder = FrameDecoder::new();
    // Declared 5 = kind + flags + 3 body bytes.
    decoder
        .push_slice(&[0, 0, 0, 5, FrameKind::Ping.as_u8(), 0, b'x', b'y', b'z'])
        .expect("push");
    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::UnexpectedBody { kind: FrameKind::Ping, len: 3 })
    ));
}

#[test]
fn a_chunk_shorter_than_its_id_is_rejected() {
    let mut decoder = FrameDecoder::new();
    // Declared 5 = kind + flags + 3 body bytes, but a chunk needs four for the id.
    decoder
        .push_slice(&[0, 0, 0, 5, FrameKind::Chunk.as_u8(), 0, 1, 2, 3])
        .expect("push");
    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::ChunkBodyTooShort { expected: 4, actual: 3 })
    ));
}

#[test]
fn an_oversized_chunk_is_rejected() {
    // A chunk's data ceiling is below the frame ceiling, so it is only reachable when the frame
    // ceiling is wide enough for the id and the data. A narrower `max_frame` would trip the
    // frame check first and the chunk check would never be exercised.
    let max_frame = u32::try_from(FRAME_HEADER_LEN + 4 + MAX_CHUNK_LEN + 1).expect("fits in u32");
    let mut decoder = FrameDecoder::with_max_frame(max_frame);

    let body_len = 4 + MAX_CHUNK_LEN + 1;
    let declared = u32::try_from(2 + body_len).expect("fits in u32");
    let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
    bytes.extend_from_slice(&declared.to_be_bytes());
    bytes.push(FrameKind::Chunk.as_u8());
    bytes.push(0);
    bytes.extend(std::iter::repeat_n(0u8, body_len));

    decoder.push_slice(&bytes).expect("push");
    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::ChunkTooLarge { len, max })
            if len == MAX_CHUNK_LEN + 1 && max == MAX_CHUNK_LEN
    ));
}

#[test]
fn empty_bye_body_is_a_missing_body_not_a_panic() {
    let mut decoder = FrameDecoder::new();
    decoder
        .push_slice(&[0, 0, 0, 2, FrameKind::Bye.as_u8(), 0])
        .expect("push");
    assert!(matches!(
        decoder.next_frame(),
        Err(FrameError::MissingBody { kind: FrameKind::Bye })
    ));
    assert!(decoder.is_poisoned());
}

#[test]
fn poisoned_decoder_refuses_further_use() {
    // This is the whole point of the module: after a structural error there is no way to
    // continue by accident.
    let mut decoder = FrameDecoder::new();
    decoder
        .push_slice(&[0, 0, 0, 1, FrameKind::Ping.as_u8(), 0])
        .expect("push");
    assert!(decoder.next_frame().is_err());
    assert!(decoder.is_poisoned());

    assert_eq!(decoder.next_frame(), Err(FrameError::Poisoned));
    assert_eq!(decoder.push(&Bytes::new()), Err(FrameError::Poisoned));
    assert_eq!(decoder.push_slice(b"x"), Err(FrameError::Poisoned));
}
