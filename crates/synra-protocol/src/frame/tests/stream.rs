use bytes::{Bytes, BytesMut};
use crate::limits::FRAME_HEADER_LEN;
use super::super::{ChunkFrame, Frame, FrameBody, FrameDecoder, FrameEncoder, FrameError, FrameKind};
use super::encode;

#[test]
fn a_whole_frame_is_sliced_not_copied() {
    // The fast path. A read containing a whole frame must be sliced, so the decoded payload
    // points into the buffer the caller handed over — which is what makes forwarding a message a
    // refcount bump rather than a memcpy.
    static PAYLOAD: [u8; 64] = [7u8; 64];
    let frame_bytes = encode(&Frame {
        kind: FrameKind::Chunk,
        flags: 0,
        body: FrameBody::Chunk(ChunkFrame { chunk_id: 1, data: Bytes::from_static(&PAYLOAD) }),
    });
    let input = Bytes::from(frame_bytes.to_vec());
    let base = input.as_ptr() as usize;

    let mut decoder = FrameDecoder::new();
    decoder.push(&input).expect("push");
    let frame = decoder.next_frame().expect("decodes").expect("one frame");

    match frame.body {
        FrameBody::Chunk(chunk) => {
            assert_eq!(
                chunk.data.as_ptr() as usize - base,
                FRAME_HEADER_LEN + 4,
                "the payload must be a slice of the caller's buffer",
            );
            assert_eq!(&chunk.data[..], &PAYLOAD[..]);
        }
        other => panic!("expected a chunk, got {other:?}"),
    }
}

#[test]
fn a_frame_split_across_reads_is_reassembled() {
    // The slow path: the pieces have to be copied somewhere, and the result must still be
    // correct. Nothing may be lost or reordered.
    let bytes = encode(&Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}")),
    });

    for split in 1..bytes.len() {
        let mut decoder = FrameDecoder::new();
        decoder.push_slice(&bytes[..split]).expect("push head");
        assert_eq!(
            decoder.next_frame().expect("head is valid or incomplete"),
            None,
            "split at {split}"
        );

        decoder.push_slice(&bytes[split..]).expect("push tail");
        let frame = decoder.next_frame().expect("decodes").expect("one frame");
        assert_eq!(
            frame.body,
            FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}")),
            "split at {split}"
        );
    }
}

#[test]
fn three_way_split_reassembles() {
    // More than two pieces, so the scratch buffer has to survive more than one append.
    let bytes = encode(&Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from_static(b"hello")),
    });
    let (a, rest) = bytes.split_at(3);
    let (b, c) = rest.split_at(2);

    let mut decoder = FrameDecoder::new();
    for piece in [a, b, c] {
        decoder.push_slice(piece).expect("push");
    }
    let frame = decoder.next_frame().expect("decodes").expect("one frame");
    assert_eq!(frame.body, FrameBody::Envelope(Bytes::from_static(b"hello")));
}

#[test]
fn multiple_frames_in_one_batch_decode_in_order() {
    let mut batch = BytesMut::new();
    FrameEncoder::encode(&Frame::empty(FrameKind::Ping), &mut batch).expect("encode ping");
    FrameEncoder::encode(
        &Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"{}")),
        },
        &mut batch,
    )
    .expect("encode envelope");

    let mut decoder = FrameDecoder::new();
    decoder.push(&batch.freeze()).expect("push");

    let first = decoder.next_frame().expect("first").expect("present");
    assert_eq!(first.kind, FrameKind::Ping);
    let second = decoder.next_frame().expect("second").expect("present");
    assert_eq!(second.kind, FrameKind::Envelope);
    assert_eq!(decoder.next_frame().expect("no more"), None);
}

#[test]
fn recycle_keeps_the_decoder_usable() {
    let mut decoder = FrameDecoder::new();
    decoder
        .push(&encode(&Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"{}")),
        }))
        .expect("push");
    let _ = decoder.next_frame().expect("decodes");
    assert_eq!(decoder.buffered(), 0);

    decoder.recycle();
    assert!(!decoder.is_poisoned());
    assert_eq!(decoder.next_frame().expect("empty"), None);

    decoder
        .push(&encode(&Frame::empty(FrameKind::Pong)))
        .expect("push");
    let frame = decoder.next_frame().expect("decodes").expect("present");
    assert_eq!(frame.kind, FrameKind::Pong);
}

#[test]
fn release_marks_the_decoder_unusable() {
    // A decoder from a dead link must not be reused: leftover bytes would be read as the new
    // stream's first frame.
    let mut decoder = FrameDecoder::new();
    decoder.push_slice(b"leftover").expect("push");
    decoder.release();
    assert!(decoder.is_poisoned());
    assert_eq!(decoder.next_frame(), Err(FrameError::Poisoned));
    assert_eq!(decoder.buffered(), 0);
}

#[test]
fn two_bodies_from_one_read_share_its_allocation() {
    let mut batch = BytesMut::new();
    for (id, data) in [(1u32, &b"aa"[..]), (2, b"bbbb")] {
        FrameEncoder::encode(
            &Frame {
                kind: FrameKind::Chunk,
                flags: 0,
                body: FrameBody::Chunk(ChunkFrame {
                    chunk_id: id,
                    data: Bytes::copy_from_slice(data),
                }),
            },
            &mut batch,
        )
        .expect("encode");
    }
    let input = batch.freeze();
    let base = input.as_ptr() as usize;

    let mut decoder = FrameDecoder::new();
    decoder.push(&input).expect("push");

    let first = decoder.next_frame().expect("first").expect("present");
    let second = decoder.next_frame().expect("second").expect("present");
    let (FrameBody::Chunk(a), FrameBody::Chunk(b)) = (&first.body, &second.body) else {
        panic!("expected two chunks");
    };

    let a_start = a.data.as_ptr() as usize - base;
    let b_start = b.data.as_ptr() as usize - base;
    assert!(b_start > a_start, "the second chunk must follow the first");
    // Both are windows onto the same allocation.
    assert!(b_start + b.data.len() <= input.len());
}
