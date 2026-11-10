use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use bytes::{Bytes, BytesMut};
use super::{ChunkFrame, Frame, FrameBody, FrameDecoder, FrameEncoder, FrameKind};

fn arbitrary_kind() -> impl Strategy<Value = FrameKind> {
    prop_oneof![
        Just(FrameKind::Envelope),
        Just(FrameKind::Chunk),
        Just(FrameKind::Ping),
        Just(FrameKind::Pong),
        Just(FrameKind::Hello),
        Just(FrameKind::HelloAck),
        Just(FrameKind::Bye),
    ]
}

/// A frame that is legal to encode, so the round-trip property is meaningful.
fn arbitrary_frame() -> impl Strategy<Value = Frame> {
    (arbitrary_kind(), any::<u8>()).prop_flat_map(|(kind, flags)| {
        let body: BoxedStrategy<FrameBody> = match kind {
            FrameKind::Ping | FrameKind::Pong => Just(FrameBody::Empty).boxed(),
            FrameKind::Envelope => proptest::collection::vec(any::<u8>(), 1..256)
                .prop_map(|v| FrameBody::Envelope(Bytes::from(v)))
                .boxed(),
            FrameKind::Hello => proptest::collection::vec(any::<u8>(), 1..64)
                .prop_map(|v| FrameBody::Hello(Bytes::from(v)))
                .boxed(),
            FrameKind::HelloAck => proptest::collection::vec(any::<u8>(), 1..64)
                .prop_map(|v| FrameBody::HelloAck(Bytes::from(v)))
                .boxed(),
            FrameKind::Chunk => (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..128))
                .prop_map(|(chunk_id, data)| {
                    FrameBody::Chunk(ChunkFrame { chunk_id, data: Bytes::from(data) })
                })
                .boxed(),
            FrameKind::Bye => (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..32))
                .prop_map(|(code, reason)| FrameBody::Bye { code, reason: Bytes::from(reason) })
                .boxed(),
        };
        body.prop_map(move |body| Frame { kind, flags, body })
    })
}

proptest! {
    // Keep using the saved regression seeds from before this suite moved.
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/frame.txt"
        )))),
        ..ProptestConfig::default()
    })]

    /// Encoding then decoding returns the frame unchanged.
    #[test]
    fn frame_round_trips(frame in arbitrary_frame()) {
        let bytes = FrameEncoder::encode_to_vec(&frame).expect("a generated frame encodes");
        let mut decoder = FrameDecoder::new();
        decoder.push(&bytes).expect("push");
        let decoded = decoder.next_frame().expect("decodes").expect("one frame");
        prop_assert_eq!(decoded, frame);
    }

    /// The property the whole module exists for: arbitrary input either produces a frame, asks
    /// for more bytes, or reports an error. It never panics and never reads out of bounds.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut decoder = FrameDecoder::new();
        decoder.push_slice(&bytes).expect("first push succeeds");

        // Bounded by the input length, so a pathological length field cannot loop forever.
        for _ in 0..=bytes.len() {
            match decoder.next_frame() {
                Ok(Some(frame)) => {
                    // Touching the body proves the slice is in range.
                    let _ = frame.body.len();
                }
                Ok(None) => break,
                Err(_) => {
                    // The only allowed outcome besides success.
                    prop_assert!(decoder.is_poisoned());
                    break;
                }
            }
        }
    }

    /// Feeding bytes in arbitrary chunks produces the same frames as feeding them at once. This
    /// is what makes a decoder safe to use over a socket, where a frame arrives in as many
    /// pieces as the network chooses.
    #[test]
    fn chunked_delivery_matches_bulk_delivery(
        frames in proptest::collection::vec(arbitrary_frame(), 1..6),
        cuts in proptest::collection::vec(0usize..64, 0..8),
    ) {
        let mut encoded = BytesMut::new();
        for frame in &frames {
            FrameEncoder::encode(frame, &mut encoded).expect("encodes");
        }
        let bulk = encoded.freeze();

        let mut decoder = FrameDecoder::new();
        let mut collected = Vec::new();
        let mut offset = 0usize;
        for cut in cuts {
            let end = (offset + cut).min(bulk.len());
            decoder.push(&bulk.slice(offset..end)).expect("push");
            offset = end;
            while let Some(frame) = decoder.next_frame().expect("valid stream") {
                collected.push(frame);
            }
        }
        decoder.push(&bulk.slice(offset..)).expect("push tail");
        while let Some(frame) = decoder.next_frame().expect("valid stream") {
            collected.push(frame);
        }

        prop_assert_eq!(collected, frames);
    }
}
