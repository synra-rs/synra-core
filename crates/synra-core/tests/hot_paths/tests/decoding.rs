use super::*;

/// A frame's bytes, encoded once outside the measurement.
///
/// Encoded before the guard is installed, because *encoding* is not a hot path — a frame is built once and decoded
/// once per hop — and measuring the two together would make the assertion about the wrong thing.
fn encoded(kind: FrameKind) -> Bytes {
    let frame = match kind {
        FrameKind::Envelope => Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: synra_protocol::frame::FrameBody::Envelope(Bytes::from_static(
                br#"{"event":"device.ping","from":"dev_a","payload":{}}"#,
            )),
        },
        other => Frame::empty(other),
    };
    synra_protocol::frame::FrameEncoder::encode_to_vec(&frame).expect("the fixture encodes")
}

#[test]
fn decoding_a_frame_allocates_nothing() {
    // ★ Hot path #1. Every frame the kernel receives goes through this, and an allocation here is paid per frame
    // rather than per message.
    let bytes = encoded(FrameKind::Envelope);

    // The decoder is built outside the measurement: its first `push` reserves, and a reservation is the one
    // allocation a decoder is *allowed* to make — it is the buffer the frames are sliced out of.
    let mut decoder = FrameDecoder::new();
    decoder.push(&bytes).expect("the frame is well formed");

    warm_the_counter();
    let (_, count) = CounterGuard::counted(|| {
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        // The kind and the body are read, because a decoder that returned a frame without touching its bytes
        // would be one that had not decoded anything.
        assert_eq!(frame.kind, FrameKind::Envelope);
        std::hint::black_box(frame.body);
    });

    assert!(
        AllocationBudget::NONE.allows(count),
        "decoding a frame allocated: {}",
        AllocationBudget::NONE.explain(count)
    );
}

#[test]
fn decoding_a_heartbeat_allocates_nothing() {
    // The frame a link sends when it has nothing to say, which is the one that runs at the highest rate: an
    // allocation here is paid once per heartbeat per link.
    let bytes = encoded(FrameKind::Ping);

    let mut decoder = FrameDecoder::new();
    decoder.push(&bytes).expect("the frame is well formed");

    warm_the_counter();
    let (_, count) = CounterGuard::counted(|| {
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!(frame.kind, FrameKind::Ping);
    });

    assert!(AllocationBudget::NONE.allows(count), "a heartbeat allocated: {count}");
}

#[test]
fn several_frames_from_one_buffer_allocate_nothing() {
    // The case a real socket produces: one read holds several frames. Each `next_frame` after the first is a slice
    // out of the same buffer, and a decoder that copied per frame would show up here and not in the single-frame
    // test.
    let mut together = bytes::BytesMut::new();
    for _ in 0..8 {
        together.extend_from_slice(&encoded(FrameKind::Envelope));
    }
    let together = together.freeze();

    let mut decoder = FrameDecoder::new();
    decoder.push(&together).expect("the frames are well formed");

    warm_the_counter();
    let (decoded, count) = CounterGuard::counted(|| {
        let mut decoded = 0u32;
        while let Some(frame) = decoder.next_frame().expect("no error") {
            decoded += 1;
            std::hint::black_box(frame.kind);
        }
        decoded
    });

    assert_eq!(decoded, 8, "the fixture did not produce eight frames");
    assert!(AllocationBudget::NONE.allows(count), "decoding eight frames allocated: {count}");
}
