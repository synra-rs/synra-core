use super::super::{ChannelError, Decoder, HEADER_LEN, MAX_MESSAGE_LEN, Request, encode};

#[test]
fn the_header_is_a_big_endian_length_of_the_body() {
    // ★ The framing is what a client and a kernel agree on, so it is asserted byte for byte rather than only
    // round-tripped: a round trip through one implementation passes even when that implementation is wrong.
    let bytes = encode(&Request::Status).expect("encodes");
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    assert_eq!(len, bytes.len() - HEADER_LEN);

    // And the body is the JSON for the request, exactly. Asserted as the literal the wire carries rather than only
    // through a round trip, because a round trip through one implementation passes even when that implementation
    // spells the variant differently from the one a release already shipped.
    let body = std::str::from_utf8(&bytes[HEADER_LEN..]).expect("utf8");
    assert_eq!(body, r#""status""#, "{body}");
}

#[test]
fn a_partial_header_is_waited_for_rather_than_refused() {
    // A socket delivers bytes, not messages. A decoder that refused a partial header would fail on the first read of
    // every real connection.
    let bytes = encode(&Request::Status).expect("encodes");
    let mut decoder = Decoder::new();
    for byte in &bytes[..HEADER_LEN - 1] {
        decoder.push(&[*byte]);
        assert!(
            decoder
                .next_message::<Request>()
                .expect("no error")
                .is_none()
        );
    }
    decoder.push(&bytes[HEADER_LEN - 1..]);
    assert!(
        decoder
            .next_message::<Request>()
            .expect("no error")
            .is_some()
    );
}

#[test]
fn a_partial_body_is_waited_for() {
    // The same, one layer in: the header arrives and the body does not. The length is known and the bytes are not,
    // which is the ordinary state of a connection mid-message.
    let bytes = encode(&Request::SendText {
        to: "a".to_owned(),
        text: "b".to_owned(),
    })
    .expect("encodes");
    let split = HEADER_LEN + 3;
    let mut decoder = Decoder::new();
    decoder.push(&bytes[..split]);
    assert!(
        decoder
            .next_message::<Request>()
            .expect("no error")
            .is_none()
    );
    decoder.push(&bytes[split..]);
    assert!(
        decoder
            .next_message::<Request>()
            .expect("no error")
            .is_some()
    );
}

#[test]
fn two_messages_in_one_read_both_come_out() {
    // What a real socket does under load: one read holds several messages. A decoder that returned only the first
    // would leave the rest in the buffer until the next read — which may never come, because the client is waiting
    // for an answer.
    let mut bytes = encode(&Request::Status).expect("encodes");
    bytes.extend_from_slice(&encode(&Request::Plugins).expect("encodes"));

    let mut decoder = Decoder::new();
    decoder.push(&bytes);
    assert_eq!(
        decoder.next_message::<Request>().expect("no error"),
        Some(Request::Status)
    );
    assert_eq!(
        decoder.next_message::<Request>().expect("no error"),
        Some(Request::Plugins)
    );
    assert!(
        decoder
            .next_message::<Request>()
            .expect("no error")
            .is_none()
    );
    assert_eq!(decoder.buffered(), 0);
}

#[test]
fn a_message_split_across_three_reads_is_assembled() {
    let bytes = encode(&Request::Logs {
        lines: 10,
        verbose: false,
        trace: None,
    })
    .expect("encodes");
    let third = bytes.len() / 3;
    let mut decoder = Decoder::new();
    decoder.push(&bytes[..third]);
    decoder.push(&bytes[third..third * 2]);
    decoder.push(&bytes[third * 2..]);
    assert_eq!(
        decoder.next_message::<Request>().expect("no error"),
        Some(Request::Logs {
            lines: 10,
            verbose: false,
            trace: None
        })
    );
}

// ── The ceiling ───────────────────────────────────────────────────────────────────────────────

#[test]
fn a_length_beyond_the_ceiling_is_refused_before_the_body_arrives() {
    // ★ A length prefix is a promise the reader has to be willing to accept. Without the check, one frame can ask
    // the kernel to allocate four gigabytes — and a reader that waited for the body would do it after waiting for
    // bytes that will never come.
    let mut decoder = Decoder::new();
    let huge = u32::try_from(MAX_MESSAGE_LEN + 1).expect("fits");
    decoder.push(&huge.to_be_bytes());

    match decoder.next_message::<Request>() {
        Err(ChannelError::TooLong { len, max }) => {
            assert_eq!(len, MAX_MESSAGE_LEN + 1);
            assert_eq!(max, MAX_MESSAGE_LEN);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And the body never arrived, yet the decoder is poisoned rather than waiting.
    assert!(decoder.is_poisoned());
    assert_eq!(decoder.buffered(), HEADER_LEN);
}

#[test]
fn a_message_exactly_at_the_ceiling_is_accepted() {
    // The boundary. An off-by-one here is a legitimate message refused, or a message one byte over accepted.
    // Sized by working backwards from what `encode` refuses, rather than by guessing the JSON overhead — a guess
    // that was wrong the first time this test was written.
    let overhead = serde_json::to_vec(&Request::SendText {
        to: "a".to_owned(),
        text: String::new(),
    })
    .expect("encodes")
    .len();
    let payload = "x".repeat(MAX_MESSAGE_LEN - overhead);
    let request = Request::SendText {
        to: "a".to_owned(),
        text: payload,
    };
    let bytes = encode(&request).expect("encodes");
    assert!(
        bytes.len() <= MAX_MESSAGE_LEN + HEADER_LEN,
        "{} bytes",
        bytes.len()
    );

    let mut decoder = Decoder::new();
    decoder.push(&bytes);
    assert!(
        decoder
            .next_message::<Request>()
            .expect("no error")
            .is_some()
    );
}

#[test]
fn encoding_something_too_long_is_refused() {
    // The other end of the same rule: a server that produced an oversized answer would otherwise write a length the
    // client refuses, and the client would report a framing error for a message that was fine.
    let payload = "x".repeat(MAX_MESSAGE_LEN);
    let request = Request::SendText {
        to: "a".to_owned(),
        text: payload,
    };
    assert!(matches!(
        encode(&request),
        Err(ChannelError::TooLong { .. })
    ));
}

// ── Poisoning ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_body_that_is_not_json_poisons_the_decoder() {
    // ★ A framing error leaves the stream in an unknown position: the bytes after a length that was wrong are not
    // where the next header is. Continuing would read a body as a header and present as nonsense several messages
    // later rather than as the one bad frame that caused it.
    let mut decoder = Decoder::new();
    let body = b"{not json";
    let len = u32::try_from(body.len()).expect("fits");
    decoder.push(&len.to_be_bytes());
    decoder.push(body);

    assert!(matches!(
        decoder.next_message::<Request>(),
        Err(ChannelError::Malformed { .. })
    ));
    assert!(decoder.is_poisoned());
    // And it keeps refusing, rather than recovering into a stream position nobody can vouch for.
    assert!(decoder.next_message::<Request>().is_err());
}

#[test]
fn a_poisoned_decoder_ignores_further_bytes() {
    // Buffering after a framing error would grow without bound for a client that kept writing, which is a memory
    // leak a peer can drive.
    let mut decoder = Decoder::new();
    let huge = u32::try_from(MAX_MESSAGE_LEN + 1).expect("fits");
    decoder.push(&huge.to_be_bytes());
    assert!(decoder.next_message::<Request>().is_err());

    let before = decoder.buffered();
    decoder.push(&[0u8; 4096]);
    assert_eq!(decoder.buffered(), before);
}

#[test]
fn an_empty_body_is_malformed_rather_than_a_message() {
    // A zero length is a header with nothing after it. A decoder that treated it as "no message yet" would wait
    // forever for a body that was never promised.
    let mut decoder = Decoder::new();
    decoder.push(&0u32.to_be_bytes());
    assert!(matches!(
        decoder.next_message::<Request>(),
        Err(ChannelError::Malformed { .. })
    ));
}

#[test]
fn a_message_with_an_unknown_field_is_refused() {
    // `deny_unknown_fields` on both sides: a client and a kernel that disagree about a field's name would otherwise
    // silently ignore it, and the field would look like it had no effect.
    let body = br#"{"status":null,"extra":1}"#;
    let len = u32::try_from(body.len()).expect("fits");
    let mut decoder = Decoder::new();
    decoder.push(&len.to_be_bytes());
    decoder.push(body);
    assert!(matches!(
        decoder.next_message::<Request>(),
        Err(ChannelError::Malformed { .. })
    ));
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        ChannelError::TooLong {
            len: 5_000_000,
            max: MAX_MESSAGE_LEN,
        },
        ChannelError::Malformed {
            why: "expected value".to_owned(),
        },
        ChannelError::VersionMismatch {
            client: 2,
            kernel: 1,
        },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
        assert!(!text.contains('}'), "{error:?} -> {text}");
    }
}

#[test]
fn the_ceiling_is_the_one_the_device_protocol_uses() {
    // Not a coincidence: one megabyte is far more than a command needs and the same figure the wire protocol uses
    // for a whole frame, so there is one number to remember rather than two.
    assert_eq!(MAX_MESSAGE_LEN, 1024 * 1024);
    assert_eq!(HEADER_LEN, 4);
}
