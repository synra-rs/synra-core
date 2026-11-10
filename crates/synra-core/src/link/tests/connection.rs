use super::{LOCAL, PEER, device, connected, link, envelope};
use super::super::*;

#[test]
fn a_ping_is_answered_without_the_caller_seeing_it() {
    // ★ A caller that had to handle a `Ping` would be one that could forget to — and the consequence is a peer that
    // concludes the link is dead while it is working. A heartbeat is the link's own business.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender.ping().expect("sends");
    // The receiver first answers the ping, then gets the envelope that follows it.
    sender
        .send(&envelope(PEER, LOCAL, "device.ping"))
        .expect("sends");

    let got = receiver.receive().expect("receives");
    assert_eq!(got.event.as_str(), "device.ping");
    // Only the envelope counted, because a heartbeat is not a message the session has anything to do with.
    assert_eq!(receiver.received(), 1);

    // And the pong came back, which the sender reads as a frame it can ignore.
    let mut decoder = FrameDecoder::new();
    let mut buffer = [0u8; 1024];
    let read = sender.stream.read(&mut buffer).expect("reads");
    decoder
        .push_slice(buffer.get(..read).expect("a chunk"))
        .expect("the frame is well formed");
    let frame = decoder.next_frame().expect("no error").expect("a frame");
    assert_eq!(frame.kind, FrameKind::Pong);
}

#[test]
fn a_frame_the_decoder_refuses_ends_the_link() {
    // ★ A1 says a structural problem closes the link. The decoder side of that was already tested
    // (the frame decoder tests: an unknown kind poisons, and a poisoned decoder refuses further use). What was missing is the
    // other half: that the **link** stops, rather than carrying on in a state where every later read fails for a
    // reason that has nothing to do with what the caller did.
    //
    // Without this, the sentence in the design document was supported by a code reading and not by a test — which is
    // the same gap `code review + test` is written to close.
    let (a, b) = connected();
    let mut a = a;

    // ★ The bytes are written straight onto the socket rather than through `send_frame`, and that is the point.
    // `send_frame` refuses this frame first — the encoder validates the kind and body pair and answers
    // `BodyKindMismatch` — so a test built on the sender could only ever prove that the *encoder* is careful.
    // A peer is not the encoder: it is whatever is on the other end, so the only honest way to test the receiving
    // half is to produce bytes no compliant sender would.
    //
    // The layout is the documented one: `u32 BE length` (4 = kind + flags + two body bytes), then an unknown
    // kind byte `0xff`, then flags, then a two-byte body.
    use std::io::Write;
    a.write_all(&[0x00, 0x00, 0x00, 0x04, 0xff, 0x00, b'{', b'}'])
        .expect("writes");

    let mut _sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    let first = receiver.receive();
    assert!(
        matches!(
            first,
            Err(LinkError::Frame(_)) | Err(LinkError::Unexpected { .. })
        ),
        "an unknown frame kind was accepted: {first:?}"
    );

    // And the link does not come back: a second read is refused rather than returning whatever happens to be next.
    let second = receiver.receive();
    assert!(
        second.is_err(),
        "the link carried on after a refused frame: {second:?}"
    );
}

#[test]
fn a_bye_ends_the_link() {
    // The peer saying goodbye is the ordinary end, and a caller reads it as closed rather than as a fault.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender.bye("done").expect("sends");
    assert!(matches!(receiver.receive(), Err(LinkError::Closed)));
}

#[test]
fn a_peer_that_hangs_up_is_reported_as_closed() {
    // The ordinary shape of a user who closed a laptop. On Windows this arrives as a reset rather than a clean
    // end-of-file, which is why the check is on the error rather than on the read count alone.
    let (a, b) = connected();
    let mut receiver = link(b, LOCAL, PEER);
    drop(a);

    assert!(matches!(receiver.receive(), Err(LinkError::Closed)));
}

#[test]
fn the_link_knows_both_identifiers_and_what_was_agreed() {
    let (a, _b) = connected();
    let link = link(a, LOCAL, PEER);
    assert_eq!(link.local(), device(LOCAL));
    assert_eq!(link.peer(), device(PEER));
    assert!(link.supports(synra_protocol::handshake::Feature::EventStream));
    assert!(!link.supports(synra_protocol::handshake::Feature::ClipboardSync));
    assert_eq!(link.sent(), 0);
    assert_eq!(link.received(), 0);
}

#[test]
fn a_link_with_a_missing_required_feature_is_still_made() {
    // The link is built from an `Agreed` rather than deciding for itself: a caller that wants to refuse a link with
    // a missing requirement does so before building it, and one that built it anyway can still ask.
    let (a, _b) = connected();
    let broken = synra_protocol::handshake::Agreed {
        common: Vec::new(),
        missing_required: vec![synra_protocol::handshake::Feature::TransferResume],
    };
    let link = PeerLink::new(a, device(LOCAL), device(PEER), broken, Flags::no_timeout());
    assert!(!link.agreed().is_usable());
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        LinkError::Transport {
            why: "reset".to_owned(),
        },
        LinkError::Closed,
        LinkError::Frame(FrameError::Poisoned),
        LinkError::Unexpected {
            found: "chunk".to_owned(),
        },
        LinkError::Envelope {
            why: "not for us".to_owned(),
        },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn a_handshake_failure_becomes_the_matching_link_failure() {
    // A handshake's transport failure and a link's are the same condition seen at different moments, so a caller does
    // not have to handle two spellings of "the connection broke".
    assert!(matches!(
        LinkError::from(HandshakeError::Transport {
            why: "x".to_owned()
        }),
        LinkError::Transport { .. }
    ));
    assert!(matches!(
        LinkError::from(HandshakeError::Closed),
        LinkError::Closed
    ));
    assert!(matches!(
        LinkError::from(HandshakeError::Frame(FrameError::Poisoned)),
        LinkError::Frame(_)
    ));
    assert!(matches!(
        LinkError::from(HandshakeError::VersionMismatch { theirs: 2, ours: 1 }),
        LinkError::Envelope { .. }
    ));
}
