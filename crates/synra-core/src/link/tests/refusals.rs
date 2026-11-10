use super::{LOCAL, PEER, OTHER, device, connected, link, envelope};
use super::super::*;

#[test]
fn an_envelope_claiming_another_sender_is_refused() {
    // ★ The check only a link can make. The peer **is** the sender, so an envelope whose `from` is a different device
    // is a peer speaking for a device it is not — and without this, any paired device could send an intent that
    // appears to come from one the user trusts more.
    let (a, b) = connected();
    // The socket on `a` carries `OTHER`: that is who the receiver believes is on the other end, decided when the link
    // was built from the handshake. So an envelope claiming to be from `PEER` is a forgery *by this link's own
    // terms* — and the two versions of this test that failed were ones where the fixture had accidentally made the
    // envelope legitimate.
    let mut liar = link(a, OTHER, LOCAL);
    let mut receiver = link(b, LOCAL, OTHER);

    let forged = envelope(PEER, LOCAL, "device.ping");
    liar.send(&forged).expect("sends");

    match receiver.receive() {
        Err(LinkError::Envelope { why }) => {
            assert!(why.contains(&device(PEER).to_string()), "{why}");
            assert!(why.contains(&device(OTHER).to_string()), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And nothing was counted as received, because nothing was.
    assert_eq!(receiver.received(), 0);
}

#[test]
fn an_envelope_addressed_elsewhere_is_refused() {
    // A peer that sends one for another device is either misconfigured or probing, and either way this link is not
    // the one to route it.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender
        .send(&envelope(PEER, OTHER, "device.ping"))
        .expect("sends");
    assert!(matches!(
        receiver.receive(),
        Err(LinkError::Envelope { .. })
    ));
}

#[test]
fn a_frame_that_is_not_an_envelope_is_refused() {
    // A `Hello` after the handshake is a peer that has lost track of where it is, and a `Bye` is one saying goodbye —
    // neither is a message this reader carries. ★ A `Chunk` used to be in this list, and is not any more: the data
    // plane travels here now, and a block is refused by `receive` specifically rather than as an unknown frame.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    // A `Hello` needs its own body: the protocol pairs each kind with a variant, and an empty one is refused by the
    // encoder rather than by the link.
    let hello = Frame {
        kind: FrameKind::Hello,
        flags: 0,
        body: FrameBody::Hello(Bytes::from_static(b"{}")),
    };
    sender.send_frame(&hello).expect("sends");
    match receiver.receive() {
        Err(LinkError::Unexpected { found }) => assert_eq!(found, "hello"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_malformed_envelope_is_refused_rather_than_panicking() {
    // The frame is well formed and its contents are not, which is the case a peer controls.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    let frame = Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from_static(b"{not json")),
    };
    sender.send_frame(&frame).expect("sends");
    assert!(matches!(
        receiver.receive(),
        Err(LinkError::Envelope { .. })
    ));
}

#[test]
fn an_envelope_that_is_not_utf8_is_refused() {
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    let frame = Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from_static(&[0xff, 0xfe, 0xfd])),
    };
    sender.send_frame(&frame).expect("sends");
    match receiver.receive() {
        Err(LinkError::Envelope { why }) => assert!(why.contains("text"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
