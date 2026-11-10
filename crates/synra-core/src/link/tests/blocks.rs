use super::{LOCAL, PEER, device, connected, agreed, link, envelope};
use super::super::*;

#[test]
fn a_block_travels_from_one_link_to_the_other() {
    // ★ The data plane, which the link did not carry until now: a `ChunkFrame` is a different frame kind from an
    // envelope, and a reader that understood only envelopes refused it.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender.send_chunk(7, b"block bytes").expect("sends");
    match receiver.receive_inbound().expect("receives") {
        Inbound::Block { chunk_id, data } => {
            assert_eq!(chunk_id, 7);
            assert_eq!(&data[..], b"block bytes");
        }
        other => panic!("expected a block, got {other:?}"),
    }
    assert_eq!(sender.sent(), 1);
    assert_eq!(receiver.received(), 1);
}

#[test]
fn the_two_planes_interleave_without_confusing_each_other() {
    // ★ What a transfer actually looks like on the wire: a control message, blocks, another control message. A reader
    // that handled one plane but not the other would fail at the first block *or* at the first envelope after one.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender
        .send(&envelope(PEER, LOCAL, "file.transfer.request"))
        .expect("sends");
    sender.send_chunk(0, b"first").expect("sends");
    sender.send_chunk(1, b"second").expect("sends");
    sender
        .send(&envelope(PEER, LOCAL, "file.transfer.complete"))
        .expect("sends");

    let mut seen = Vec::new();
    for _ in 0..4 {
        match receiver.receive_inbound().expect("receives") {
            Inbound::Envelope(envelope) => {
                seen.push(format!("event:{}", envelope.event.as_str()));
            }
            Inbound::Block { chunk_id, data } => {
                seen.push(format!(
                    "block:{chunk_id}:{}",
                    String::from_utf8_lossy(&data)
                ));
            }
        }
    }
    assert_eq!(
        seen,
        vec![
            "event:file.transfer.request",
            "block:0:first",
            "block:1:second",
            "event:file.transfer.complete",
        ]
    );
}

#[test]
fn a_caller_that_asked_for_an_envelope_is_told_about_a_block() {
    // ★ `receive` refuses a block rather than dropping it. Dropping would lose part of a file silently, and the caller
    // that wanted only envelopes is one that has nowhere to put it.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender.send_chunk(0, b"data").expect("sends");
    match receiver.receive() {
        Err(LinkError::Unexpected { found }) => assert_eq!(found, "chunk"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_block_too_large_for_a_frame_is_refused() {
    // The ceiling is the protocol's, and the refusal happens before anything is written rather than after.
    let (a, _b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let too_big = vec![0u8; synra_protocol::limits::MAX_CHUNK_LEN + 1];
    assert!(sender.send_chunk(0, &too_big).is_err());
    // And the ceiling itself is accepted, because an off-by-one here would refuse a block the protocol allows.
    let at_limit = vec![0u8; synra_protocol::limits::MAX_CHUNK_LEN];
    assert!(sender.send_chunk(0, &at_limit).is_ok());
}

#[test]
fn a_ping_between_two_blocks_is_still_answered_invisibly() {
    // The heartbeat stays the link's business on the data plane too: a caller reading blocks should never see one.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender.send_chunk(0, b"before").expect("sends");
    sender.ping().expect("sends");
    sender.send_chunk(1, b"after").expect("sends");

    match receiver.receive_inbound().expect("first") {
        Inbound::Block { chunk_id, .. } => assert_eq!(chunk_id, 0),
        other => panic!("expected a block, got {other:?}"),
    }
    match receiver.receive_inbound().expect("second") {
        Inbound::Block { chunk_id, .. } => {
            assert_eq!(chunk_id, 1, "the ping was not swallowed")
        }
        other => panic!("expected a block, got {other:?}"),
    }
    // Exactly the two blocks were counted; the heartbeat is not a message.
    assert_eq!(receiver.received(), 2);
}

#[test]
fn a_full_size_block_survives_the_round_trip() {
    // ★ The size a real transfer uses, which is the size that found a bug: a 256 KiB block is far more than one socket
    // read, so it arrives in pieces. An earlier `read_frame` treated a socket timeout **between** two of those pieces
    // as a broken link and threw the buffered bytes away — so a 300 KB file arrived byte-for-byte while both ends
    // reported a timeout.
    // ★ `production()` rather than `no_timeout()`, because the timeout is the thing under test: a block larger than one
    // socket read sits in the buffer across several reads, and a timeout between two of them must not abandon it.
    let (a, b) = connected();
    let mut sender = PeerLink::new(
        a,
        device(LOCAL),
        device(PEER),
        agreed(),
        Flags::production(),
    );
    let mut receiver = PeerLink::new(
        b,
        device(PEER),
        device(LOCAL),
        agreed(),
        Flags::production(),
    );

    let first = vec![7u8; synra_protocol::limits::MAX_CHUNK_LEN];
    let second = vec![9u8; 37_856];

    let writer = std::thread::spawn(move || {
        sender.send_chunk(0, &first).expect("sends the first");
        sender.send_chunk(1, &second).expect("sends the second");
        sender
    });

    let mut seen = Vec::new();
    for _ in 0..2 {
        match receiver.receive_inbound().expect("receives a block") {
            Inbound::Block { chunk_id, data } => seen.push((chunk_id, data)),
            other => panic!("expected a block, got {other:?}"),
        }
    }
    let sender = writer.join().expect("the writer finished");

    assert_eq!(seen[0].0, 0);
    assert_eq!(seen[0].1.len(), synra_protocol::limits::MAX_CHUNK_LEN);
    assert!(seen[0].1.iter().all(|byte| *byte == 7));
    assert_eq!(seen[1].0, 1);
    assert_eq!(seen[1].1.len(), 37_856);
    assert!(seen[1].1.iter().all(|byte| *byte == 9));
    assert_eq!(sender.sent(), 2);
}
