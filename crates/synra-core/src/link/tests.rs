use super::memory::MemoryStream;
use super::*;
use std::net::Ipv4Addr;
use synra_protocol::envelope::OutboundSpec;
use synra_protocol::event::EventName;
use synra_protocol::ids::TraceId;

const LOCAL: &str = "11111111-1111-4111-8111-111111111111";
const PEER: &str = "22222222-2222-4222-8222-222222222222";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";

fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

/// A pair of connected sockets, as an established link would have.
fn connected() -> (TcpStream, TcpStream) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds");
    let address = listener.local_addr().expect("an address");
    let dialer = TcpStream::connect(address).expect("connects");
    let (accepted, _) = listener.accept().expect("accepts");
    (dialer, accepted)
}

fn agreed() -> synra_protocol::handshake::Agreed {
    synra_protocol::handshake::Agreed {
        common: vec![synra_protocol::handshake::Feature::EventStream],
        missing_required: Vec::new(),
    }
}

fn link_with_timeout(
    stream: TcpStream,
    local: &str,
    peer: &str,
    timeout: std::time::Duration,
) -> PeerLink {
    PeerLink::new(
        stream,
        device(local),
        device(peer),
        agreed(),
        Flags {
            timeout: Some(timeout),
        },
    )
}

#[test]
fn the_callers_write_deadline_wins_over_the_negotiated_one() {
    // ★ The decision, which is the part a test can hold: a socket's write timeout has no getter, so "was
    // `set_write_timeout` called" is not askable — but *which deadline applies* is, and that is the question the two
    // sources raise. Without this, the override could be stored and never consulted and nothing would notice.
    let (dialer, _peer) = connected();
    let mut link = link_with_timeout(dialer, LOCAL, PEER, std::time::Duration::from_secs(30));

    assert_eq!(
        link.write_deadline(),
        Some(std::time::Duration::from_secs(30)),
        "the negotiated one"
    );
    link.set_write_timeout(Some(std::time::Duration::from_millis(250)));
    assert_eq!(
        link.write_deadline(),
        Some(std::time::Duration::from_millis(250)),
        "the caller's"
    );
    // And `None` puts the negotiated one back rather than removing every deadline — the same reading
    // `set_read_timeout` has.
    link.set_write_timeout(None);
    assert_eq!(
        link.write_deadline(),
        Some(std::time::Duration::from_secs(30))
    );
}

// ── A peer that stops reading ─────────────────────────────────────────────────────────────────
//
// ★ The socket-based version of this test is gone, and what replaced it is above: `a_pipe_that_is_full_stops_the_writer`
// uses a 4 KiB pipe so the bound is the **fixture's** rather than the operating system's. The version that remains below
// tests the other direction — a peer that is **gone** rather than busy — and needs a real socket, because only a closed
// socket produces a connection reset while a dropped `MemoryStream` produces end-of-file.

#[test]
fn a_peer_that_is_gone_is_a_transport_failure_rather_than_a_quiet_link() {
    // ★ The other half of the distinction, and the reason it is a distinction at all. If a closed socket were also
    // reported as `TimedOut`, a caller would back off from a peer that has actually gone — waiting out a backoff schedule
    // for a link that will never carry anything again. One condition has a repair and the other does not.
    let (dialer, peer) = connected();
    let mut link = link_with_timeout(dialer, LOCAL, PEER, std::time::Duration::from_secs(5));
    drop(peer);

    // The first write after a peer closes may still be absorbed by the local buffer; the failure arrives after that.
    let block = vec![0u8; 32 * 1024];
    let mut refusal = None;
    for index in 0..64_u32 {
        match link.send_chunk(index, &block) {
            Ok(()) => continue,
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }

    match refusal {
        Some(LinkError::Transport { .. }) => {}
        Some(LinkError::TimedOut) => {
            panic!("a closed socket is not a quiet link: the peer is gone, not busy")
        }
        Some(other) => panic!("expected a transport failure, got {other:?}"),
        None => panic!("a closed peer absorbed sixty-four blocks"),
    }
}

#[test]
fn two_links_exchange_an_envelope_over_memory_rather_than_a_socket() {
    // ★ The seam, proved by the only thing that can prove it: a link that was never near a socket.
    //
    // `04 §11` records that the design's end-to-end tests were unwritable because `PeerLink` held a concrete
    // `TcpStream` while `synra-testkit`'s `MemoryTransport` moves decoded frames — two layers, no seam. This is the
    // seam, and this test is the smallest thing that shows it carries a real envelope through the real framing, with the
    // real checks (the target is ours, the sender is the peer) applied on the way.
    let (here, there) = MemoryStream::pair();
    let mut sender = link_with_stream(here, LOCAL, PEER);
    let mut receiver = link_with_stream(there, PEER, LOCAL);

    sender
        .send(&envelope(LOCAL, PEER, "_plugin.@acme/chat.text"))
        .expect("sends over memory");
    let received = receiver.receive().expect("receives over memory");

    assert_eq!(received.event.as_str(), "_plugin.@acme/chat.text");
    assert_eq!(received.from, device(LOCAL));
    assert_eq!(received.target, device(PEER));
    // And the counters the report is built from moved, so this went through the same path a socket does.
    assert_eq!(sender.sent(), 1);
    assert_eq!(receiver.received(), 1);
}

#[test]
fn a_memory_reader_with_nothing_to_read_reports_a_quiet_link_rather_than_waiting() {
    // ★ The deadline, over memory. A fixture that blocked forever when nothing had been written would make every
    // test that reads before writing hang — and would make `is_a_timeout`'s distinction untestable, because the
    // distinction is exactly "nothing arrived yet" against "the connection is broken".
    let (here, _there) = MemoryStream::pair();
    let mut link = link_with_stream(here, LOCAL, PEER);
    link.set_read_timeout(Some(std::time::Duration::from_millis(20)));

    let started = std::time::Instant::now();
    let refused = link.receive().expect_err("nothing was written");

    match refused {
        LinkError::TimedOut => {}
        other => panic!("a quiet memory link is not {other:?}"),
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "it waited {:?}, which is not a deadline",
        started.elapsed()
    );
}

#[test]
fn dropping_one_end_stops_the_other_rather_than_leaving_it_waiting() {
    // The third property a socket has and a `Vec` does not: a closed peer is visible. The unwrap is what would hang if
    // the close did not wake the reader.
    let (here, there) = MemoryStream::pair();
    let mut link = link_with_stream(here, LOCAL, PEER);
    drop(there);

    assert!(matches!(link.receive(), Err(LinkError::Closed)));
}

#[test]
fn a_pipe_that_is_full_stops_the_writer_without_waiting_for_a_socket_buffer_to_fill() {
    // ★ What the seam buys over a socket, in one test.
    //
    // `a_peer_that_stops_reading_is_told_rather_than_waited_for` reaches the same behaviour by writing into a real
    // socket until the operating system's buffer fills — which is slow, depends on how that machine is configured, and
    // has to send megabytes to get there. A pipe that is **4 KiB wide** reaches it in microseconds and reaches it the
    // same way on every machine, because the bound is this fixture's rather than the kernel's.
    //
    // The deadline is one millisecond, so "the write stopped" means "its deadline passed" rather than "the operating
    // system eventually gave up".
    let (here, _there) = MemoryStream::pair_with_capacity(4 * 1024);
    let mut link = link_with_stream(here, LOCAL, PEER);
    link.set_write_timeout(Some(std::time::Duration::from_millis(1)));

    let started = std::time::Instant::now();
    let refused = link
        .send_chunk(0, &[0u8; 8 * 1024])
        .expect_err("the pipe holds four");

    // ★ `TimedOut` and not `Transport`: the reader is alive and not reading, which is the distinction rounds 83 and 84
    // built. A caller backs off from this one and reconnects from the other.
    assert!(matches!(refused, LinkError::TimedOut), "{refused:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "it waited {:?}, which is not a deadline",
        started.elapsed()
    );
}

#[test]
fn the_same_narrow_pipe_carries_everything_when_somebody_reads() {
    // ★ The control for the test above, and the reason it is not just "a small pipe fails": the same 4 KiB pipe
    // delivers a block twice its width intact once a reader is taking bytes. Without this, a fixture that refused
    // everything would pass the other test.
    let (here, there) = MemoryStream::pair_with_capacity(4 * 1024);
    let mut sender = link_with_stream(here, LOCAL, PEER);
    let mut receiver = link_with_stream(there, PEER, LOCAL);
    sender.set_write_timeout(Some(std::time::Duration::from_millis(500)));
    receiver.set_read_timeout(Some(std::time::Duration::from_millis(500)));

    // Eight kibibytes through a four-kibibyte pipe, from another thread: the writer cannot finish until the reader
    // starts, which is exactly what a bounded pipe is for.
    let payload = vec![7u8; 8 * 1024];
    let writer = std::thread::spawn(move || {
        sender.send_chunk(0, &payload).expect("sends");
        sender
    });

    // ★ A block arrives on the block plane, so `receive` — which is the control plane and refuses anything else —
    // is the wrong door and said so: `Unexpected { found: "chunk" }`. `receive_inbound` is the sum of both planes.
    match receiver.receive_inbound().expect("receives") {
        Inbound::Block { chunk_id, data } => {
            assert_eq!(chunk_id, 0);
            assert_eq!(
                data.len(),
                8 * 1024,
                "the whole block, through a pipe half its width"
            );
            assert!(data.iter().all(|byte| *byte == 7));
        }
        other => panic!("expected a block, got {other:?}"),
    }
    let sender = writer.join().expect("the writer finished");
    assert_eq!(sender.sent(), 1);
    assert_eq!(receiver.received(), 1);
}

/// A link over anything that carries bytes.
fn link_with_stream(stream: impl LinkStream + 'static, local: &str, peer: &str) -> PeerLink {
    PeerLink::new(
        stream,
        device(local),
        device(peer),
        agreed(),
        Flags::no_timeout(),
    )
}

fn link(stream: TcpStream, local: &str, peer: &str) -> PeerLink {
    PeerLink::new(
        stream,
        device(local),
        device(peer),
        agreed(),
        Flags::no_timeout(),
    )
}

/// An envelope from `from` to `target`.
fn envelope(from: &str, target: &str, event: &str) -> Envelope {
    Envelope::outbound(
        OutboundSpec {
            event: EventName::parse(event).expect("a valid event name"),
            target: device(target),
            from: device(from),
            trace_id: TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: Some(60_000),
        },
        None::<&serde_json::Value>,
    )
    .expect("builds")
}

#[test]
fn a_partial_frame_obeys_the_read_budget_and_resumes_without_losing_bytes() {
    use std::io::Write as _;
    let (near, mut far) = MemoryStream::pair();
    let mut receiving = link_with_stream(near, LOCAL, PEER);
    receiving.set_read_timeout(Some(std::time::Duration::from_millis(30)));
    let frame = Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from(
            serde_json::to_vec(&envelope(PEER, LOCAL, "_synra.clipboard.received")).unwrap(),
        )),
    };
    let encoded = FrameEncoder::encode_to_vec(&frame).unwrap();
    let (prefix, rest) = encoded.split_at(7);
    far.write_all(prefix).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        receiving.receive_inbound().unwrap_err(),
        LinkError::TimedOut
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    far.write_all(rest).unwrap();
    assert_eq!(
        receiving.receive().unwrap().event.as_str(),
        "_synra.clipboard.received"
    );
}

#[test]
fn answering_a_ping_cannot_extend_the_callers_read_budget() {
    use std::io::Write as _;
    let (near, mut far) = MemoryStream::pair_with_capacity(128);
    let mut receiving = link_with_stream(near, LOCAL, PEER);
    receiving.set_read_timeout(Some(std::time::Duration::from_millis(30)));
    receiving.set_write_timeout(Some(std::time::Duration::from_secs(2)));
    receiving.stream.write_all(&[0; 128]).unwrap();
    far.write_all(&FrameEncoder::encode_to_vec(&Frame::empty(FrameKind::Ping)).unwrap())
        .unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        receiving.receive_inbound().unwrap_err(),
        LinkError::TimedOut
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(
        receiving.write_deadline(),
        Some(std::time::Duration::from_secs(2))
    );
}

// ── Envelopes in both directions ──────────────────────────────────────────────────────────────

#[test]
fn an_envelope_travels_from_one_link_to_the_other() {
    // The whole point: a socket whose handshake is done becomes a link that carries messages.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    sender
        .send(&envelope(PEER, LOCAL, "device.ping"))
        .expect("sends");
    let got = receiver.receive().expect("receives");

    assert_eq!(got.event.as_str(), "device.ping");
    assert_eq!(got.from, device(PEER));
    assert_eq!(got.target, device(LOCAL));
    assert_eq!(sender.sent(), 1);
    assert_eq!(receiver.received(), 1);
}

#[test]
fn a_link_with_a_recorder_counts_the_payload_bytes_it_moves() {
    // ★ The byte counters live on the link because the link is what holds the payloads; the host counts frames and
    // cannot add a number it never took. Payload bytes, not wire bytes: the frame header is the transport's accounting,
    // and "how much did this device move" is the question the counter exists to answer.
    use synra_observe::metrics::Value;

    let (a, b) = connected();
    let sender_metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
    let receiver_metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut sender = link(a, PEER, LOCAL).with_metrics(Arc::clone(&sender_metrics));
    let mut receiver = link(b, LOCAL, PEER).with_metrics(Arc::clone(&receiver_metrics));

    // The envelope helper carries no payload, so a block is what proves the counters move — and it proves it for both
    // directions, which are separate series.
    sender
        .send(&envelope(PEER, LOCAL, "device.ping"))
        .expect("sends");
    let _ = receiver.receive().expect("receives");
    sender.send_chunk(0, &[1, 2, 3, 4]).expect("sends a block");
    let _ = receiver.receive_inbound().expect("receives a block");

    assert_eq!(
        sender_metrics.snapshot().get("bytes_sent_total"),
        Some(&Value::Counter(4))
    );
    assert_eq!(
        receiver_metrics.snapshot().get("bytes_received_total"),
        Some(&Value::Counter(4))
    );
    // ★ And the frame counters, by event: the half that used to be counted in `Host::send`/`listener`, and therefore
    // only for frames that passed through one. Both directions are asserted here because the link is now the one
    // place they are taken.
    assert_eq!(
        sender_metrics
            .snapshot()
            .get("frames_sent_total{event=device.ping}"),
        Some(&Value::Counter(1))
    );
    assert_eq!(
        receiver_metrics
            .snapshot()
            .get("frames_received_total{event=device.ping}"),
        Some(&Value::Counter(1))
    );
}

#[test]
fn several_envelopes_arrive_in_order() {
    // A link is one socket and one stream, so order is the transport's — and a link that reordered would be one a
    // session could not use for a conversation.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    for event in ["device.first", "device.second", "device.third"] {
        sender.send(&envelope(PEER, LOCAL, event)).expect("sends");
    }
    let events: Vec<String> = (0..3)
        .map(|_| {
            receiver
                .receive()
                .expect("receives")
                .event
                .as_str()
                .to_owned()
        })
        .collect();
    assert_eq!(
        events,
        vec!["device.first", "device.second", "device.third"]
    );
}

#[test]
fn a_payload_survives_the_round_trip() {
    // The payload is a `RawValue` the kernel checks without parsing, so it has to arrive byte for byte.
    let (a, b) = connected();
    let mut sender = link(a, PEER, LOCAL);
    let mut receiver = link(b, LOCAL, PEER);

    let payload = serde_json::json!({"nested": {"list": [1, 2, 3]}, "text": "héllo"});
    let mut message = envelope(PEER, LOCAL, "device.ping");
    message.payload = Some(serde_json::value::to_raw_value(&payload).expect("raw"));

    sender.send(&message).expect("sends");
    let got = receiver.receive().expect("receives");

    let got_payload = got.payload.expect("a payload");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(got_payload.get()).expect("parses"),
        payload
    );
}

// ── The checks a socket cannot make ───────────────────────────────────────────────────────────

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

// ── Heartbeats ────────────────────────────────────────────────────────────────────────────────

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
    // (`frame.rs`: an unknown kind poisons, and a poisoned decoder refuses further use). What was missing is the
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

// ── What the link knows ───────────────────────────────────────────────────────────────────────

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

// ── Errors ────────────────────────────────────────────────────────────────────────────────────

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
