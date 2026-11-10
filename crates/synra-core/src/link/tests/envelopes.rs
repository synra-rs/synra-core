use super::{LOCAL, PEER, device, connected, link, envelope};
use super::super::*;

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
