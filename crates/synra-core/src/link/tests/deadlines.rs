use super::super::memory::MemoryStream;
use super::{LOCAL, PEER, connected, link_with_timeout, link_with_stream, envelope};
use super::super::*;

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
