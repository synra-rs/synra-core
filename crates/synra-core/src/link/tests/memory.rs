use super::super::memory::MemoryStream;
use super::{LOCAL, PEER, device, link_with_stream, envelope};
use super::super::*;

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
