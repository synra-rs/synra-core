use super::*;
use std::io::{Read, Write};
use std::sync::mpsc;

#[test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "Readiness must be announced with the predicate locked to prove wait registration."
)]
fn notification_without_data_does_not_end_a_pending_read() {
    let (mut reader, mut writer) = MemoryStream::pair();
    let pipe = Arc::clone(&reader.incoming);
    let (ready, started) = mpsc::channel();
    let (completed, result) = mpsc::channel();
    std::thread::scope(|scope| {
        let shared = Arc::clone(&pipe);
        let worker = scope.spawn(move || {
            let state = shared.state.lock().unwrap();
            ready.send(()).unwrap();
            let state = shared.wait_for_data(state, Some(Duration::from_secs(5)));
            let readable = !state.bytes.is_empty();
            drop(state);
            completed.send(readable).unwrap();
            if readable {
                let mut byte = [0];
                reader.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [7]);
            }
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        // Acquiring the predicate mutex proves the reader registered its condition-variable wait.
        let state = pipe.state.lock().unwrap();
        pipe.ready.notify_all();
        drop(state);
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        writer.write_all(&[7]).unwrap();
        assert!(result.recv_timeout(Duration::from_secs(5)).unwrap());
        worker.join().unwrap();
    });
}

#[test]
fn closing_the_reader_wakes_a_writer_blocked_on_a_full_pipe() {
    let (mut writer, reader) = MemoryStream::pair_with_capacity(1);
    writer.write_all(&[1]).unwrap();
    writer.set_write_deadline(Duration::from_secs(5)).unwrap();
    let (started, ready) = mpsc::channel();
    let (completed, result) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            started.send(()).unwrap();
            completed
                .send(writer.write(&[2]).unwrap_err().kind())
                .unwrap();
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(reader);
        assert_eq!(
            result.recv_timeout(Duration::from_secs(1)).unwrap(),
            std::io::ErrorKind::BrokenPipe
        );
    });
}

#[test]
fn closing_the_writer_preserves_buffered_bytes_then_returns_eof() {
    let (mut writer, mut reader) = MemoryStream::pair_with_capacity(1);
    writer.write_all(&[9]).unwrap();
    drop(writer);
    let mut byte = [0];
    reader.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [9]);
    assert_eq!(reader.read(&mut byte).unwrap(), 0);
}

#[test]
fn zero_length_io_does_not_wait_even_when_the_pipe_is_empty_or_full() {
    let (mut writer, mut reader) = MemoryStream::pair_with_capacity(1);
    reader.set_read_deadline(Duration::ZERO).unwrap();
    writer.set_write_deadline(Duration::ZERO).unwrap();
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    writer.write_all(&[1]).unwrap();
    assert_eq!(writer.write(&[]).unwrap(), 0);
}
