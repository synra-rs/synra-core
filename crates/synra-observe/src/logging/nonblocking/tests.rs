use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};

use super::*;

/// A sink that counts what the worker wrote.
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Vec<u8>>>);

impl Write for Memory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("a lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A sink that refuses every write, as a full disk does.
struct Refusing;

impl Write for Refusing {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("no space left on device"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("no space left on device"))
    }
}

#[test]
fn a_refused_write_is_counted_rather_than_swallowed() {
    // ★ The background thread has no caller to return an error to; the count is the only report. A full disk therefore
    // shows up in the next `synra logs` instead of a file that silently stops growing.
    let stats = Arc::new(LogStats::default());
    let (mut queue, worker) = Worker::spawn(Refusing, 4, Arc::clone(&stats)).expect("a worker");
    queue.write_all(b"lost\n").expect("queued");
    drop(worker);

    assert_eq!(stats.write_errors(), 2, "the failed write and the failed flush");
    assert!(
        stats.last_write_error().is_some_and(|detail| detail.contains("no space")),
        "the failure's own sentence was not kept: {:?}",
        stats.last_write_error()
    );
}

#[test]
fn a_flush_waits_until_the_queued_lines_are_on_the_sink() {
    // ★ The property an on-demand reader needs: after `flush`, everything logged before it is on disk, **without**
    // shutting the writer down. Dropping the worker would satisfy the first half and end the log, which is not what a
    // diagnostic bundle or a test wants.
    let sink = Memory::default();
    let stats = Arc::new(LogStats::default());
    let (mut queue, worker) = Worker::spawn(sink.clone(), 8, Arc::clone(&stats)).expect("a worker");

    queue.write_all(b"queued\n").expect("queued");
    worker.flush();
    assert_eq!(sink.0.lock().expect("a lock").as_slice(), b"queued\n");

    queue.write_all(b"more\n").expect("queued");
    worker.flush();
    assert_eq!(sink.0.lock().expect("a lock").as_slice(), b"queued\nmore\n");
    drop(worker);
}

#[test]
fn queued_lines_reach_the_sink_before_the_worker_stops() {
    let sink = Memory::default();
    let stats = Arc::new(LogStats::default());
    let (mut queue, worker) = Worker::spawn(sink.clone(), 8, Arc::clone(&stats)).expect("a worker");

    queue.write_all(b"one\n").expect("queued");
    queue.write_all(b"two\n").expect("queued");
    drop(worker);

    assert_eq!(sink.0.lock().expect("a lock").as_slice(), b"one\ntwo\n");
    assert_eq!(stats.dropped(), 0, "a healthy queue drops nothing");
}

/// A sink that blocks inside its first write until the test releases it, and never again.
struct Blocking {
    started: Sender<()>,
    release: Mutex<Receiver<()>>,
    released: std::sync::atomic::AtomicBool,
}

impl Write for Blocking {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.released.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.started.send(());
            let _ = self.release.lock().expect("a lock").recv();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_full_queue_drops_and_counts_rather_than_blocking_the_caller() {
    // ★ The property: a stuck disk must not stall the thread that logged. The worker is held inside its first write,
    // the queue fills, and the extra lines come back immediately — counted, not lost silently.
    let (started, started_rx) = channel();
    let (release, release_rx) = channel();
    let stats = Arc::new(LogStats::default());
    let sink = Blocking {
        started,
        release: Mutex::new(release_rx),
        released: std::sync::atomic::AtomicBool::new(false),
    };
    let (mut queue, worker) = Worker::spawn(sink, 2, Arc::clone(&stats)).expect("a worker");

    queue.write_all(b"first\n").expect("queued");
    started_rx.recv().expect("the worker started its first write");
    // The worker holds the first line; two more fit in the queue; the rest are dropped.
    for _ in 0..10 {
        queue.write_all(b"more\n").expect("the caller does not block");
    }
    assert_eq!(stats.dropped(), 8, "ten lines, two slots and one in flight");

    release.send(()).expect("release the worker");
    drop(worker);
    assert!(stats.lines() > 0 || stats.dropped() > 0, "the count is populated");
}
