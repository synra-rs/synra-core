//! Writing the log without making the caller wait for the disk.
//!
//! # Why
//!
//! Because logging is diagnostics, and diagnostics must not become the latency. `tracing` calls the writer on whatever
//! thread produced the event — a transport thread, a command answering a user, a plugin host mid-call — and a synchronous
//! write makes each of them wait for the filesystem. On a healthy disk that is microseconds; on a full disk, a slow
//! network share or an antivirus scanning every write, it is not, and a product that stalls because it is writing about
//! itself is one whose owner turns the log off.
//!
//! # Why a bounded queue, and what happens at the bound
//!
//! Because an unbounded queue is a different way to fail: a busy plugin could enqueue for ever while the disk is stuck,
//! and the process would grow until it cannot. The bound is the honest place to choose between blocking and dropping, and
//! dropping wins: the line is a diagnostic, the work it describes already happened. Every dropped line is counted in
//! [`LogStats::dropped`](super::stats::LogStats), so the choice is visible in the status report rather than silent.
//!
//! # Why the queue sits **after** redaction
//!
//! Because [`RedactingWriter`](super::writer::RedactingWriter) is the destination of the queueing writer, not the other
//! way round. Bytes are redacted while the event is still on the caller's thread, and only redacted bytes are handed to
//! the worker — a secret never sits in the queue, and a bug in the queue cannot bypass the policy.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use super::stats::LogStats;

/// How many lines may wait for the disk before further lines are dropped.
///
/// Four thousand lines is a few seconds of a verbose kernel at full tilt, and under a megabyte in memory: large enough
/// that a healthy disk never reaches it, small enough that a stuck disk costs no more.
pub const DEFAULT_QUEUE_CAPACITY: usize = 4096;

/// What the queue carries.
enum Message {
    /// Already-redacted bytes for the file.
    Line(Vec<u8>),
    /// Flush the destination and tell the caller it happened.
    ///
    /// # Why a message and not just `flush` on the writer
    ///
    /// Because the writer's `flush` can only flush the **queue**, not the file the worker owns. A reader that wants to see
    /// what has been logged — an integration test, a diagnostic bundle assembled on demand — needs the bytes on disk, and
    /// without an answer it would be reading a file that is correct but not yet complete. That is the race this variant
    /// exists to remove rather than paper over with a sleep.
    Flush(std::sync::mpsc::Sender<()>),
    /// The writer is going away; flush and stop.
    Stop,
}

/// The writer `tracing` hands each event's bytes to.
pub(crate) struct QueueWriter {
    sender: SyncSender<Message>,
    stats: Arc<LogStats>,
}

impl Write for QueueWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // ★ `Ok(buf.len())` even when the line is dropped: an error here would make `tracing` report a logging failure to
        // a logger that is already failing, and a partial line is worse than none. The drop is counted instead.
        match self.sender.try_send(Message::Line(buf.to_vec())) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => self.stats.record_drop(),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Nothing is buffered here: `write` queued the bytes. The worker's own flush is what reaches the disk, and it
        // runs on `Stop`.
        Ok(())
    }
}

/// A cloneable way to ask the worker to catch up, held by a host that does not own the guard.
///
/// # Why a separate handle
///
/// Because the daemon answers `synra logs` on a thread that does not own the `LogGuard`: the guard lives for the life of
/// the process, while the command is served by the runtime. Passing the guard around would tie two lifetimes together
/// that have nothing to do with each other; the handle is only the queue's sender, and cloning it is what makes "flush
/// before you read" available where the read happens.
#[derive(Clone)]
pub(crate) struct FlushHandle {
    sender: SyncSender<Message>,
}

impl FlushHandle {
    /// Waits until every line queued before this call has reached the destination.
    pub(crate) fn flush(&self) {
        let (ack, wait) = std::sync::mpsc::channel();
        // `send` rather than `try_send`: a full queue is exactly the case where the caller wants to wait for it to drain.
        if self.sender.send(Message::Flush(ack)).is_ok() {
            let _ = wait.recv();
        }
    }
}

/// The thread that drains the queue, and the handle that stops it.
///
/// Dropping the worker is the stop: it sends `Stop` after every line already queued and waits for the thread. That is
/// what makes a `LogGuard`'s drop a promise that the last line reached the disk.
pub(crate) struct Worker {
    sender: SyncSender<Message>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    /// A cloneable handle that can wait for the queue without owning the worker.
    pub(crate) fn flusher(&self) -> FlushHandle {
        FlushHandle { sender: self.sender.clone() }
    }

    /// Starts a thread that writes queued lines to `sink`.
    ///
    /// # Errors
    ///
    /// The operating system's refusal to start a thread, which at start-up is a logging failure the caller reports.
    pub(crate) fn spawn(
        sink: impl Write + Send + 'static,
        capacity: usize,
        stats: Arc<LogStats>,
    ) -> io::Result<(QueueWriter, Self)> {
        let (sender, receiver) = sync_channel(capacity.max(1));
        let control = sender.clone();
        let worker_stats = Arc::clone(&stats);
        let handle = std::thread::Builder::new()
            .name("synra-log".to_owned())
            .spawn(move || run(receiver, sink, &worker_stats))?;
        Ok((
            QueueWriter { sender, stats },
            Self { sender: control, handle: Some(handle) },
        ))
    }
}

impl Worker {
    /// Waits until every line queued before this call has reached the destination.
    pub(crate) fn flush(&self) {
        let (ack, wait) = std::sync::mpsc::channel();
        // `send` rather than `try_send`: a full queue is exactly the case where the caller wants to wait for it to drain.
        if self.sender.send(Message::Flush(ack)).is_ok() {
            let _ = wait.recv();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // `send` rather than `try_send`: a full queue means lines are waiting, and the Stop must come after them.
        let _ = self.sender.send(Message::Stop);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Drains the queue until it is stopped, then flushes.
fn run(receiver: Receiver<Message>, mut sink: impl Write, stats: &LogStats) {
    for message in receiver {
        match message {
            Message::Line(bytes) => {
                // A failed write has no caller to go to: this *is* the reporting path. The line is lost, and the counter
                // is what keeps that from being invisible — the next `synra logs` reports it.
                if sink.write_all(&bytes).is_err() {
                    stats.record_write_error();
                }
            }
            Message::Flush(ack) => {
                if sink.flush().is_err() {
                    stats.record_write_error();
                }
                // Whether the flush worked or not, the caller waiting on this must be released: a hanging reader is a
                // worse failure than a stale file.
                let _ = ack.send(());
            }
            Message::Stop => break,
        }
    }
    // Every line before the Stop has been written by now; the flush is what makes it visible to a reader.
    if sink.flush().is_err() {
        stats.record_write_error();
    }
}

#[cfg(test)]
mod tests {
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
}