use std::io::{self, Write};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::fmt::MakeWriter;

use super::nonblocking::QueueWriter;
use super::writer::RedactingWriter;

/// A cloneable writer handle handed to `tracing` once per event.
#[derive(Clone)]
pub(super) struct SharedWriter(pub(super) Arc<Mutex<RedactingWriter<QueueWriter>>>);

/// One event's writer, holding the shared handle for the duration of the write.
pub(super) struct SharedGuard(pub(super) Arc<Mutex<RedactingWriter<QueueWriter>>>);

impl Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().flush()
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard(Arc::clone(&self.0))
    }
}
