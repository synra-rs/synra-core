//! A byte stream backed by memory, so a link can exist without a socket.
//!
//! # Why this is a library type rather than a test fixture
//!
//! Because `04 §11` records what its absence cost: the design's end-to-end tests want two kernels linked **in one process**,
//! `synra-testkit` has a `MemoryTransport`, and that transport moves **decoded frames** while a link decodes **bytes** — so the
//! two were type-incompatible and the tests could not be written. The missing piece was never a fixture; it was a place for
//! the fixture to attach. That place is [`LinkStream`](super::LinkStream), and this is the byte-level implementation of it. It
//! lives in the library rather than in a test module because whoever writes those tests needs it to be nameable, and a fixture
//! that only exists inside `#[cfg(test)]` is one nobody outside can use.
//!
//! # Why it behaves like a socket rather than like a `Vec`
//!
//! Because a stream that never blocks cannot test the things a socket does. Three properties are deliberate, and each is one
//! a real socket has:
//!
//! 1. **A bounded buffer.** Writing to a full pipe **waits** and then fails, exactly as a socket whose peer has stopped
//!    reading. An unbounded queue would make a stalled peer look like a peer that is keeping up, and would grow without limit
//!    in a test that never reads.
//! 2. **Deadlines that expire as `WouldBlock`.** A read with nothing to read returns `WouldBlock` once its deadline passes
//!    rather than blocking forever, which is what makes
//!    [`LinkStream::set_read_deadline`](super::LinkStream::set_read_deadline) testable at all — and the link's `is_a_timeout`
//!    recognises it as a **quiet** peer rather than a broken one, which is the distinction the two of them exist to keep.
//! 3. **A close that unblocks the other end.** Dropping one half wakes a reader on the other, which becomes end-of-file — the
//!    same fact as a peer closing its socket.

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{LinkError, LinkStream};

/// How many bytes one direction holds before a write waits.
///
/// Small on purpose: it is this fixture's backpressure, and a value large enough never to fill would make the "peer stops
/// reading" case untestable — which is the case the bound exists for.
pub const MEMORY_CAPACITY: usize = 64 * 1024;

/// One end of a pair of byte pipes.
///
/// `!Sync` because the two deadlines are [`Cell`]s: the link sets them through `&self` before a read or a write, and the two
/// ends of a pair are owned by one link each. A `Mutex` would say the same thing with more machinery.
#[derive(Debug)]
pub struct MemoryStream {
    /// What this end writes, and the other reads.
    outgoing: Arc<Pipe>,
    /// What the other writes, and this reads.
    incoming: Arc<Pipe>,
    /// The deadline one read call runs under.
    read_deadline: Cell<Option<Duration>>,
    /// The deadline one write call runs under.
    write_deadline: Cell<Option<Duration>>,
}

/// One direction, shared by the two ends.
#[derive(Debug, Default)]
struct Pipe {
    /// The bytes in flight, and the lock that makes them a queue.
    bytes: Mutex<VecDeque<u8>>,
    /// Signalled whenever the queue changes, in either direction.
    ready: Condvar,
    /// Set when the writing end is dropped, so the reading end sees end-of-file rather than waiting forever.
    closed: Mutex<bool>,
}

impl Pipe {
    fn push(&self, bytes: &[u8], deadline: Option<Duration>) -> std::io::Result<usize> {
        let mut queue = self.bytes.lock().unwrap_or_else(|error| error.into_inner());
        if queue.len() >= MEMORY_CAPACITY {
            // Full: wait for the reader, under the write deadline. This is where a stalled peer becomes observable rather
            // than a hang.
            queue = match deadline {
                Some(timeout) => self
                    .ready
                    .wait_timeout_while(queue, timeout, |queue| queue.len() >= MEMORY_CAPACITY)
                    .unwrap_or_else(|error| error.into_inner())
                    .0,
                None => self
                    .ready
                    .wait_while(queue, |queue| queue.len() >= MEMORY_CAPACITY)
                    .unwrap_or_else(|error| error.into_inner()),
            };
            if queue.len() >= MEMORY_CAPACITY {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "the peer is not reading",
                ));
            }
        }
        let room = MEMORY_CAPACITY - queue.len();
        let taken = room.min(bytes.len());
        queue.extend(bytes.iter().take(taken));
        drop(queue);
        self.ready.notify_all();
        Ok(taken)
    }

    fn pop(&self, buffer: &mut [u8], deadline: Option<Duration>) -> std::io::Result<usize> {
        let mut queue = self.bytes.lock().unwrap_or_else(|error| error.into_inner());
        while queue.is_empty() {
            if *self.closed.lock().unwrap_or_else(|error| error.into_inner()) {
                // End-of-file, which is what a peer that closed its socket produces.
                return Ok(0);
            }
            queue = match deadline {
                Some(timeout) => self
                    .ready
                    .wait_timeout(queue, timeout)
                    .unwrap_or_else(|error| error.into_inner())
                    .0,
                None => self
                    .ready
                    .wait(queue)
                    .unwrap_or_else(|error| error.into_inner()),
            };
            // Still nothing after waiting: a **quiet** peer, which is not a broken one.
            if queue.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "nothing arrived within the deadline",
                ));
            }
        }
        let taken = buffer.len().min(queue.len());
        for slot in buffer.iter_mut().take(taken) {
            *slot = queue.pop_front().unwrap_or(0);
        }
        drop(queue);
        self.ready.notify_all();
        Ok(taken)
    }

    fn close(&self) {
        *self.closed.lock().unwrap_or_else(|error| error.into_inner()) = true;
        self.ready.notify_all();
    }
}

impl MemoryStream {
    /// Two ends of one connection.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let first = Arc::new(Pipe::default());
        let second = Arc::new(Pipe::default());
        (
            Self {
                outgoing: Arc::clone(&first),
                incoming: Arc::clone(&second),
                read_deadline: Cell::new(None),
                write_deadline: Cell::new(None),
            },
            Self {
                outgoing: Arc::clone(&second),
                incoming: Arc::clone(&first),
                read_deadline: Cell::new(None),
                write_deadline: Cell::new(None),
            },
        )
    }

    /// How many bytes are waiting to be read.
    ///
    /// For a test that needs to say "nothing has been written yet" without racing a read.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.incoming
            .bytes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}

impl Drop for MemoryStream {
    fn drop(&mut self) {
        // The other end's read becomes end-of-file, which is what a closed socket does and what lets a reader stop waiting.
        self.outgoing.close();
    }
}

impl std::io::Read for MemoryStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.incoming.pop(buffer, self.read_deadline.get())
    }
}

impl std::io::Write for MemoryStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.outgoing.push(bytes, self.write_deadline.get())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LinkStream for MemoryStream {
    fn set_read_deadline(&self, timeout: Duration) -> Result<(), LinkError> {
        // Never refuses, unlike `TcpStream` on Windows where a zero timeout is rejected. A caller cannot tell the two apart
        // from the outside, which is the point of the seam: the link asks for a deadline and gets one or an error.
        self.read_deadline.set(Some(timeout));
        Ok(())
    }

    fn set_write_deadline(&self, timeout: Duration) -> Result<(), LinkError> {
        self.write_deadline.set(Some(timeout));
        Ok(())
    }
}
