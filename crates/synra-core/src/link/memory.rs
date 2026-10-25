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
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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
#[derive(Debug)]
struct Pipe {
    /// How many bytes this direction holds before a write waits.
    ///
    /// ★ Why this is a field rather than the constant it started as.
    ///
    /// Because the interesting case is a **full** pipe, and a real socket's buffer is whatever the operating system decided —
    /// so the socket-based test of "a peer that stops reading" had to write enough bytes to fill an unknown amount, which is
    /// slow and depends on a machine's configuration. A fixture that can be made 4 KiB wide tests the same behaviour in
    /// microseconds and tests it the same way every time.
    capacity: usize,
    /// The bytes in flight, and the lock that makes them a queue.
    state: Mutex<PipeState>,
    /// Signalled whenever bytes or closure change; the predicate is protected by the same mutex.
    ready: Condvar,
}

#[derive(Debug)]
struct PipeState {
    bytes: VecDeque<u8>,
    closed: bool,
}

impl Pipe {
    fn push(&self, bytes: &[u8], deadline: Option<Duration>) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let full = |state: &mut PipeState| state.bytes.len() >= self.capacity && !state.closed;
        let mut state = match deadline {
            Some(timeout) => {
                self.ready
                    .wait_timeout_while(state, timeout, full)
                    .unwrap_or_else(|error| error.into_inner())
                    .0
            }
            None => self
                .ready
                .wait_while(state, full)
                .unwrap_or_else(|error| error.into_inner()),
        };
        if state.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the peer closed",
            ));
        }
        if state.bytes.len() >= self.capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "the peer is not reading",
            ));
        }
        let taken = (self.capacity - state.bytes.len()).min(bytes.len());
        state.bytes.extend(bytes.iter().take(taken));
        drop(state);
        self.ready.notify_all();
        Ok(taken)
    }

    fn wait_for_data<'a>(
        &self,
        state: MutexGuard<'a, PipeState>,
        deadline: Option<Duration>,
    ) -> MutexGuard<'a, PipeState> {
        let empty = |state: &mut PipeState| state.bytes.is_empty() && !state.closed;
        // A notification is only a reason to recheck; timeout_while retains the original budget.
        match deadline {
            Some(timeout) => {
                self.ready
                    .wait_timeout_while(state, timeout, empty)
                    .unwrap_or_else(|error| error.into_inner())
                    .0
            }
            None => self
                .ready
                .wait_while(state, empty)
                .unwrap_or_else(|error| error.into_inner()),
        }
    }

    fn pop(&self, buffer: &mut [u8], deadline: Option<Duration>) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.bytes.is_empty() && !state.closed {
            state = self.wait_for_data(state, deadline);
        }
        if state.bytes.is_empty() {
            return if state.closed {
                Ok(0)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "nothing arrived within the deadline",
                ))
            };
        }
        let taken = buffer.len().min(state.bytes.len());
        for slot in buffer.iter_mut().take(taken) {
            *slot = state.bytes.pop_front().unwrap_or(0);
        }
        drop(state);
        self.ready.notify_all();
        Ok(taken)
    }

    fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed = true;
        self.ready.notify_all();
    }
}

impl MemoryStream {
    /// Two ends of one connection.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        Self::pair_with_capacity(MEMORY_CAPACITY)
    }

    /// Two ends of one connection, holding this many bytes per direction.
    ///
    /// A small capacity makes a write block after very little data, which is how a test reaches the "peer is not reading"
    /// case deterministically rather than by filling a socket buffer the operating system sized.
    #[must_use]
    pub fn pair_with_capacity(capacity: usize) -> (Self, Self) {
        let capacity = capacity.max(1);
        let pipe = |capacity| {
            Arc::new(Pipe {
                capacity,
                state: Mutex::new(PipeState {
                    bytes: VecDeque::new(),
                    closed: false,
                }),
                ready: Condvar::new(),
            })
        };
        let first = pipe(capacity);
        let second = pipe(capacity);
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
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .bytes
            .len()
    }
}

impl Drop for MemoryStream {
    fn drop(&mut self) {
        // Wake the peer's reader at EOF and its writer if the peer had filled our receive buffer.
        self.outgoing.close();
        self.incoming.close();
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

#[cfg(test)]
mod tests;
