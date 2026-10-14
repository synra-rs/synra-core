//! One recorded event, which side produced it, and why an expectation failed.


use synra_protocol::frame::Frame;
use crate::transport::TransportError;

/// How many frames each direction's record keeps.
///
/// A hundred: enough for a handshake, a session and a small transfer, and bounded so a long test does not grow.
pub const RECORD_CAPACITY: usize = 100;

/// Why an expectation was not met.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExpectationError {
    /// No such frame arrived.
    #[error("{expected} did not arrive from {from}")]
    NeverArrived {
        /// Which direction it was expected from.
        from: &'static str,
        /// What was expected.
        expected: String,
    },

    /// A frame of that kind arrived, but not with the expected event.
    #[error("a {kind} frame from {from} carried {found:?}, not {expected:?}")]
    WrongEvent {
        /// Which direction.
        from: &'static str,
        /// The frame's kind.
        kind: &'static str,
        /// What arrived.
        found: String,
        /// What was expected.
        expected: String,
    },

    /// The link refused the send.
    #[error("the link refused a frame: {0}")]
    Refused(TransportError),

    /// The clock refused to move.
    #[error("the clock refused to move: {0}")]
    Clock(#[from] crate::clock::ClockError),
}

/// One side of a pair, as a test sees it.
///
/// Named rather than `a`/`b` at the call site because a test about "the initiator" and "the responder" reads wrong
/// when the two are interchangeable variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The end a test acts as.
    Near,
    /// The end it talks to.
    Far,
}

impl Side {
    /// The other side.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Near => Self::Far,
            Self::Far => Self::Near,
        }
    }

    /// A name for an assertion message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Near => "near",
            Self::Far => "far",
        }
    }
}

/// A record of what crossed the link, in one direction.
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) frames: parking_lot::Mutex<std::collections::VecDeque<Frame>>,
}

impl Record {
    pub(crate) const fn new() -> Self {
        Self { frames: parking_lot::Mutex::new(std::collections::VecDeque::new()) }
    }

    pub(crate) fn push(&self, frame: Frame) {
        let mut frames = self.frames.lock();
        if frames.len() >= RECORD_CAPACITY {
            frames.pop_front();
        }
        frames.push_back(frame);
    }

    pub(crate) fn find(&self, predicate: impl Fn(&Frame) -> bool) -> Option<Frame> {
        self.frames.lock().iter().find(|frame| predicate(frame)).cloned()
    }

    pub(crate) fn len(&self) -> usize {
        self.frames.lock().len()
    }

    pub(crate) fn clear(&self) {
        self.frames.lock().clear();
    }
}
