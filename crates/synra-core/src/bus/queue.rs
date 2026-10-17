//! One subscriber's queue, and what it has to say about itself.

use std::collections::VecDeque;

/// One subscriber's queue and what it has to say about itself.
///
/// The queue holds `(sequence, event)` pairs rather than events alone: the number is assigned by the bus at `emit`, and
/// a subscriber that received the event without it could not tell a gap from a shorter batch. That is the whole reason
/// the bus numbers anything.
pub(super) struct Subscriber<E> {
    pub(super) queue: VecDeque<(u64, E)>,
    pub(super) delivered: u64,
    pub(super) dropped: u64,
    pub(super) overflowed: bool,
}

impl<E> Subscriber<E> {
    pub(super) const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            delivered: 0,
            dropped: 0,
            overflowed: false,
        }
    }
}
