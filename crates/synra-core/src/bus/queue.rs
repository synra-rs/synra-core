//! One subscriber's queue, and what it has to say about itself.

use std::collections::VecDeque;

/// One subscriber's queue and what it has to say about itself.
pub(super) struct Subscriber<E> {
    pub(super) queue: VecDeque<E>,
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
