//! The bus itself, and the one lock it publishes under.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use super::queue::Subscriber;
use super::subscription::{Delivery, SUBSCRIBER_QUEUE_CAPACITY, SubscriberId, SubscriberReport};
/// The kernel's event bus.
///
/// # Why one bus and not one per subscriber
///
/// The sequence number is a property of the *stream*, so a bus per subscriber would give each its own numbering — and
/// two interfaces comparing what they saw would disagree about which event came first. One bus, one numbering, many
/// readers.
///
/// # Why the sequence starts at one
///
/// Because the client library's tracker does: a subscriber that starts at zero would see the first event as a
/// repeat. The numbering is part of the wire contract, so it is asserted by a test rather than left to `0` being the
/// natural default.
pub struct EventBus<E> {
    inner: Arc<Inner<E>>,
    next_id: AtomicU64,
}

struct Inner<E> {
    next_seq: Mutex<u64>,
    subscribers: Mutex<Vec<(SubscriberId, Subscriber<E>)>>,
}

impl<E> Default for EventBus<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> EventBus<E> {
    /// A bus with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                next_seq: Mutex::new(1),
                subscribers: Mutex::new(Vec::new()),
            }),
            next_id: AtomicU64::new(1),
        }
    }

    /// How many subscribers there are.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscribers.lock().len()
    }

    /// The sequence number the next event will carry.
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        *self.inner.next_seq.lock()
    }

    /// The last sequence number handed out, if any.
    #[must_use]
    pub fn last_sequence(&self) -> Option<u64> {
        self.next_sequence().checked_sub(1).filter(|last| *last > 0)
    }
}

impl<E: Clone> EventBus<E> {
    /// Adds a subscriber and returns its identity.
    ///
    /// # Why the caller must unsubscribe
    ///
    /// The bus holds the queue, so a subscriber that went away without unsubscribing is memory held for the life of the
    /// kernel — and a caller that opened a window per device would leak one per window. [`EventBus::unsubscribe`] is
    /// the counterpart, and the interface's teardown calls it.
    pub fn subscribe(&self) -> SubscriberId {
        let id = SubscriberId(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.inner
            .subscribers
            .lock()
            .push((id, Subscriber::new()));
        id
    }

    /// Removes a subscriber.
    ///
    /// Returns whether it was there, so a caller that unsubscribed twice can tell a second call from a subscriber it
    /// never had — the two are different mistakes and a `bool` is what distinguishes them.
    pub fn unsubscribe(&self, id: SubscriberId) -> bool {
        let mut subscribers = self.inner.subscribers.lock();
        let before = subscribers.len();
        subscribers.retain(|(existing, _)| *existing != id);
        subscribers.len() != before
    }

    /// Emits an event to every subscriber.
    ///
    /// # The two locks are taken one at a time
    ///
    /// The sequence and the queues are separate, and the sequence is taken and released before the queues are touched.
    /// Holding both at once would make emitting an event wait on a subscriber's queue, and while the queue operations
    /// are bounded, a lock ordering that two paths disagree about is a deadlock waiting for a third path to be added.
    ///
    /// # What happens to a full queue
    ///
    /// The oldest event is dropped and the count goes up. The subscriber is not blocked, retried or disconnected: an
    /// interface that is behind should be told it is behind, and a bus that refused to emit would be one where a
    /// resizing window pauses device discovery.
    ///
    /// Returns the sequence number the event was given.
    pub fn emit(&self, event: E) -> u64 {
        let seq = self.allocate_sequence();
        self.fan_out(&event);
        seq
    }

    /// Takes the next sequence number.
    ///
    /// Its own method, so the guard's lifetime is the whole of a three-statement function. That is what
    /// `significant_drop_in_scrutinee` is about: a guard in a larger function is one whose critical section a reader has
    /// to work out, and here there is nothing to work out.
    fn allocate_sequence(&self) -> u64 {
        let mut next = self.inner.next_seq.lock();
        let seq = *next;
        *next = next.saturating_add(1);
        seq
    }

    /// Pushes an event onto every subscriber's queue, dropping the oldest where one is full.
    ///
    /// Its own method for the same reason as [`Self::allocate_sequence`], and separately so that the two locks are
    /// visibly not held at once: `allocate_sequence` has returned before this is called, and a deadlock needs two
    /// guards.
    fn fan_out(&self, event: &E) {
        let mut subscribers = self.inner.subscribers.lock();
        for (_, subscriber) in subscribers.iter_mut() {
            if subscriber.queue.len() >= SUBSCRIBER_QUEUE_CAPACITY {
                // The oldest, because the newest describes the world as it is now.
                subscriber.queue.pop_front();
                subscriber.dropped = subscriber.dropped.saturating_add(1);
                subscriber.overflowed = true;
            }
            subscriber.queue.push_back(event.clone());
            subscriber.delivered = subscriber.delivered.saturating_add(1);
        }
    }

    /// Takes everything waiting for a subscriber.
    ///
    /// Returns `None` when there is **nothing to hand over**: no events waiting and no loss to report. That is a poll
    /// rather than a wait, and `None` is what makes a drain terminate — a `while let Some(delivery) = take(id)` around a
    /// call that answered `Some` with an empty batch is an unbounded loop, so a caller that wrote one would have a
    /// *hang* rather than a failing test.
    ///
    /// [`Delivery::Behind`] is returned even when no events survived, because the **loss** is the thing being handed
    /// over: a subscriber told nothing after an overflow would go on drawing a picture with a hole in it.
    pub fn take(&self, id: SubscriberId) -> Option<Delivery<E>> {
        // ★ The lock is released before the `Delivery` is built. Clippy's `significant_drop_in_scrutinee` is about
        // resource contention rather than about correctness, and it is right here: a guard held while a `Vec` is moved
        // into an enum keeps every other emitter waiting for a construction that does not touch the guarded data.
        let (events, overflowed, missed) = self.drain(id)?;
        if overflowed {
            return Some(Delivery::Behind { events, missed });
        }
        if events.is_empty() {
            return None;
        }
        Some(Delivery::Events(events))
    }

    /// Empties a subscriber's queue and reports its overflow state, with the lock held for nothing else.
    ///
    /// Returns `(events, overflowed, dropped)`. The flag is cleared here because the caller is about to tell the
    /// subscriber: telling it again on the next read would report the same loss twice, and a caller that reacted to each
    /// report would re-read a snapshot per read. The *count* is not cleared, because a diagnostic wants the total rather
    /// than the per-read figure.
    fn drain(&self, id: SubscriberId) -> Option<(Vec<E>, bool, u64)> {
        let mut subscribers = self.inner.subscribers.lock();
        // ★ `match` rather than `?`, and the reason is a lint rather than taste: `significant_drop_in_scrutinee` reads
        // an early `return` as "the guard can be dropped here", which is true of this one and is the point — the guard
        // is released on the way out, and a caller that passed an identity the bus never issued is not a case worth
        // holding a lock for. What matters is that the *contains* path releases it too, which a block scope does.
        let Some((_, subscriber)) = subscribers.iter_mut().find(|(existing, _)| *existing == id) else {
            drop(subscribers);
            return None;
        };
        let events: Vec<E> = subscriber.queue.drain(..).collect();
        let missed = subscriber.dropped;
        let overflowed = subscriber.overflowed;
        subscriber.overflowed = false;
        drop(subscribers);
        Some((events, overflowed, missed))
    }

    /// Peeks at what is waiting without taking it.
    ///
    /// For a caller that has to decide whether to read before reading — a worker that wants to batch, say. The
    /// overflow flag is not cleared, because nothing was delivered.
    #[must_use]
    pub fn peek(&self, id: SubscriberId) -> Option<Delivery<E>> {
        // Read under the lock, decide, and release before building the delivery — the same reasoning as `take`.
        let (events, overflowed, missed) = {
            let subscribers = self.inner.subscribers.lock();
            match subscribers.iter().find(|(existing, _)| *existing == id) {
                Some((_, subscriber)) => (
                    subscriber.queue.iter().cloned().collect::<Vec<E>>(),
                    subscriber.overflowed,
                    subscriber.dropped,
                ),
                None => return None,
            }
        };
        if overflowed {
            return Some(Delivery::Behind { events, missed });
        }
        Some(Delivery::Events(events))
    }

    /// What a subscriber has to say about itself.
    #[must_use]
    pub fn report(&self, id: SubscriberId) -> Option<SubscriberReport> {
        let (dropped, delivered, queued, overflowed) = {
            let subscribers = self.inner.subscribers.lock();
            match subscribers.iter().find(|(existing, _)| *existing == id) {
                Some((_, subscriber)) => (
                    subscriber.dropped,
                    subscriber.delivered,
                    subscriber.queue.len(),
                    subscriber.overflowed,
                ),
                None => return None,
            }
        };
        Some(SubscriberReport { dropped, delivered, queued, overflowed })
    }

    /// What every subscriber has to say, for a diagnostic bundle.
    #[must_use]
    pub fn reports(&self) -> Vec<(SubscriberId, SubscriberReport)> {
        let subscribers = self.inner.subscribers.lock();
        let reports: Vec<(SubscriberId, SubscriberReport)> = subscribers
            .iter()
            .map(|(id, subscriber)| {
                (
                    *id,
                    SubscriberReport {
                        dropped: subscriber.dropped,
                        delivered: subscriber.delivered,
                        queued: subscriber.queue.len(),
                        overflowed: subscriber.overflowed,
                    },
                )
            })
            .collect();
        drop(subscribers);
        reports
    }

    /// Clears a subscriber's counters without touching its queue.
    ///
    /// For a diagnostic tool that has recorded the numbers, or a test that wants a second measurement. The queue is not
    /// touched because clearing the counts and dropping the events would be two decisions in one call, and the caller
    /// that wanted both can read and then reset.
    pub fn reset_counters(&self, id: SubscriberId) -> bool {
        // The whole function is the critical section, and the answer is computed inside it. A guard whose lifetime is a
        // function body with no early exits is the shape `significant_drop_in_scrutinee` asks for.
        let mut subscribers = self.inner.subscribers.lock();
        subscribers.iter_mut().find(|(existing, _)| *existing == id).is_some_and(|(_, subscriber)| {
            subscriber.dropped = 0;
            subscriber.delivered = 0;
            subscriber.overflowed = false;
            true
        })
    }
}
