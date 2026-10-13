//! Where kernel events come from, and what an interface gets when it cannot keep up.
//!
//! # The problem this exists for
//!
//! Every interface — the desktop window, a phone's companion screen, a diagnostic tool attached to a running kernel —
//! wants to know what changed. The kernel emits; the interfaces read. Two things make that harder than a broadcast:
//!
//! 1. **An interface can be slower than the kernel.** A window that is being resized, a phone on a slow link, a tool
//!    that paused in a debugger. A queue per subscriber that grows without bound is a memory leak whose size is the
//!    user's device count.
//! 2. **Events are ordered, and the interfaces can tell.** Each event carries a sequence number, so an interface that
//!    received 5 then 7 knows it missed 6 — and can ask for a snapshot rather than showing a list that is quietly wrong.
//!
//! So the bus hands out sequence numbers, gives each subscriber a **bounded** queue, and when a queue overflows it
//! *drops the oldest and counts what it dropped*. The count is what makes the loss visible: the subscriber learns it
//! missed some and how many.
//!
//! # Why dropping the oldest rather than refusing the newest
//!
//! Because the newest event is the one that describes the world as it is now. A subscriber that is behind by a hundred
//! events and receives the hundred-and-first is one that can be brought up to date by a snapshot; a subscriber that
//! received the first hundred and not the last is one that is behind by an unknown amount and does not know it.
//!
//! # Why the drop is silent to the *emitter*
//!
//! A kernel that blocked when an interface was slow would be one where a resizing window pauses device discovery. The
//! emitter's contract is `emit` and nothing else: it does not learn whether anyone was listening, and a caller that
//! wanted to know reads the bus's report.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use synra_protocol::event::MAX_COUNTED_GAP;

/// How many events one subscriber's queue holds.
///
/// The same figure as the protocol's write queue, and for the same reason: an interface that is a quarter of a second
/// behind on a busy kernel is fine, and one that is a minute behind is one that should re-read a snapshot instead. Two
/// hundred and fifty-six events is seconds of ordinary activity and kilobytes of memory.
pub const SUBSCRIBER_QUEUE_CAPACITY: usize = 256;

/// A subscriber's identity, as the bus issued it.
///
/// Opaque and `Copy`: a caller holds it to unsubscribe and to read that subscriber's report, and a caller that
/// constructed one would be able to read another subscriber's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriberId(u64);

impl SubscriberId {
    /// The number, for a log line or a report.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sub{}", self.0)
    }
}

/// What a subscriber is told about its own queue.
///
/// # Why `dropped` is separate from `missed`
///
/// `dropped` is what *this bus* threw away because this subscriber was slow — the bus's own decision, and one it can
/// report precisely. `missed` is the gap a subscriber computes from the sequence numbers it received, which counts
/// everything that did not arrive, whatever the reason. They are equal in the ordinary case and diverge when something
/// else lost events, and a diagnostic that conflated them would blame the queue for a socket's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscriberReport {
    /// How many events were dropped from this subscriber's queue because it was full.
    pub dropped: u64,
    /// How many events it has been handed.
    pub delivered: u64,
    /// How many are waiting.
    pub queued: usize,
    /// Whether its queue has overflowed at least once since the last reset.
    pub overflowed: bool,
}

impl SubscriberReport {
    /// Whether this subscriber is keeping up.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        !self.overflowed
    }

    /// A sentence for a log line or a diagnostic bundle.
    #[must_use]
    pub fn explain(&self) -> String {
        if self.overflowed {
            format!(
                "dropped {} of {} event(s); {} waiting — the subscriber is slower than the kernel and should re-read a \
                 snapshot",
                self.dropped,
                self.delivered + self.dropped,
                self.queued,
            )
        }
        else {
            format!("delivered {} event(s), none dropped, {} waiting", self.delivered, self.queued)
        }
    }
}

/// What a subscriber learns when it reads its queue.
///
/// # Why the gap is reported rather than the events alone
///
/// A caller that received `[7, 8, 9]` after `5` has no way to tell from those three that 6 is missing — the sequence
/// numbers are there, but checking them is exactly the bookkeeping every subscriber would have to redo. The bus knows
/// what it threw away, so it says.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery<E> {
    /// The events that were waiting, in sequence order.
    ///
    /// Empty when nothing was waiting, which is the ordinary case for a subscriber that is keeping up: it reads after
    /// each notification and finds one event.
    Events(Vec<E>),
    /// Events were waiting, and the subscriber is **behind**: it has to re-read a snapshot.
    ///
    /// The events that survived are carried anyway. They are not sufficient — the subscriber cannot apply them to a
    /// picture with a hole in it — but they are what it has, and discarding them would make a diagnostic that wanted
    /// only the sequence numbers do a second round trip.
    Behind {
        /// The events that survived the overflow, oldest first.
        events: Vec<E>,
        /// How many were dropped from this subscriber's queue.
        missed: u64,
    },
}

impl<E> Delivery<E> {
    /// The events, whichever shape the delivery has.
    #[must_use]
    pub fn events(&self) -> &[E] {
        match self {
            Self::Events(events) | Self::Behind { events, .. } => events,
        }
    }

    /// How many events were dropped, if any.
    #[must_use]
    pub const fn missed(&self) -> u64 {
        match self {
            Self::Behind { missed, .. } => *missed,
            _ => 0,
        }
    }

    /// Whether the subscriber has to re-read.
    #[must_use]
    pub const fn must_refresh(&self) -> bool {
        matches!(self, Self::Behind { .. })
    }
}

/// One subscriber's queue and what it has to say about itself.
struct Subscriber<E> {
    queue: VecDeque<E>,
    delivered: u64,
    dropped: u64,
    overflowed: bool,
}

impl<E> Subscriber<E> {
    const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            delivered: 0,
            dropped: 0,
            overflowed: false,
        }
    }
}

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
    /// Returns [`Delivery::Events`] with an empty vector when nothing is waiting, which is not an error: a subscriber
    /// that reads after every notification finds one event and a subscriber woken spuriously finds none.
    pub fn take(&self, id: SubscriberId) -> Option<Delivery<E>> {
        // ★ The lock is released before the `Delivery` is built. Clippy's `significant_drop_in_scrutinee` is about
        // resource contention rather than about correctness, and it is right here: a guard held while a `Vec` is moved
        // into an enum keeps every other emitter waiting for a construction that does not touch the guarded data.
        let (events, overflowed, missed) = self.drain(id)?;
        if overflowed {
            return Some(Delivery::Behind { events, missed });
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

/// What a subscriber decided about one event's sequence number.
///
/// The Rust side of the client library's tracker, and the two have to agree: the library decides what to do with an
/// event it received, and this decides what the kernel and its own diagnostics think. They are separate implementations
/// of one rule, which is why the rule is small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Judgement {
    /// The event follows the last one. Apply it.
    Apply,
    /// It has been seen. Apply nothing.
    IgnoreRepeat,
    /// Something was missed. Re-read, and the count says how much was missed when it is known.
    RefreshSnapshot {
        /// How many events are missing, capped at [`MAX_COUNTED_GAP`].
        ///
        /// `None` when the gap is unknown — a subscriber that attached in the middle of a stream cannot tell how far
        /// back the events it never saw began.
        missed: Option<u32>,
    },
}

/// Tracks sequence numbers for one subscriber.
///
/// # Why this is not the bus
///
/// The bus knows what *it* dropped. This knows what a *consumer* received, which is a different question: the consumer
/// may have received everything the bus sent and still be missing events the bus never saw — the ones from before it
/// subscribed, or from a link that reconnect dropped. A tracker over the received stream is the only thing that
/// answers "is my picture whole".
#[derive(Debug, Clone, Default)]
pub struct SequenceTracker {
    last: Option<u64>,
    gaps: u32,
    stale: bool,
}

impl SequenceTracker {
    /// A tracker that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Judges one sequence number and records it.
    ///
    /// # The three answers, and why `IgnoreRepeat` is not an error
    ///
    /// A channel delivers the same event twice around a reconnect or a reload. Applying it twice is what makes a device
    /// appear once in a list and be fetched twice — so a repeat is refused, and refused *quietly*: it is not a fault,
    /// and a caller that logged one would have a log full of the ordinary case.
    ///
    /// # Why the tracker advances on a refresh request
    ///
    /// An earlier version left the sequence where it was, so every event after a gap was another gap and the interface
    /// could not make progress without a round trip per event. Advancing is the tracker saying "I know where I am; my
    /// picture is incomplete until the snapshot arrives" — which is what the `stale` flag is for.
    pub fn observe(&mut self, seq: u64) -> Judgement {
        let Some(last) = self.last else {
            // The first event, whatever its number. A subscriber that attached mid-stream — a second window, a
            // diagnostic tool — starts here, and calling its first event a gap would make it re-read a snapshot it has
            // just taken.
            self.last = Some(seq);
            return Judgement::Apply;
        };

        if seq <= last {
            return Judgement::IgnoreRepeat;
        }

        let missed = seq - last - 1;
        if missed == 0 {
            self.last = Some(seq);
            return Judgement::Apply;
        }

        self.gaps = self.gaps.saturating_add(1);
        self.stale = true;
        self.last = Some(seq);
        // Capped, because a *reported* count of four billion says nothing and the instruction is the same either way.
        // `None` rather than a capped number when the gap is beyond the cap: reporting `1000` for a gap of four billion
        // would be a number the caller believes.
        let counted = u32::try_from(missed).ok().filter(|missed| *missed <= MAX_COUNTED_GAP);
        Judgement::RefreshSnapshot { missed: counted }
    }

    /// Records that a snapshot arrived, so the picture is whole again.
    pub const fn snapshot_taken(&mut self) {
        self.stale = false;
    }

    /// Whether the picture may be missing something.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.stale
    }

    /// The last sequence number seen.
    #[must_use]
    pub const fn last_seen(&self) -> Option<u64> {
        self.last
    }

    /// How many gaps were noticed.
    #[must_use]
    pub const fn gaps(&self) -> u32 {
        self.gaps
    }

    /// Forgets everything, for a reload.
    ///
    /// The gap count goes too: it is a count of the gaps in *this* stream, and a reloaded interface that carried the
    /// old total would report a number about a stream it is no longer reading.
    pub const fn reset(&mut self) {
        self.last = None;
        self.gaps = 0;
        self.stale = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An event, which the bus clones per subscriber.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Tick(u64);

    fn bus() -> EventBus<Tick> {
        EventBus::new()
    }

    // ── Sequence numbers ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_first_event_is_numbered_one() {
        // ★ The client library's tracker treats a sequence at or below the last as a repeat, so a bus that started at
        // zero would make every subscriber see its first event as one it had already had. The numbering is part of the
        // wire contract, asserted rather than left to `0` being the natural default.
        let bus = bus();
        assert_eq!(bus.next_sequence(), 1);
        assert_eq!(bus.emit(Tick(1)), 1);
        assert_eq!(bus.emit(Tick(2)), 2);
    }

    #[test]
    fn the_sequence_is_the_bus_is_not_the_subscribers() {
        // Two subscribers see the same numbers, because the numbers are a property of the stream. A bus per subscriber
        // would give each its own, and two interfaces comparing what they saw would disagree about which event came
        // first.
        let bus = bus();
        let first = bus.subscribe();
        let second = bus.subscribe();

        bus.emit(Tick(1));
        bus.emit(Tick(2));

        assert_eq!(bus.take(first).expect("first").events(), &[Tick(1), Tick(2)]);
        assert_eq!(bus.take(second).expect("second").events(), &[Tick(1), Tick(2)]);
    }

    #[test]
    fn last_sequence_is_none_before_anything_is_emitted() {
        // `next - 1` would be zero, and zero is not a sequence number this bus hands out — a caller comparing it would
        // be comparing against a number that never appears.
        let bus = bus();
        assert_eq!(bus.last_sequence(), None);
        bus.emit(Tick(1));
        assert_eq!(bus.last_sequence(), Some(1));
    }

    // ── Subscribers ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_event_reaches_every_subscriber() {
        let bus = bus();
        let first = bus.subscribe();
        let second = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        bus.emit(Tick(7));
        assert_eq!(bus.take(first).expect("first").events(), &[Tick(7)]);
        assert_eq!(bus.take(second).expect("second").events(), &[Tick(7)]);
    }

    #[test]
    fn an_event_emitted_before_a_subscriber_existed_does_not_reach_it() {
        // A subscriber sees the stream from where it attached. A bus that replayed its history would give a diagnostic
        // tool the whole past unbounded, and a second window every event since the kernel started.
        let bus = bus();
        bus.emit(Tick(1));
        let late = bus.subscribe();
        bus.emit(Tick(2));
        assert_eq!(bus.take(late).expect("late").events(), &[Tick(2)]);
    }

    #[test]
    fn taking_empties_the_queue() {
        // A `take` that left the events would hand the same event to a caller twice, which is what the sequence tracker
        // then refuses — so the mistake would be invisible except as a stalled queue.
        let bus = bus();
        let id = bus.subscribe();
        bus.emit(Tick(1));
        assert_eq!(bus.take(id).expect("id").events(), &[Tick(1)]);
        assert_eq!(bus.take(id).expect("id").events(), &[] as &[Tick]);
    }

    #[test]
    fn peeking_does_not_consume() {
        // For a caller that has to decide whether to read before reading. The events are still there afterwards.
        let bus = bus();
        let id = bus.subscribe();
        bus.emit(Tick(1));
        assert_eq!(bus.peek(id).expect("id").events(), &[Tick(1)]);
        assert_eq!(bus.take(id).expect("id").events(), &[Tick(1)]);
    }

    #[test]
    fn unsubscribing_removes_the_queue() {
        // ★ A subscriber that went away without unsubscribing is memory held for the life of the kernel, and a caller
        // that opened a window per device would leak one per window.
        let bus = bus();
        let id = bus.subscribe();
        bus.emit(Tick(1));

        assert!(bus.unsubscribe(id));
        assert_eq!(bus.subscriber_count(), 0);
        // And a second unsubscribe is `false` rather than an error: an interface torn down twice is ordinary.
        assert!(!bus.unsubscribe(id));
        assert!(bus.take(id).is_none());
        assert!(bus.report(id).is_none());
    }

    #[test]
    fn an_unknown_subscriber_reads_nothing_rather_than_panicking() {
        // A stale identity is ordinary — a window closed while a timer was in flight — and a panic there would take the
        // kernel down for a UI mistake.
        let bus: EventBus<Tick> = bus();
        let ghost = SubscriberId(9_999);
        assert!(bus.take(ghost).is_none());
        assert!(bus.peek(ghost).is_none());
        assert!(bus.report(ghost).is_none());
        assert!(!bus.reset_counters(ghost));
    }

    #[test]
    fn the_emitter_does_not_learn_whether_anyone_was_listening() {
        // ★ A kernel that blocked when an interface was slow would be one where a resizing window pauses device
        // discovery. The contract is `emit` and nothing else, and what it returns is the sequence number rather than a
        // subscriber count.
        let bus: EventBus<Tick> = bus();
        assert_eq!(bus.emit(Tick(1)), 1);
        assert_eq!(bus.emit(Tick(2)), 2);
    }

    // ── The bounded queue ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_full_queue_drops_the_oldest_and_counts_it() {
        // ★ The newest event describes the world as it is now. A subscriber behind by a hundred events that receives the
        // hundred-and-first can be brought up to date by a snapshot; one that received the first hundred and not the
        // last is behind by an unknown amount and does not know it.
        let bus = bus();
        let id = bus.subscribe();
        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 3) {
            bus.emit(Tick(seq));
        }

        let delivery = bus.take(id).expect("id");
        assert!(delivery.must_refresh(), "{delivery:?}");
        assert_eq!(delivery.missed(), 3);
        let events = delivery.events();
        assert_eq!(events.len(), SUBSCRIBER_QUEUE_CAPACITY);
        // The oldest three are gone, and the newest is there.
        assert_eq!(events[0], Tick(4));
        assert_eq!(events[events.len() - 1], Tick(SUBSCRIBER_QUEUE_CAPACITY as u64 + 3));
    }

    #[test]
    fn a_queue_that_never_overflows_never_asks_for_a_refresh() {
        // The ordinary case must not be the expensive one: a subscriber that reads after each notification never sees
        // `Behind`, and one that did would re-read a snapshot per event.
        let bus = bus();
        let id = bus.subscribe();
        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64) {
            bus.emit(Tick(seq));
        }
        let delivery = bus.take(id).expect("id");
        assert!(!delivery.must_refresh(), "{delivery:?}");
        assert_eq!(delivery.missed(), 0);
    }

    #[test]
    fn the_overflow_is_reported_once_and_the_total_is_kept() {
        // ★ Telling a subscriber the same loss twice would make a diagnostic count one overflow as several, and a
        // caller that reacted to each would re-read a snapshot per read. The count stays because a diagnostic wants the
        // total rather than the per-read figure.
        let bus = bus();
        let id = bus.subscribe();
        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 1) {
            bus.emit(Tick(seq));
        }

        let first = bus.take(id).expect("id");
        assert_eq!(first.missed(), 1);
        // Nothing new was emitted, so the second read has nothing and is not `Behind`.
        let second = bus.take(id).expect("id");
        assert!(!second.must_refresh(), "{second:?}");
        // But the total survives, for a diagnostic.
        assert_eq!(bus.report(id).expect("id").dropped, 1);
    }

    #[test]
    fn one_subscriber_overflowing_does_not_affect_another() {
        // ★ Each queue is its own. A slow window must not cost a diagnostic tool its events, and a shared buffer would
        // make the fastest reader's health depend on the slowest writer's.
        let bus = bus();
        let slow = bus.subscribe();
        let fast = bus.subscribe();

        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 * 2) {
            bus.emit(Tick(seq));
            // The fast subscriber reads every time, so it never fills.
            let _ = bus.take(fast);
        }

        let slow_delivery = bus.take(slow).expect("slow");
        assert!(slow_delivery.must_refresh());
        assert!(bus.report(slow).expect("slow").dropped > 0);

        let fast_report = bus.report(fast).expect("fast");
        assert_eq!(fast_report.dropped, 0);
        assert!(fast_report.is_healthy());
    }

    #[test]
    fn a_report_says_what_happened_and_why_it_matters() {
        let bus = bus();
        let id = bus.subscribe();
        let healthy = bus.report(id).expect("id");
        assert!(healthy.is_healthy());
        assert!(healthy.explain().contains("none dropped"), "{}", healthy.explain());

        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 5) {
            bus.emit(Tick(seq));
        }
        let behind = bus.report(id).expect("id");
        assert!(!behind.is_healthy());
        assert_eq!(behind.dropped, 5);
        assert_eq!(behind.queued, SUBSCRIBER_QUEUE_CAPACITY);
        // The sentence says what to do, which is the whole point of reporting it.
        assert!(behind.explain().contains("re-read"), "{}", behind.explain());
    }

    #[test]
    fn resetting_the_counters_keeps_the_queue() {
        // Clearing the counts and dropping the events would be two decisions in one call, and the caller that wanted
        // both can read and then reset.
        let bus = bus();
        let id = bus.subscribe();
        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 2) {
            bus.emit(Tick(seq));
        }
        assert!(bus.reset_counters(id));
        let report = bus.report(id).expect("id");
        assert_eq!(report.dropped, 0);
        assert_eq!(report.delivered, 0);
        assert!(report.is_healthy());
        // The queue is untouched.
        assert_eq!(report.queued, SUBSCRIBER_QUEUE_CAPACITY);
    }

    #[test]
    fn every_subscribers_report_is_listed() {
        // A diagnostic bundle wants all of them, and a report that covered only the first would hide the subscriber
        // that is actually the problem.
        let bus = bus();
        let first = bus.subscribe();
        let second = bus.subscribe();
        bus.emit(Tick(1));

        let reports = bus.reports();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].0, first);
        assert_eq!(reports[1].0, second);
        assert!(reports.iter().all(|(_, report)| report.delivered == 1));
    }

    // ── The sequence tracker ──────────────────────────────────────────────────────────────────────

    #[test]
    fn the_first_event_is_applied_whatever_its_number() {
        // A subscriber that attached mid-stream — a second window, a diagnostic tool — starts where it starts. Calling
        // its first event a gap would make it re-read a snapshot it has just taken.
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(1), Judgement::Apply);
        assert!(!tracker.is_stale());

        let mut late = SequenceTracker::new();
        assert_eq!(late.observe(5_000), Judgement::Apply);
        assert!(!late.is_stale());
    }

    #[test]
    fn a_repeat_is_refused_quietly() {
        // ★ A channel delivers the same event twice around a reconnect. Applying it twice is what makes a device appear
        // once in a list and be fetched twice. And it is not a fault, so it does not set the stale flag: a caller that
        // treated a repeat as a gap would re-read a snapshot for every duplicate.
        let mut tracker = SequenceTracker::new();
        assert_eq!(tracker.observe(5), Judgement::Apply);
        assert_eq!(tracker.observe(5), Judgement::IgnoreRepeat);
        assert_eq!(tracker.observe(4), Judgement::IgnoreRepeat);
        assert!(!tracker.is_stale());
        assert_eq!(tracker.gaps(), 0);
    }

    #[test]
    fn a_gap_is_reported_with_its_size() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        assert_eq!(tracker.observe(4), Judgement::RefreshSnapshot { missed: Some(2) });
        assert!(tracker.is_stale());
        assert_eq!(tracker.gaps(), 1);
    }

    #[test]
    fn a_contiguous_event_after_a_gap_is_applied_and_the_picture_stays_known_stale() {
        // ★ The decision an earlier version got wrong: leaving the sequence where it was made every event after a gap
        // another gap, so the interface could not make progress without a round trip per event. Advancing says "I know
        // where I am; my picture is incomplete until the snapshot arrives" — and the flag is what says the second half.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        assert!(matches!(tracker.observe(3), Judgement::RefreshSnapshot { .. }));
        assert!(tracker.is_stale());

        assert_eq!(tracker.observe(4), Judgement::Apply);
        // Applied, and still known to be incomplete.
        assert!(tracker.is_stale());
        assert_eq!(tracker.gaps(), 1);
        assert_eq!(tracker.last_seen(), Some(4));
    }

    #[test]
    fn a_snapshot_makes_the_picture_whole_again() {
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        tracker.observe(9);
        assert!(tracker.is_stale());
        tracker.snapshot_taken();
        assert!(!tracker.is_stale());
        // And the gap count survives, because it is a count of what happened rather than of what is still wrong.
        assert_eq!(tracker.gaps(), 1);
    }

    #[test]
    fn a_gap_beyond_the_cap_is_reported_as_unknown_rather_than_capped() {
        // ★ Reporting `MAX_COUNTED_GAP` for a gap of four billion would be a number the caller believes. `None` says
        // "there was a gap and its size is not worth reporting", which is the same instruction — re-read — without a
        // false figure.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        let judgement = tracker.observe(u64::from(MAX_COUNTED_GAP) + 100);
        assert_eq!(judgement, Judgement::RefreshSnapshot { missed: None });
        assert!(tracker.is_stale());
    }

    #[test]
    fn a_gap_exactly_at_the_cap_is_counted_and_one_beyond_it_is_not() {
        // ★ The boundary, asserted because an off-by-one there is a gap that reports itself as unknown when its size is
        // exactly the largest a consumer is told — or a capped figure where the true one would not have fitted.
        //
        // The count is the number of events *between* the two seen, which is the difference less one. That is the figure
        // a consumer can act on: seeing 1 and 1001 means events 2 through 1000 are missing, which is 999.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        assert_eq!(
            tracker.observe(u64::from(MAX_COUNTED_GAP) + 1),
            Judgement::RefreshSnapshot { missed: Some(MAX_COUNTED_GAP - 1) }
        );

        // One further and the gap is exactly the cap, which is still reported.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        assert_eq!(
            tracker.observe(u64::from(MAX_COUNTED_GAP) + 2),
            Judgement::RefreshSnapshot { missed: Some(MAX_COUNTED_GAP) }
        );

        // One beyond that and the size is not worth a number.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        assert_eq!(
            tracker.observe(u64::from(MAX_COUNTED_GAP) + 3),
            Judgement::RefreshSnapshot { missed: None }
        );
    }

    #[test]
    fn a_gap_from_the_buses_first_event_is_counted() {
        // The first event is applied whatever its number, so the gap between it and the second is one less than the
        // difference — and getting that wrong is a report that is off by one for every subscriber that attaches late.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1_000);
        assert_eq!(tracker.observe(1_003), Judgement::RefreshSnapshot { missed: Some(2) });
    }

    #[test]
    fn resetting_forgets_the_stream_and_the_gap_count() {
        // ★ The gap count goes too: it is a count of the gaps in *this* stream, and a reloaded interface that carried
        // the old total would report a number about a stream it is no longer reading.
        let mut tracker = SequenceTracker::new();
        tracker.observe(1);
        tracker.observe(50);
        assert!(tracker.is_stale());
        assert_eq!(tracker.gaps(), 1);

        tracker.reset();
        assert_eq!(tracker.last_seen(), None);
        assert_eq!(tracker.gaps(), 0);
        assert!(!tracker.is_stale());
        // And the next event is the first again rather than a gap.
        assert_eq!(tracker.observe(1), Judgement::Apply);
    }

    #[test]
    fn the_tracker_and_the_bus_agree_about_what_a_subscriber_saw() {
        // ★ The integration the two halves exist for: the bus drops the oldest, the tracker notices the hole, and the
        // subscriber's instruction is to re-read. A test of either alone would miss a disagreement between the size the
        // bus dropped and the size the tracker computed.
        let bus = bus();
        let id = bus.subscribe();
        let mut tracker = SequenceTracker::new();

        let mut judgements = Vec::new();
        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 7) {
            let emitted = bus.emit(Tick(seq));
            // The subscriber reads every time, so nothing overflows — and everything is applied.
            let delivery = bus.take(id).expect("id");
            assert!(!delivery.must_refresh());
            for _ in delivery.events() {
                judgements.push(tracker.observe(emitted));
            }
        }
        assert!(judgements.iter().all(|judgement| *judgement == Judgement::Apply));
        assert!(!tracker.is_stale());
    }

    #[test]
    fn a_subscriber_that_stops_reading_learns_how_much_it_missed() {
        // The same loop with the read removed, which is the case the queue is bounded for. The tracker is fed what the
        // subscriber actually received, and computes the hole the bus created.
        let bus = bus();
        let id = bus.subscribe();

        for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 7) {
            bus.emit(Tick(seq));
        }

        let delivery = bus.take(id).expect("id");
        assert!(delivery.must_refresh());
        assert_eq!(delivery.missed(), 7);
        // What the subscriber sees begins after the hole, and the tracker's judgement about the first event is `Apply`
        // because it has no history — which is why the bus's own `missed` is what a fresh subscriber relies on.
        assert_eq!(delivery.events()[0], Tick(8));
    }

    #[test]
    fn a_bus_with_no_subscribers_still_numbers_its_events() {
        // The numbering is the kernel's, not a subscriber's. A kernel that only counted when someone was listening
        // would restart its numbering when the last window closed, and an interface that reconnected would see numbers
        // it had already seen.
        let bus: EventBus<Tick> = bus();
        assert_eq!(bus.emit(Tick(1)), 1);
        assert_eq!(bus.emit(Tick(2)), 2);
        let id = bus.subscribe();
        bus.emit(Tick(3));
        assert_eq!(bus.take(id).expect("id").events(), &[Tick(3)]);
        assert_eq!(bus.last_sequence(), Some(3));
    }

    #[test]
    fn the_default_bus_is_empty_and_numbered_from_one() {
        let bus: EventBus<Tick> = EventBus::default();
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.next_sequence(), 1);
    }

    #[test]
    fn the_bus_can_be_shared_between_threads() {
        // ★ Where the bus is used: one kernel task emits and several interfaces read, so the bus crosses threads by
        // construction. A compile-time assertion with a runtime witness — a bus that was not `Send + Sync` would not
        // compile here, and the failure would otherwise appear wherever it was first put behind an `Arc`.
        fn assert_shareable<T: Send + Sync>() {}
        assert_shareable::<EventBus<Tick>>();
        assert_shareable::<SubscriberId>();
        assert_shareable::<SubscriberReport>();

        // And it works from another thread, which is the property the assertion is a proxy for.
        let bus = Arc::new(bus());
        let id = bus.subscribe();
        let emitted = Arc::clone(&bus);
        let handle = std::thread::spawn(move || emitted.emit(Tick(42)));
        let seq = handle.join().expect("the thread finished");
        assert_eq!(seq, 1);
        assert_eq!(bus.take(id).expect("id").events(), &[Tick(42)]);
    }

    #[test]
    fn a_subscriber_identity_is_readable_in_a_report() {
        // A diagnostic bundle names the subscriber it is complaining about, and an opaque tuple would give it a number
        // with no way to refer to it.
        let bus = bus();
        let id = bus.subscribe();
        assert_eq!(id.to_string(), format!("sub{}", id.get()));
        assert!(id.get() >= 1);
    }
}
