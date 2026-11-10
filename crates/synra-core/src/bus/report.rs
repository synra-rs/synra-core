use super::fanout::EventBus;
use super::subscription::{SubscriberId, SubscriberReport};

impl<E: Clone> EventBus<E> {
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
        Some(SubscriberReport {
            dropped,
            delivered,
            queued,
            overflowed,
        })
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
        subscribers
            .iter_mut()
            .find(|(existing, _)| *existing == id)
            .is_some_and(|(_, subscriber)| {
                subscriber.dropped = 0;
                subscriber.delivered = 0;
                subscriber.overflowed = false;
                true
            })
    }
}
