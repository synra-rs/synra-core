use super::*;

/// How one attempt ended, as the runner needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attempt {
    /// The answer arrived and the host applied it.
    Answered,
    /// The intent is no longer in flight, so there is nothing to send. Its schedule goes without a retry.
    Ended,
    /// The send went out and nothing came back inside the wait.
    Unanswered,
    /// The send could not be made at all.
    Failed,
}

/// The host-specific halves of the retry loop.
///
/// # Why a trait and not four closures
///
/// Because the three pieces read the same host state, and a closure passed for each would either capture it three times
/// or need a struct anyway. A trait is that struct with the compiler checking which half is which.
pub trait RetryHost {
    /// The intents the host would send right now.
    fn pending(&mut self) -> Vec<IntentId>;

    /// One attempt at one intent.
    fn attempt(&mut self, id: IntentId) -> Attempt;

    /// A schedule changed: the row to write (or `None` to remove it) and what to tell the user.
    fn changed(
        &mut self,
        id: IntentId,
        row: Option<synra_store::IntentRetryRow>,
        status: Option<RetryStatus>,
    );
}

/// Runs the schedule until cancelled.
///
/// # What is shared, and what is not
///
/// The loop is the same in every host: take what is due, attempt it, forget the answered, back off the rest, see what
/// new work appeared, then sleep until the next due time. What differs is [`RetryHost`] — how to send, where to write,
/// what to show. Before this, the window and the daemon each wrote that loop; a change to the wait ceiling or the
/// give-up rule had to be made twice.
///
/// The clock and the sleep are arguments rather than calls, so a test drives a number forward and a cancellation
/// instead of waiting five minutes.
pub fn run_loop(
    queue: &mut RetryQueue,
    cancel: &Cancellation,
    host: &mut dyn RetryHost,
    now: &mut dyn FnMut() -> i64,
    sleep: &mut dyn FnMut(Duration),
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }

        for id in queue.take_due(now()) {
            match host.attempt(id) {
                Attempt::Answered | Attempt::Ended => queue.forget(id),
                Attempt::Unanswered | Attempt::Failed => {
                    // The return value is "another attempt was scheduled"; a host that cares reads `status.gave_up` in
                    // `changed`, which is the same fact in the shape it shows.
                    let _ = queue.record_failure(id, now());
                }
            }
            host.changed(id, queue.row(id), queue.status(id));
        }

        // New dispatches can appear while a send is in flight; the next wake has to see them, and their first schedule
        // has to be written down.
        for id in queue.observe(host.pending(), now()) {
            host.changed(id, queue.row(id), queue.status(id));
        }

        let wait = queue
            .next_wait(now())
            .min(Duration::from_secs(30))
            .max(Duration::from_millis(10));
        sleep(wait);
    }
}
