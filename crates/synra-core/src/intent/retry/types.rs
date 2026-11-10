use super::*;

///
/// # Why these numbers
///
/// A dispatch that timed out has just spent `crate::dispatch::REMOTE_RESULT_WAIT` waiting; retrying immediately would be a
/// busy loop against a device that is asleep. Half a minute is long enough for a peer to come back from a suspend and short
/// enough to be useful; the cap is five minutes because a device that is off will be off for a while, and the attempt bound
/// (eight) is what keeps a day's worth of retries from becoming a day's worth of dials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// The wait before the first retry.
    pub initial: Duration,
    /// The longest wait between retries.
    pub max: Duration,
    /// How many retries before this pass gives up until the next start.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(30),
            max: Duration::from_secs(300),
            max_attempts: 8,
        }
    }
}

impl RetryPolicy {
    /// The wait before retry number `attempt`, jittered by the intent's own name.
    ///
    /// ★ Reusing the supervisor's policy rather than writing a second backoff: the shape (double, cap, add a name-derived
    /// jitter so two intents do not retry in lockstep) is already implemented and already tested.
    #[must_use]
    pub fn delay(self, id: IntentId, attempt: u32) -> Duration {
        RestartPolicy::Backoff {
            max_attempts: self.max_attempts,
            initial: self.initial,
            max: self.max,
        }
        .delay_for(attempt, &TaskId::new(id.to_string()))
    }

    /// The same wait in the store's clock, saturating rather than wrapping.
    #[must_use]
    pub fn delay_ms(self, id: IntentId, attempt: u32) -> i64 {
        i64::try_from(self.delay(id, attempt).as_millis()).unwrap_or(i64::MAX)
    }
}

/// What a host tells the user about one intent's retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryStatus {
    /// How many retries have already been sent.
    pub attempts: u32,
    /// How many this pass will make before giving up.
    pub max_attempts: u32,
    /// Whether this pass stopped retrying. The intent itself is still in flight.
    pub gave_up: bool,
    /// When the next try is due, in milliseconds since the epoch. `None` when nothing is scheduled — a given-up entry,
    /// or one whose attempt is in flight at this moment.
    pub next_at_ms: Option<i64>,
}

/// When each outstanding dispatch is next due, and how many times it has been retried.
#[derive(Debug)]
pub struct RetryQueue {
    pub(super) policy: RetryPolicy,
    /// How many retries have been scheduled, counting the next one. Missing means "not seen yet".
    pub(super) attempts: HashMap<IntentId, u32>,
    /// When the next attempt is due, in milliseconds since the epoch. Missing means "not waiting".
    pub(super) due: HashMap<IntentId, i64>,
    /// Intents this pass stopped retrying. Kept rather than forgotten because the interface is told "no answer yet" — the
    /// intent itself is still `Dispatching`, and the entry goes when the intent ends.
    pub(super) gave_up: HashSet<IntentId>,
}
