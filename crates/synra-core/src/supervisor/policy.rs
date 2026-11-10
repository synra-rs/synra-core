use super::*;

/// How long a task is given to notice it was cancelled before the shutdown gives up on it.
///
/// Two seconds, and the number is about *the user closing the window*: a shutdown that waits for a task stuck in a
/// syscall is a window that will not close, and the honest alternative to waiting for ever is to say the task did
/// not stop. Every task in the kernel is written to notice a cancellation token, so the grace period is a
/// backstop rather than the usual path.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// A task's stable name.
///
/// # Why a name and not a number
///
/// Because the two things this is used for both need one: a log line that says which task restarted, and a
/// `doctor` report that says which task is not running. `task-7` answers neither, and the numbering would change
/// between runs — so a support conversation about "task 7" would be about a different task each time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub(super) String);

impl TaskId {
    /// Names a task.
    ///
    /// The convention is `area.thing` — `discovery.udp`, `transport.accept`, `heartbeat.ticker` — which makes a
    /// list of them readable and makes a prefix search meaningful.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this task is in an area, such as everything under `discovery.`.
    #[must_use]
    pub fn is_in(&self, area: &str) -> bool {
        self.0.starts_with(area) && self.0.len() > area.len()
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&str> for TaskId {
    fn from(name: &str) -> Self {
        Self(name.to_owned())
    }
}

impl From<String> for TaskId {
    fn from(name: String) -> Self {
        Self(name)
    }
}

/// What to do when a task stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestartPolicy {
    /// It ran once. Stopping is the end.
    ///
    /// For bootstrap work — opening the store, loading the identity — where a second attempt would be a second
    /// attempt at the same thing that just failed.
    Once,
    /// Start it again, up to `max_attempts` times, without waiting.
    ///
    /// For a task whose failure is a *configuration* problem that a retry could not fix either, and where waiting
    /// would only delay the report. Rare: most things that can fail can fail because a peer is asleep.
    Retry {
        /// How many restarts are allowed before it is given up on.
        max_attempts: u32,
    },
    /// Start it again after a wait, up to `max_attempts` times.
    ///
    /// The ordinary policy for a long-lived service: a listener that could not bind because another process held the
    /// port will succeed when that process exits, and retrying immediately would be a busy loop.
    Backoff {
        /// How many restarts are allowed before it is given up on.
        max_attempts: u32,
        /// How long the first wait is. Later waits grow, up to `max`.
        initial: Duration,
        /// The longest a wait may be.
        max: Duration,
    },
}

impl RestartPolicy {
    /// The policy a service that should outlive its failures uses.
    #[must_use]
    pub const fn service() -> Self {
        Self::Backoff {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
        }
    }

    /// Whether it starts again at all.
    #[must_use]
    pub const fn restarts(self) -> bool {
        !matches!(self, Self::Once)
    }

    /// How many restarts are allowed.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        match self {
            Self::Once => 0,
            Self::Retry { max_attempts } | Self::Backoff { max_attempts, .. } => max_attempts,
        }
    }

    /// How long to wait before a restart, by attempt number counting from one.
    ///
    /// # Why this does not grow without bound, and why it is not exponential-with-a-crawl
    ///
    /// A doubling tail is right for a resource that might be *busy* and wrong for one that might be *absent*: a port
    /// held by another process is released in seconds, and a peer on a network is reachable or not. So the wait
    /// doubles up to `max` and then stays there, which is the same shape the reconnect schedule settled on and for
    /// the same reason.
    ///
    /// The jitter is derived from the task's name, not random: two listeners that failed together because the
    /// machine's network went down must not come back at the same instant, and a delay that a test can compute is a
    /// delay a test can assert.
    #[must_use]
    pub fn delay_for(self, attempt: u32, task: &TaskId) -> Duration {
        let (initial, ceiling) = match self {
            Self::Backoff { initial, max, .. } => (initial, max),
            // A plain retry does not wait. `Duration::ZERO` rather than a small number: a caller that wanted a wait
            // asked for `Backoff`.
            Self::Once | Self::Retry { .. } => return Duration::ZERO,
        };
        if attempt <= 1 {
            return jitter(initial, task, attempt, ceiling);
        }
        // `attempt - 1` doublings, saturating: a task that has failed forty times must not overflow the shift.
        let factor = 1_u32
            .checked_shl(attempt.saturating_sub(1).min(16))
            .unwrap_or(u32::MAX);
        let grown = initial.saturating_mul(factor).min(ceiling);
        jitter(grown, task, attempt, ceiling)
    }

    /// A name, for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Retry { .. } => "retry",
            Self::Backoff { .. } => "backoff",
        }
    }
}

/// How many restarts a service gets before it is reported as one that keeps failing.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

/// Derives a jitter for a delay.
///
/// # Why the offset is only ever *added*, and why the ceiling is applied last
///
/// A symmetric jitter would let a later attempt wait less than an earlier one, which makes "the wait grows" a
/// property a test can only assert within a band — and, worse, makes a policy whose numbers a user was shown describe
/// something the schedule does not do. Adding up to a quarter keeps every attempt at least as long as its nominal
/// value, so the growth is real, and the spreading that matters still happens: two tasks that failed together get
/// different offsets, and no attempt is ever zero.
///
/// The clamp at the end is what makes `max` a ceiling rather than a number the jitter can cross. Without it a policy
/// that said "no longer than four seconds" would wait four and a bit.
fn jitter(nominal: Duration, task: &TaskId, attempt: u32, ceiling: Duration) -> Duration {
    let nominal_ms = u64::try_from(nominal.as_millis()).unwrap_or(u64::MAX);
    let ceiling_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    if nominal_ms <= 1 {
        return Duration::from_millis(1);
    }
    // A splitmix64 step over the name and the attempt, so consecutive attempts do not move in a straight line and
    // two tasks with similar names do not fail in lockstep.
    let seed = task
        .as_str()
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |accumulated, byte| {
            (accumulated ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
        });
    let mut mixed = seed ^ u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^= mixed >> 31;

    let span = (nominal_ms / 4).max(1);
    Duration::from_millis(nominal_ms.saturating_add(mixed % span).min(ceiling_ms))
}

/// Whether a task's failure should degrade the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Criticality {
    /// Its failure is reported and the kernel carries on.
    ///
    /// The default, and the right answer for most things: a discovery listener that cannot bind does not stop the
    /// transport, and a kernel that degraded because of it would be reporting an unrelated failure as a whole-system
    /// one.
    Ordinary,
    /// Its failure means the kernel is not doing its job.
    ///
    /// For the things without which there is nothing to degrade *to* — the store, the identity, the accept loop. A
    /// kernel that has lost one of these is one a user should be told about rather than one that quietly does less.
    Critical,
}
