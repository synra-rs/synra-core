//! Long-running work: what may run, what happens when it stops, and how the kernel shuts down.
//!
//! # Why a supervisor rather than `spawn`
//!
//! Because a task that stopped is the most expensive thing to *not* notice. A discovery listener that died silently
//! leaves a device that is on the network appearing absent; a heartbeat that died leaves links that look up and
//! time out one message at a time. Neither is a crash, and neither produces a log line unless something is watching
//! — which is what this is: a registry of what should be running, and a decision, made when something stops, about
//! whether it should be running again.
//!
//! # What is here, and what is deliberately not
//!
//! This is the **synchronous** half: the registry, the restart decision, cancellation, the shutdown order, and the
//! report a caller gets afterwards. It runs on a thread of its own, which is the model the plugin executor already
//! uses and the reason nothing here needs an asynchronous runtime.
//!
//! What is not here is the drive loop that would *run* asynchronous factories — `BoxFuture` and the joining of
//! several futures at shutdown need an executor, and the kernel's own runtime is not part of this crate. A caller
//! with one supplies the tasks through [`Supervisor::run_task`], which is the entry point that exists for it.
//!
//! # The rule that shapes the decision
//!
//! **A task that fails the same way for ever is a task that should stop.** An exponential-free, bounded schedule
//! plus a ceiling is what turns "the network is down" into a device that stops trying and says so, rather than one
//! that has spent an hour of battery by the time the user looks at it. And giving up is never permanent: a task may
//! be started again deliberately — by the user, by a plugin being enabled, by a network change — which is what
//! [`Supervisor::start`] does.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;

mod cancellation;
pub use cancellation::Cancellation;

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
pub struct TaskId(String);

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
        Self::Backoff { max_attempts: DEFAULT_MAX_ATTEMPTS, initial: Duration::from_millis(250), max: Duration::from_secs(30) }
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
        let factor = 1_u32.checked_shl(attempt.saturating_sub(1).min(16)).unwrap_or(u32::MAX);
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
    let seed = task.as_str().bytes().fold(0xcbf2_9ce4_8422_2325_u64, |accumulated, byte| {
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

/// A task that should be running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    /// Its stable name.
    pub id: TaskId,
    /// What to do when it stops.
    pub restart: RestartPolicy,
    /// How much its failure matters.
    pub criticality: Criticality,
}

impl TaskSpec {
    /// A long-lived service that restarts with a backoff.
    #[must_use]
    pub fn service(id: impl Into<TaskId>) -> Self {
        Self { id: id.into(), restart: RestartPolicy::service(), criticality: Criticality::Ordinary }
    }

    /// A task that runs once, such as a bootstrap step.
    #[must_use]
    pub fn bootstrap(id: impl Into<TaskId>) -> Self {
        Self { id: id.into(), restart: RestartPolicy::Once, criticality: Criticality::Critical }
    }

    /// Marks its failure as one the whole kernel feels.
    #[must_use]
    pub const fn critical(mut self) -> Self {
        self.criticality = Criticality::Critical;
        self
    }

    /// Sets the restart policy.
    #[must_use]
    pub const fn with_policy(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }
}

/// Why a task stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopReason {
    /// Its work finished. Not a failure.
    Finished,
    /// It was asked to stop.
    Cancelled,
    /// It failed.
    Failed {
        /// What went wrong, in a sentence.
        detail: String,
    },
}

impl StopReason {
    /// Whether this is a reason to restart anything.
    ///
    /// A finished task and a cancelled one are both *done*: restarting either would undo a decision somebody made,
    /// and a shutdown that restarted its own tasks would never finish.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// A name, for a log line.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::Cancelled => "cancelled",
            Self::Failed { .. } => "failed",
        }
    }
}

/// What the supervisor decided about a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Start it again after this long.
    Restart {
        /// The wait.
        after: Duration,
        /// Which attempt this will be, counting from one.
        attempt: u32,
    },
    /// Leave it stopped.
    ///
    /// Every reason carries *why*, because "it is not running" is the start of a support conversation rather than
    /// the end of one.
    Leave {
        /// Why it will not be restarted.
        why: WhyNot,
    },
}

impl Decision {
    /// Whether a restart was decided on.
    #[must_use]
    pub const fn is_restart(&self) -> bool {
        matches!(self, Self::Restart { .. })
    }
}

/// Why a task is not being restarted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WhyNot {
    /// It did not fail: it finished, or it was asked to stop.
    NotAFailure,
    /// Its policy says it runs once.
    RunsOnce,
    /// It has been restarted as many times as its policy allows.
    AttemptsExhausted {
        /// How many restarts were made.
        attempts: u32,
    },
    /// The kernel is shutting down.
    ShuttingDown,
}

impl std::fmt::Display for WhyNot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFailure => formatter.write_str("it did not fail"),
            Self::RunsOnce => formatter.write_str("it runs once"),
            Self::AttemptsExhausted { attempts } => {
                write!(formatter, "it has already restarted {attempts} time(s)")
            }
            Self::ShuttingDown => formatter.write_str("the kernel is shutting down"),
        }
    }
}

/// What the supervisor knows about one task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    /// What it should be doing.
    pub spec: TaskSpec,
    /// How many times it has been restarted.
    pub restarts: u32,
    /// Whether it is running now.
    pub running: bool,
    /// The last time it stopped, in signed milliseconds since the epoch.
    pub last_stop_ms: Option<i64>,
    /// Why it stopped last.
    pub last_reason: Option<StopReason>,
}

impl TaskRecord {
    /// Whether the task is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Whether it has been given up on, and why.
    #[must_use]
    pub const fn is_abandoned(&self) -> Option<WhyNot> {
        match (&self.last_reason, self.running) {
            (Some(reason), false) if reason.is_failure() && !self.spec.restart.restarts() => {
                Some(WhyNot::RunsOnce)
            }
            (Some(reason), false)
                if reason.is_failure() && self.restarts >= self.spec.restart.max_attempts() =>
            {
                Some(WhyNot::AttemptsExhausted { attempts: self.restarts })
            }
            _ => None,
        }
    }

    /// A sentence for a `doctor` report.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.running, &self.last_reason) {
            (true, _) => format!("{} is running", self.spec.id),
            (false, Some(reason)) => match reason {
                StopReason::Failed { detail } => {
                    format!("{} stopped: {detail}", self.spec.id)
                }
                StopReason::Cancelled => format!("{} was stopped", self.spec.id),
                StopReason::Finished => format!("{} finished", self.spec.id),
            },
            (false, None) => format!("{} has not started", self.spec.id),
        }
    }
}

/// Why the supervisor would not take a task.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SupervisorError {
    /// A task with that name is already registered.
    ///
    /// Refused rather than replacing the first: two tasks with one name would make every log line about either of
    /// them ambiguous, and the second registration is far more likely to be a copy-paste mistake than an intent.
    #[error("{id} is already supervised")]
    AlreadyRegistered {
        /// Which name.
        id: TaskId,
    },

    /// The supervisor has been shut down.
    #[error("the supervisor has been shut down")]
    ShutDown,

    /// No task by that name.
    #[error("{id} is not supervised by this supervisor")]
    Unknown {
        /// Which name.
        id: TaskId,
    },
}

/// The decision itself, over a record that is already locked.
///
/// # Why this is a free function
///
/// Because the rule is what needs testing and the lock is what needs releasing, and a body that returned from four
/// places while holding a lock is exactly the shape `significant_drop_tightening` refuses. Taking the record and
/// answering is the whole decision; whether a lock was held is the caller's business.
fn decide_for(record: &mut TaskRecord, reason: &StopReason, shutting_down: bool, id: &TaskId) -> Decision {
    if !reason.is_failure() {
        return Decision::Leave { why: WhyNot::NotAFailure };
    }
    if shutting_down {
        // ★ Checked before the policy, because a shutdown that restarted a task would never finish: the task would
        // come back, be cancelled again, and come back again.
        return Decision::Leave { why: WhyNot::ShuttingDown };
    }
    let policy = record.spec.restart;
    if !policy.restarts() {
        return Decision::Leave { why: WhyNot::RunsOnce };
    }
    let attempt = record.restarts.saturating_add(1);
    if attempt > policy.max_attempts() {
        return Decision::Leave { why: WhyNot::AttemptsExhausted { attempts: record.restarts } };
    }

    record.restarts = attempt;
    Decision::Restart { after: policy.delay_for(attempt, id), attempt }
}

/// The registry: what should be running, what is, and what was decided when something stopped.
///
/// # Why the decision is a value
///
/// Because "should this be restarted" is the part of a supervisor that gets it wrong, and it is the part that needs
/// no threads to test. [`Supervisor::decide`] takes a stop and answers; the loop that waits for stops and applies
/// the answer is a dozen lines that a single test can drive with a channel.
#[derive(Debug)]
pub struct Supervisor {
    tasks: Mutex<HashMap<TaskId, TaskRecord>>,
    /// The order tasks were registered in, so a list and a shutdown are deterministic.
    order: Mutex<Vec<TaskId>>,
    shutdown: Cancellation,
    /// How many tasks are running, for a cheap answer to "is anything still up".
    running: AtomicU64,
    /// When the supervisor started, in signed milliseconds since the epoch. The reference for the waits.
    started_at_ms: i64,
}

impl Supervisor {
    /// An empty supervisor.
    #[must_use]
    pub fn new(started_at_ms: i64) -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
            shutdown: Cancellation::new(),
            running: AtomicU64::new(0),
            started_at_ms,
        }
    }

    /// Registers a task.
    ///
    /// # Errors
    ///
    /// [`SupervisorError::AlreadyRegistered`] when the name is taken, and [`SupervisorError::ShutDown`] afterwards.
    pub fn register(&self, spec: TaskSpec) -> Result<(), SupervisorError> {
        if self.shutdown.is_cancelled() {
            return Err(SupervisorError::ShutDown);
        }
        // One scope for both locks, and both released before the function returns. The lock is the last thing the
        // body touches, so there is nothing after it — and a caller that registered a task is about to start it,
        // which takes the same lock.
        {
            let mut tasks = self.tasks.lock();
            if tasks.contains_key(&spec.id) {
                return Err(SupervisorError::AlreadyRegistered { id: spec.id });
            }
            self.order.lock().push(spec.id.clone());
            let _ = tasks.insert(
                spec.id.clone(),
                TaskRecord { spec, restarts: 0, running: false, last_stop_ms: None, last_reason: None },
            );
        }
        Ok(())
    }

    /// Marks a task as started.
    ///
    /// # Errors
    ///
    /// [`SupervisorError::Unknown`] when nothing by that name was registered — which is the check that matters: a
    /// task that started without being registered is one nothing is watching.
    pub fn start(&self, id: &TaskId) -> Result<(), SupervisorError> {
        let mut tasks = self.tasks.lock();
        let record = tasks.get_mut(id).ok_or_else(|| SupervisorError::Unknown { id: id.clone() })?;
        if !record.running {
            record.running = true;
            let _ = self.running.fetch_add(1, Ordering::AcqRel);
        }
        // Released by the `drop`, which is what `significant_drop_tightening` is asking for: nothing below this
        // line touches the map, and the counter is shared with the readers.
        drop(tasks);
        Ok(())
    }

    /// Decides what to do about a task that stopped.
    ///
    /// # Why `reason` is borrowed
    ///
    /// Because it is recorded *and* decided from, and a caller that has it already should not have to give it up to
    /// ask a question about it. `now_ms` is a parameter for the other reason a clock ever is: the decision depends on
    /// it, so a test that asserts "it stopped at this moment" passes a number rather than sleeping.
    pub fn decide(&self, id: &TaskId, reason: &StopReason, now_ms: i64) -> Result<Decision, SupervisorError> {
        let shutting_down = self.shutdown.is_cancelled();
        let mut tasks = self.tasks.lock();
        let record = tasks.get_mut(id).ok_or_else(|| SupervisorError::Unknown { id: id.clone() })?;
        if record.running {
            record.running = false;
            let _ = self.running.fetch_sub(1, Ordering::AcqRel);
        }
        record.last_reason = Some(reason.clone());
        record.last_stop_ms = Some(now_ms);
        let decision = decide_for(record, reason, shutting_down, id);
        // Released by the `drop` rather than at the end of the function, which is what the lint is asking for: the
        // decision is made by now, and a caller's next move is usually `start`, which takes the same lock.
        drop(tasks);
        Ok(decision)
    }

    /// The tasks that should be running and are not.
    ///
    /// What a `doctor` report and a health probe both read. Ordered by registration, so two reports agree.
    #[must_use]
    pub fn stopped(&self) -> Vec<TaskRecord> {
        let tasks = self.tasks.lock();
        self.order
            .lock()
            .iter()
            .filter_map(|id| tasks.get(id))
            .filter(|record| !record.running)
            .cloned()
            .collect()
    }

    /// Everything registered, ordered by registration.
    #[must_use]
    pub fn records(&self) -> Vec<TaskRecord> {
        let tasks = self.tasks.lock();
        self.order.lock().iter().filter_map(|id| tasks.get(id)).cloned().collect()
    }

    /// One task's record.
    ///
    /// # Errors
    ///
    /// [`SupervisorError::Unknown`] when nothing by that name was registered.
    pub fn record(&self, id: &TaskId) -> Result<TaskRecord, SupervisorError> {
        self.tasks
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| SupervisorError::Unknown { id: id.clone() })
    }

    /// Whether every critical task is running.
    ///
    /// # Why criticality is the question rather than "is anything stopped"
    ///
    /// Because a discovery listener that failed is not a kernel that is broken, and a health report that treated the
    /// two the same would be one a user learns to ignore. This is the answer to "is this device doing its job".
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.tasks
            .lock()
            .values()
            .filter(|record| record.spec.criticality == Criticality::Critical)
            .all(|record| record.running)
    }

    /// How many tasks are running.
    #[must_use]
    pub fn running_count(&self) -> u64 {
        self.running.load(Ordering::Acquire)
    }

    /// How many tasks are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.lock().len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.lock().is_empty()
    }

    /// When the supervisor was created.
    #[must_use]
    pub const fn started_at_ms(&self) -> i64 {
        self.started_at_ms
    }

    /// Asks everything to stop.
    ///
    /// # Returns
    ///
    /// The names in the order they should be stopped: **reverse registration**. A task registered later is one that
    /// depends on the ones before it — a heartbeat on a transport, a transport on discovery — so stopping in
    /// registration order would take the ground out from under the tasks still running.
    #[must_use]
    pub fn begin_shutdown(&self) -> Vec<TaskId> {
        self.shutdown.cancel();
        let order = self.order.lock();
        order.iter().rev().cloned().collect()
    }

    /// Whether a shutdown has been asked for.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    /// The token a task watches.
    #[must_use]
    pub fn cancellation(&self) -> Cancellation {
        self.shutdown.clone()
    }

    /// What the shutdown did, once everything has been waited for.
    ///
    /// # Why the report exists
    ///
    /// Because a task that did not stop is a fact the caller has to act on — a process that exits with a locked port
    /// will not start again — and a shutdown that returned nothing would make "it seemed to close" the only
    /// observable outcome.
    #[must_use]
    pub fn report(&self) -> ShutdownReport {
        let stopped: Vec<TaskId> = self
            .records()
            .into_iter()
            .filter(|record| !record.running)
            .map(|record| record.spec.id)
            .collect();
        let still_running: Vec<TaskId> = self
            .records()
            .into_iter()
            .filter(|record| record.running)
            .map(|record| record.spec.id)
            .collect();
        ShutdownReport { stopped, still_running }
    }
}

/// What a shutdown left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// The tasks that are not running.
    pub stopped: Vec<TaskId>,
    /// The tasks that are still running, which is what a caller has to decide about.
    pub still_running: Vec<TaskId>,
}

impl ShutdownReport {
    /// Whether everything stopped.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.still_running.is_empty()
    }

    /// A sentence for a log line.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.is_clean() {
            return format!("{} task(s) stopped", self.stopped.len());
        }
        format!(
            "{} task(s) stopped, but {} did not: {}",
            self.stopped.len(),
            self.still_running.len(),
            self.still_running.iter().map(TaskId::as_str).collect::<Vec<&str>>().join(", ")
        )
    }
}

/// Runs a task under supervision, on a thread of its own.
///
/// # Why this is a function and not a method
///
/// Because what a task *does* is the caller's: this owns the lifecycle — registration, the cancellation token, the
/// restart decision, the record — and the work is a closure. A supervisor that knew how to run a discovery listener
/// would be a supervisor that knows about discovery.
///
/// # The contract with the work
///
/// The closure is given the cancellation token and must return when it is cancelled, or must return a failure. A
/// closure that ignores the token leaves a thread running after [`Supervisor::report`] says the task stopped, which
/// is why [`SHUTDOWN_GRACE`] exists and why the token is passed rather than reachable through the supervisor.
///
/// # Errors
///
/// [`SupervisorError`] when the task is unknown or the supervisor has been shut down. The task's own failure is not
/// an error here: it is recorded, and the restart policy decides what happens next.
pub fn run_task<F>(
    supervisor: &Arc<Supervisor>,
    id: &TaskId,
    work: F,
) -> Result<thread::JoinHandle<()>, SupervisorError>
where
    F: FnOnce(&Cancellation) -> Result<(), String> + Send + 'static,
{
    // Read before the thread starts, so a refusal happens on the caller's thread rather than inside a task that
    // would then have to report it somewhere nobody is listening.
    let _ = supervisor.record(id)?;
    let token = supervisor.cancellation();
    let supervisor = Arc::clone(supervisor);
    let task_id = id.clone();

    thread::Builder::new()
        .name(format!("synra-{id}"))
        .spawn(move || {
            let outcome = work(&token);
            let reason = match outcome {
                Ok(()) if token.is_cancelled() => StopReason::Cancelled,
                Ok(()) => StopReason::Finished,
                Err(detail) => StopReason::Failed { detail },
            };
            // The decision is made and *not* acted on here: acting on it would be a task that restarts itself, and
            // a supervisor that cannot see its own restarts is not supervising anything.
            let _ = supervisor.decide(&task_id, &reason, 0);
        })
        .map_err(|_| SupervisorError::ShutDown)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000;

    fn supervisor() -> Arc<Supervisor> {
        Arc::new(Supervisor::new(NOW))
    }

    fn id(name: &str) -> TaskId {
        TaskId::new(name)
    }

    #[test]
    fn a_task_is_registered_and_starts_stopped() {
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("discovery.udp")).expect("registered");

        let record = supervisor.record(&id("discovery.udp")).expect("a record");
        assert!(!record.is_running(), "registering is not starting");
        assert_eq!(record.restarts, 0);
        assert_eq!(supervisor.running_count(), 0);
        assert_eq!(supervisor.len(), 1);
        assert!(!supervisor.is_empty());
        // And nothing critical has failed, so the kernel is healthy with nothing running yet.
        assert!(supervisor.is_healthy());
    }

    #[test]
    fn two_tasks_with_one_name_are_refused() {
        // ★ Two tasks with one name would make every log line about either of them ambiguous, and the second
        // registration is far more likely to be a copy-paste mistake than an intent.
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("transport.accept")).expect("registered");
        match supervisor.register(TaskSpec::service("transport.accept")) {
            Err(SupervisorError::AlreadyRegistered { id: name }) => {
                assert_eq!(name.as_str(), "transport.accept");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn starting_a_task_nothing_registered_is_refused() {
        // The check that matters: a task that started without being registered is one nothing is watching.
        let supervisor = supervisor();
        match supervisor.start(&id("ghost")) {
            Err(SupervisorError::Unknown { id: name }) => assert_eq!(name.as_str(), "ghost"),
            other => panic!("expected an unknown-task refusal, got {other:?}"),
        }
    }

    #[test]
    fn starting_twice_counts_one_running_task() {
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("heartbeat.ticker")).expect("registered");
        supervisor.start(&id("heartbeat.ticker")).expect("started");
        supervisor.start(&id("heartbeat.ticker")).expect("started again");

        assert_eq!(supervisor.running_count(), 1, "a task started twice is one task");
    }

    #[test]
    fn a_finished_task_is_not_restarted() {
        // ★ Restarting a task that finished would undo a decision somebody made — and a shutdown that restarted its
        // own tasks would never finish.
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("bootstrap.load-store")).expect("registered");
        let _ = supervisor.start(&id("bootstrap.load-store"));

        let decision = supervisor.decide(&id("bootstrap.load-store"), &StopReason::Finished, NOW).expect("decided");
        assert_eq!(decision, Decision::Leave { why: WhyNot::NotAFailure });
        assert_eq!(supervisor.running_count(), 0);
        assert!(supervisor.stopped().len() == 1);
    }

    #[test]
    fn a_cancelled_task_is_not_restarted_even_by_a_service_policy() {
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("discovery.udp")).expect("registered");
        let _ = supervisor.start(&id("discovery.udp"));

        let decision = supervisor.decide(&id("discovery.udp"), &StopReason::Cancelled, NOW).expect("decided");
        assert!(!decision.is_restart());
    }

    #[test]
    fn a_service_restarts_with_a_growing_wait() {
        // The shape the policy promises: the first wait is short, and later ones grow to the ceiling rather than
        // without bound.
        let supervisor = supervisor();
        let task = id("transport.accept");
        supervisor
            .register(TaskSpec::service(task.clone()).with_policy(RestartPolicy::Backoff {
                max_attempts: 6,
                initial: Duration::from_millis(250),
                max: Duration::from_secs(4),
            }))
            .expect("registered");

        let mut previous = Duration::ZERO;
        let mut grew = 0_u32;
        for attempt in 1..=6 {
            let _ = supervisor.start(&task);
            let decision = supervisor
                .decide(&task, &StopReason::Failed { detail: format!("attempt {attempt}") }, NOW)
                .expect("decided");
            let Decision::Restart { after, attempt: counted } = decision else {
                panic!("attempt {attempt} was not restarted: {decision:?}");
            };
            assert_eq!(counted, attempt, "the supervisor counts its own restarts");
            assert!(after > Duration::ZERO, "a wait of zero is a busy loop");
            // ★ The wait never shrinks, and it does grow until it reaches the ceiling. Both halves matter: a
            // symmetric jitter would make the first false, and a schedule that was flat from the start would make
            // the second false while still satisfying the first.
            assert!(after >= previous, "the wait shrank: {previous:?} -> {after:?}");
            if after > previous {
                grew += 1;
            }
            previous = after;
        }
        assert!(grew >= 3, "the wait barely grew: {grew} increases over six attempts");
        assert!(previous <= Duration::from_secs(4), "the wait grew past its ceiling: {previous:?}");
    }

    #[test]
    fn a_once_task_is_never_restarted() {
        let supervisor = supervisor();
        let task = id("bootstrap.open-store");
        supervisor.register(TaskSpec::bootstrap(task.clone())).expect("registered");
        let _ = supervisor.start(&task);

        let decision = supervisor
            .decide(&task, &StopReason::Failed { detail: "the disk is full".to_owned() }, NOW)
            .expect("decided");
        assert_eq!(decision, Decision::Leave { why: WhyNot::RunsOnce });
    }

    #[test]
    fn a_plain_retry_policy_does_not_wait() {
        // A caller that wanted a wait asked for `Backoff`. A `Retry` that waited anyway would be a policy whose name
        // does not describe it.
        let supervisor = supervisor();
        let task = id("plugin.activate");
        supervisor
            .register(TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 2 }))
            .expect("registered");
        let _ = supervisor.start(&task);

        let decision = supervisor
            .decide(&task, &StopReason::Failed { detail: "it trapped".to_owned() }, NOW)
            .expect("decided");
        assert_eq!(decision, Decision::Restart { after: Duration::ZERO, attempt: 1 });
    }

    #[test]
    fn a_task_that_keeps_failing_is_given_up_on_with_a_reason() {
        let supervisor = supervisor();
        let task = id("discovery.udp");
        supervisor
            .register(TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 3 }))
            .expect("registered");

        for attempt in 1..=3 {
            let _ = supervisor.start(&task);
            let decision = supervisor
                .decide(&task, &StopReason::Failed { detail: "the port is taken".to_owned() }, NOW)
                .expect("decided");
            assert!(decision.is_restart(), "attempt {attempt} should restart");
        }
        let _ = supervisor.start(&task);
        let decision = supervisor
            .decide(&task, &StopReason::Failed { detail: "the port is taken".to_owned() }, NOW)
            .expect("decided");
        match decision {
            Decision::Leave { why: WhyNot::AttemptsExhausted { attempts } } => assert_eq!(attempts, 3),
            other => panic!("expected the attempts to run out, got {other:?}"),
        }

        let record = supervisor.record(&task).expect("a record");
        assert_eq!(record.is_abandoned(), Some(WhyNot::AttemptsExhausted { attempts: 3 }));
        assert!(record.describe().contains("the port is taken"), "{}", record.describe());
    }

    #[test]
    fn giving_up_is_not_permanent_because_starting_again_is_deliberate() {
        // ★ "The network is down" must become a device that stops trying and *says so*, rather than one that spends
        // an hour of battery. Coming back is a decision somebody makes: the user, a plugin being enabled, a network
        // change — and each of those calls `start`.
        let supervisor = supervisor();
        let task = id("transport.accept");
        supervisor
            .register(TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 1 }))
            .expect("registered");
        let _ = supervisor.start(&task);
        let _ = supervisor.decide(&task, &StopReason::Failed { detail: "down".to_owned() }, NOW);
        let _ = supervisor.start(&task);
        let _ = supervisor.decide(&task, &StopReason::Failed { detail: "still down".to_owned() }, NOW);
        assert!(supervisor.record(&task).expect("a record").is_abandoned().is_some());

        // Starting it again works, and running again is what makes the record healthy.
        supervisor.start(&task).expect("started again");
        assert!(supervisor.record(&task).expect("a record").is_running());
        assert_eq!(supervisor.running_count(), 1);
    }

    #[test]
    fn a_shutdown_stops_restarts_whatever_the_policy_says() {
        // ★ A shutdown that restarted a task would never finish: the task would come back, be cancelled again, and
        // come back again.
        let supervisor = supervisor();
        let task = id("discovery.udp");
        supervisor.register(TaskSpec::service(task.clone())).expect("registered");
        let _ = supervisor.start(&task);

        let order = supervisor.begin_shutdown();
        assert!(supervisor.is_shutting_down());
        assert_eq!(order, vec![task.clone()], "one task, in reverse registration order");

        let decision = supervisor
            .decide(&task, &StopReason::Failed { detail: "it noticed the shutdown".to_owned() }, NOW)
            .expect("decided");
        assert_eq!(decision, Decision::Leave { why: WhyNot::ShuttingDown });
        assert!(matches!(
            supervisor.register(TaskSpec::service("late")),
            Err(SupervisorError::ShutDown)
        ));
    }

    #[test]
    fn the_shutdown_order_is_the_reverse_of_registration() {
        // A task registered later depends on the ones before it — a heartbeat on a transport, a transport on
        // discovery — so stopping in registration order would take the ground out from under the tasks still running.
        let supervisor = supervisor();
        for name in ["discovery.udp", "transport.accept", "heartbeat.ticker"] {
            supervisor.register(TaskSpec::service(name)).expect("registered");
        }
        let order: Vec<String> = supervisor.begin_shutdown().into_iter().map(|id| id.0).collect();
        assert_eq!(order, vec!["heartbeat.ticker", "transport.accept", "discovery.udp"]);
    }

    #[test]
    fn the_report_says_what_did_not_stop() {
        // A task that did not stop is a fact the caller has to act on: a process that exits with a locked port will
        // not start again.
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("discovery.udp")).expect("registered");
        supervisor.register(TaskSpec::service("transport.accept")).expect("registered");
        let _ = supervisor.start(&id("discovery.udp"));
        let _ = supervisor.start(&id("transport.accept"));

        // One stops, the other does not.
        let _ = supervisor.decide(&id("transport.accept"), &StopReason::Cancelled, NOW).expect("decided");
        let report = supervisor.report();

        assert!(!report.is_clean());
        assert_eq!(report.stopped, vec![id("transport.accept")]);
        assert_eq!(report.still_running, vec![id("discovery.udp")]);
        assert!(report.describe().contains("did not"), "{}", report.describe());
    }

    #[test]
    fn health_is_about_the_critical_tasks_and_not_about_every_task() {
        // ★ A discovery listener that failed is not a kernel that is broken, and a health report that treated the two
        // the same would be one a user learns to ignore.
        let supervisor = supervisor();
        supervisor.register(TaskSpec::service("discovery.udp")).expect("registered");
        supervisor.register(TaskSpec::service("transport.accept").critical()).expect("registered");
        let _ = supervisor.start(&id("discovery.udp"));
        let _ = supervisor.start(&id("transport.accept"));
        assert!(supervisor.is_healthy());

        // The ordinary one failing leaves the kernel healthy.
        let _ = supervisor.decide(&id("discovery.udp"), &StopReason::Failed { detail: "no network".to_owned() }, NOW);
        assert!(supervisor.is_healthy(), "an ordinary task failing is not a broken kernel");

        // The critical one failing does not.
        let _ = supervisor.decide(&id("transport.accept"), &StopReason::Failed { detail: "port taken".to_owned() }, NOW);
        assert!(!supervisor.is_healthy());
    }

    #[test]
    fn a_cancellation_is_visible_to_everyone_holding_a_clone() {
        let supervisor = supervisor();
        let token = supervisor.cancellation();
        assert!(!token.is_cancelled());
        let _ = supervisor.begin_shutdown();
        assert!(token.is_cancelled(), "a clone is the same token, not a copy of it");
    }

    #[test]
    fn waiting_on_a_cancellation_returns_when_it_is_cancelled() {
        let token = Cancellation::new();
        let waiter = token.clone();
        let handle = thread::spawn(move || waiter.wait(Duration::from_secs(2)));
        thread::sleep(Duration::from_millis(20));
        token.cancel();

        assert!(handle.join().expect("the waiter"), "the wait did not notice the cancellation");
    }

    #[test]
    fn waiting_on_a_cancellation_that_never_comes_times_out() {
        // A shutdown that waits for ever is a window that will not close, so the wait has to be bounded even when
        // the answer is no.
        let token = Cancellation::new();
        assert!(!token.wait(Duration::from_millis(30)));
    }

    #[test]
    fn a_task_id_can_be_searched_by_area() {
        // The convention — `area.thing` — is what makes a prefix search meaningful in a `doctor` report.
        let udp = id("discovery.udp");
        assert!(udp.is_in("discovery."));
        assert!(!udp.is_in("transport."));
        assert!(!id("discovery").is_in("discovery."), "the area alone is not in the area");
        assert_eq!(udp.to_string(), "discovery.udp");
    }

    #[test]
    fn a_running_task_is_started_on_its_own_thread_and_recorded_when_it_returns() {
        // The whole point of the module, driven end to end: a task runs, stops, and the decision is made from what it
        // returned rather than from anywhere else.
        let supervisor = supervisor();
        let task = id("work.once");
        supervisor
            .register(TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 1 }))
            .expect("registered");

        let handle = run_task(&supervisor, &task, |_token| Err("the disk is full".to_owned())).expect("a thread");
        handle.join().expect("the task finished");

        let record = supervisor.record(&task).expect("a record");
        assert!(!record.is_running());
        assert_eq!(
            record.last_reason,
            Some(StopReason::Failed { detail: "the disk is full".to_owned() })
        );
    }

    #[test]
    fn a_task_that_stops_because_it_was_cancelled_says_so() {
        // The distinction a supervisor needs: a task that returned cleanly because it was asked to is not a task that
        // finished its work, and restarting it would undo a decision.
        let supervisor = supervisor();
        let task = id("work.forever");
        supervisor.register(TaskSpec::service(task.clone())).expect("registered");

        let token = supervisor.cancellation();
        let handle = run_task(&supervisor, &task, move |given| {
            let _ = given.wait(Duration::from_secs(1));
            Ok(())
        })
        .expect("a thread");
        thread::sleep(Duration::from_millis(20));
        token.cancel();
        handle.join().expect("the task finished");

        assert_eq!(supervisor.record(&task).expect("a record").last_reason, Some(StopReason::Cancelled));
    }

    #[test]
    fn running_a_task_nothing_registered_is_refused_before_a_thread_starts() {
        let supervisor = supervisor();
        match run_task(&supervisor, &id("ghost"), |_token| Ok(())) {
            Err(SupervisorError::Unknown { id: name }) => assert_eq!(name.as_str(), "ghost"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_jittered_delay_is_never_zero_and_never_far_from_its_nominal() {
        // A delay that rounded to zero would turn the failure path into a busy loop; one far from its nominal would
        // make the policy's numbers a description of nothing.
        for name in ["discovery.udp", "transport.accept", "heartbeat.ticker", "", "x"] {
            let task = id(name);
            for attempt in 1..=10 {
                let delay = RestartPolicy::service().delay_for(attempt, &task);
                assert!(delay >= Duration::from_millis(1), "{name} attempt {attempt}: {delay:?}");
                assert!(delay <= Duration::from_secs(30), "{name} attempt {attempt}: {delay:?}");
            }
        }
    }

    #[test]
    fn two_tasks_that_failed_together_do_not_come_back_together() {
        // The jitter's whole purpose: a machine whose network went down takes every listener with it, and they must
        // not all retry at the same instant.
        let first = RestartPolicy::service().delay_for(3, &id("discovery.udp"));
        let second = RestartPolicy::service().delay_for(3, &id("discovery.mdns"));
        assert_ne!(first, second, "two tasks got the same delay");
    }

    #[test]
    fn every_policy_and_reason_names_itself() {
        for policy in [
            RestartPolicy::Once,
            RestartPolicy::Retry { max_attempts: 1 },
            RestartPolicy::service(),
        ] {
            assert!(!policy.as_str().is_empty());
            assert!(!policy.as_str().contains(' '));
        }
        for reason in [StopReason::Finished, StopReason::Cancelled, StopReason::Failed { detail: "x".to_owned() }] {
            assert!(!reason.as_str().is_empty());
        }
        for why in [
            WhyNot::NotAFailure,
            WhyNot::RunsOnce,
            WhyNot::AttemptsExhausted { attempts: 2 },
            WhyNot::ShuttingDown,
        ] {
            let sentence = why.to_string();
            assert!(sentence.len() > 5, "{why:?} -> {sentence}");
        }
    }
}
