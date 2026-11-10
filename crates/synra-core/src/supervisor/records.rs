use std::time::Duration;

use super::{Criticality, RestartPolicy, TaskId};

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
        Self {
            id: id.into(),
            restart: RestartPolicy::service(),
            criticality: Criticality::Ordinary,
        }
    }

    /// A task that runs once, such as a bootstrap step.
    #[must_use]
    pub fn bootstrap(id: impl Into<TaskId>) -> Self {
        Self {
            id: id.into(),
            restart: RestartPolicy::Once,
            criticality: Criticality::Critical,
        }
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
                Some(WhyNot::AttemptsExhausted {
                    attempts: self.restarts,
                })
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
pub(super) fn decide_for(
    record: &mut TaskRecord,
    reason: &StopReason,
    shutting_down: bool,
    id: &TaskId,
) -> Decision {
    if !reason.is_failure() {
        return Decision::Leave {
            why: WhyNot::NotAFailure,
        };
    }
    if shutting_down {
        // ★ Checked before the policy, because a shutdown that restarted a task would never finish: the task would
        // come back, be cancelled again, and come back again.
        return Decision::Leave {
            why: WhyNot::ShuttingDown,
        };
    }
    let policy = record.spec.restart;
    if !policy.restarts() {
        return Decision::Leave {
            why: WhyNot::RunsOnce,
        };
    }
    let attempt = record.restarts.saturating_add(1);
    if attempt > policy.max_attempts() {
        return Decision::Leave {
            why: WhyNot::AttemptsExhausted {
                attempts: record.restarts,
            },
        };
    }

    record.restarts = attempt;
    Decision::Restart {
        after: policy.delay_for(attempt, id),
        attempt,
    }
}
