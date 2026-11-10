use super::*;

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
            self.still_running
                .iter()
                .map(TaskId::as_str)
                .collect::<Vec<&str>>()
                .join(", ")
        )
    }
}
