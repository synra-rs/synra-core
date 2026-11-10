use super::*;

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
