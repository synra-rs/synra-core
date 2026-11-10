use super::*;

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
                TaskRecord {
                    spec,
                    restarts: 0,
                    running: false,
                    last_stop_ms: None,
                    last_reason: None,
                },
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
        let record = tasks
            .get_mut(id)
            .ok_or_else(|| SupervisorError::Unknown { id: id.clone() })?;
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
    pub fn decide(
        &self,
        id: &TaskId,
        reason: &StopReason,
        now_ms: i64,
    ) -> Result<Decision, SupervisorError> {
        let shutting_down = self.shutdown.is_cancelled();
        let mut tasks = self.tasks.lock();
        let record = tasks
            .get_mut(id)
            .ok_or_else(|| SupervisorError::Unknown { id: id.clone() })?;
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
        self.order
            .lock()
            .iter()
            .filter_map(|id| tasks.get(id))
            .cloned()
            .collect()
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
        ShutdownReport {
            stopped,
            still_running,
        }
    }
}
