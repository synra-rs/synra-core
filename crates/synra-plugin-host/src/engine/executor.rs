//! Where a plugin's code actually runs: a pool of threads that do nothing else.
//!
//! # The mistake this module exists to prevent
//!
//! Executing Wasm is a **blocking** call. It does not yield, it does not await, and a guest that loops forever or waits
//! inside a host function holds its thread for as long as the budget allows. Running that on an asynchronous runtime's
//! worker is therefore not a slow call — it is a call that stops *every other task* on the same worker, including the
//! timer that was supposed to end it.
//!
//! So Wasm runs here: on threads of this module's own, in a count the caller chooses, with a queue that is bounded and
//! a capacity that refuses rather than grows. The caller blocks on a channel; the runtime's workers stay free.
//!
//! # The two halves of an interruption
//!
//! A budget has an instruction count and a wall clock, and they are enforced by different mechanisms:
//!
//! * the count is the engine's, set on the store before the call;
//! * the clock needs something outside the guest to *notice* it, because a guest looping in pure arithmetic never gives
//!   the engine a chance to look at a timer. [`EpochTicker`] is that something: one thread, one atomic increment every
//!   ten milliseconds, and an engine that checks the counter at its own safepoints.
//!
//! The ticker is a long-lived service with a failure mode worth naming: if it stops, no wall-clock limit is ever
//! reached, so a plugin that blocks in a host call returns a call that never ends. It is therefore owned by whatever
//! owns the executor and reported through [`EpochTicker::is_running`] rather than being started and forgotten.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;

/// How often the epoch advances.
///
/// Ten milliseconds, which is the design document's number: it makes a timeout accurate to one tick, and a plugin call
/// is normally tens of milliseconds, so a finer tick would wake a thread for nothing. A coarser one would let a call
/// overrun its budget by a visible amount.
pub const EPOCH_PERIOD: Duration = Duration::from_millis(10);

/// The most threads an executor will start.
///
/// A ceiling rather than a validation: the concurrency an engine can usefully reach is bounded by cores, and a caller
/// asking for a thousand threads is a caller with a bug that would otherwise become a thousand stacks.
pub const MAX_THREADS: usize = 64;

/// The epoch a running engine checks its deadlines against.
///
/// Cheap to clone — an `Arc` and an atomic — because the store, the ticker and every instance hold one.
#[derive(Debug, Clone)]
pub struct Epoch {
    current: Arc<AtomicU64>,
}

impl Epoch {
    /// A new epoch at zero.
    #[must_use]
    pub fn new() -> Self {
        Self { current: Arc::new(AtomicU64::new(0)) }
    }

    /// The current value.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// Advances by one and returns the new value.
    pub fn advance(&self) -> u64 {
        self.current.fetch_add(1, Ordering::AcqRel).saturating_add(1)
    }

    /// The epoch value that is `after` from now.
    ///
    /// # Why this rounds up
    ///
    /// A deadline that lands *between* two ticks must be given the later one. Rounding down would shorten the budget by
    /// up to a whole tick, and rounding a one-tick budget down to "now" would make every such call fail immediately —
    /// which is the kind of bug that shows up as an intermittent timeout under load.
    #[must_use]
    pub fn deadline_in(&self, after: Duration) -> u64 {
        let ticks = after.as_nanos().div_ceil(EPOCH_PERIOD.as_nanos().max(1));
        let ticks = u64::try_from(ticks).unwrap_or(u64::MAX);
        self.now().saturating_add(ticks.max(1))
    }
}

impl Default for Epoch {
    fn default() -> Self {
        Self::new()
    }
}

/// A thread that advances an epoch until it is dropped.
///
/// # Why this is a type with a flag rather than a detached thread
///
/// Because the thread is what makes every wall-clock limit in the process work, and a thread that died leaves no trace:
/// the symptom is a call that never returns, minutes later, with nothing in the log. [`is_running`](Self::is_running)
/// is what a supervisor checks, and dropping the value is what stops it.
#[derive(Debug)]
pub struct EpochTicker {
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    epoch: Epoch,
    handle: Option<thread::JoinHandle<()>>,
}

impl EpochTicker {
    /// Starts a ticker over an epoch.
    ///
    /// The thread ends when the returned value is dropped, so a caller that forgets to keep it is a caller whose
    /// timeouts stop working — which is why the executor holds it rather than handing it out.
    #[must_use]
    pub fn start(epoch: Epoch) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let handle = {
            let epoch = epoch.clone();
            let stop = Arc::clone(&stop);
            let running = Arc::clone(&running);
            thread::Builder::new()
                .name("synra-epoch".to_owned())
                // A small stack: the thread has one thing to do, and this is a process that may already be running
                // several plugins on machines with a plugin memory ceiling of its own.
                .stack_size(64 * 1024)
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        thread::sleep(EPOCH_PERIOD);
                        let _ = epoch.advance();
                    }
                    // Cleared on the way out rather than by the drop: the flag is what a supervisor reads, and a
                    // ticker that cleared it after the join would report a live thread for as long as the join took.
                    running.store(false, Ordering::Release);
                })
        };

        match handle {
            Ok(handle) => Self { stop, running, epoch, handle: Some(handle) },
            Err(_) => {
                // A process that cannot start a thread has nothing left to degrade to: the caller learns by reading
                // `is_running`, and every timeout it asks for will be a budget the engine cannot enforce.
                running.store(false, Ordering::Release);
                Self { stop, running, epoch, handle: None }
            }
        }
    }

    /// Whether the ticker is advancing.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// The epoch it advances.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            // Joined rather than detached: a ticker outliving its owner would keep incrementing an epoch the owner's
            // instances are gone from, and a test that dropped one and started another would see two threads racing on
            // the same counter.
            let _ = handle.join();
        }
    }
}

/// A unit of work for the executor.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Why the executor would not take a job.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExecutorRefusal {
    /// Every thread is busy and the queue is at its capacity.
    ///
    /// Retryable, and deliberately a refusal rather than a wait: a caller with more concurrent plugin calls than the
    /// host has threads has found a limit it should surface, not queue behind indefinitely.
    #[error("all {threads} plugin threads are busy and {queued} calls are already waiting")]
    Saturated {
        /// How many threads exist.
        threads: usize,
        /// How many calls are waiting.
        queued: usize,
    },

    /// The pool has been shut down.
    #[error("the plugin executor has been shut down")]
    ShutDown,
}

/// A pool of threads that run plugin calls and nothing else.
///
/// # Why the queue is bounded
///
/// Because an unbounded one turns "the plugin is slow" into "the process ran out of memory holding work it will never
/// reach". The capacity is threads times the multiplier in [`ThreadPool::new`], which is a number the caller picks
/// knowing how long its calls take.
#[derive(Debug)]
pub struct ThreadPool {
    sender: Option<std::sync::mpsc::SyncSender<Job>>,
    threads: usize,
    capacity: usize,
}

impl ThreadPool {
    /// Starts a pool.
    ///
    /// `threads` is clamped to `1..=`[`MAX_THREADS`] rather than refused: a caller that asked for zero wanted no
    /// concurrency, and one thread is the smallest thing that can still run a call.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when a thread cannot be started. Returned rather than ignored because an executor with fewer
    /// threads than asked for has a concurrency the caller did not agree to.
    pub fn new(threads: usize, queue_per_thread: usize) -> Result<Self, std::io::Error> {
        let threads = threads.clamp(1, MAX_THREADS);
        let capacity = threads.saturating_mul(queue_per_thread.max(1));
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Job>(capacity);
        let receiver = Arc::new(Mutex::new(receiver));

        for index in 0..threads {
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("synra-plugin-{index}"))
                .spawn(move || {
                    loop {
                        // The lock is held only for the receive, and it is released before the job runs: a job that
                        // takes a second must not stop the other threads from taking work.
                        let job = {
                            let receiver = receiver.lock();
                            receiver.recv()
                        };
                        match job {
                            Ok(job) => job(),
                            // The sender is gone, which is the executor being dropped.
                            Err(_) => break,
                        }
                    }
                })?;
        }

        Ok(Self { sender: Some(sender), threads, capacity })
    }

    /// How many threads this pool has.
    #[must_use]
    pub const fn threads(&self) -> usize {
        self.threads
    }

    /// How many jobs may be waiting.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Runs a job and answers with its result.
    ///
    /// # Why the caller blocks here rather than at the join
    ///
    /// Because the value is what the caller came for, and a `JoinHandle` would make every caller write the same
    /// channel dance — with the failure mode of a dropped handle leaving a task nobody waits for.
    ///
    /// # Errors
    ///
    /// [`ExecutorRefusal::Saturated`] when the queue is full, and [`ExecutorRefusal::ShutDown`] afterwards.
    pub fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ExecutorRefusal> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<T>(1);
        let wrapper: Job = Box::new(move || {
            let produced = job();
            // Ignored: the only way the send fails is the caller having gone away, which is a cancellation rather than
            // a failure of the work.
            let _ = sender.send(produced);
        });

        let sender = self.sender.as_ref().ok_or(ExecutorRefusal::ShutDown)?;
        match sender.try_send(wrapper) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                return Err(ExecutorRefusal::Saturated { threads: self.threads, queued: self.capacity });
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Err(ExecutorRefusal::ShutDown),
        }

        receiver.recv().map_err(|_| ExecutorRefusal::ShutDown)
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        // Dropped first, which closes the channel: every thread finishes the job it holds and then leaves the loop,
        // rather than being killed mid-call with a plugin's state half-written.
        drop(self.sender.take());
    }
}

/// The pair of things a plugin call needs: threads to run on, and an epoch to be interrupted by.
///
/// # Why one type holds both
///
/// Because they fail together. A call with a wall-clock budget is only bounded if the epoch is advancing, so an
/// executor whose ticker died is an executor with fewer guarantees than it advertises — and a caller that had to
/// assemble the two would be a caller that could forget one.
#[derive(Debug)]
pub struct WasmExecutor {
    pool: ThreadPool,
    epoch: Epoch,
    ticker: Mutex<Option<EpochTicker>>,
}

impl WasmExecutor {
    /// Starts an executor with a ticker already running.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when a thread cannot be started.
    pub fn start(threads: usize, queue_per_thread: usize) -> Result<Self, std::io::Error> {
        let epoch = Epoch::new();
        let ticker = EpochTicker::start(epoch.clone());
        Ok(Self { pool: ThreadPool::new(threads, queue_per_thread)?, epoch, ticker: Mutex::new(Some(ticker)) })
    }

    /// The epoch, which every instance's store is given.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    /// Whether wall-clock limits are being enforced.
    ///
    /// False means the ticker is not running, so a `timeout` in a budget is a number nothing will act on. Checked by a
    /// host that is about to run untrusted code, and reported rather than assumed.
    #[must_use]
    pub fn enforces_timeouts(&self) -> bool {
        self.ticker.lock().as_ref().is_some_and(EpochTicker::is_running)
    }

    /// Stops the ticker, leaving the pool usable.
    ///
    /// Exists so a test can prove that a host notices: with timeouts no longer enforced, a call that asks for one must
    /// be reported as unbounded rather than run without its limit.
    pub fn stop_ticker(&self) {
        drop(self.ticker.lock().take());
    }

    /// How many threads the pool has.
    #[must_use]
    pub const fn threads(&self) -> usize {
        self.pool.threads()
    }

    /// Runs a plugin call on a pool thread and waits for it.
    ///
    /// # Errors
    ///
    /// [`ExecutorRefusal`] when every thread is busy and the queue is full.
    pub fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ExecutorRefusal> {
        self.pool.run(job)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[test]
    fn a_job_runs_on_another_thread_and_answers() {
        let executor = WasmExecutor::start(2, 4).expect("a pool");
        let caller = thread::current().id();
        let (answer, thread) = executor
            .run(move || (7_u32 * 6, thread::current().id()))
            .expect("a thread");
        assert_eq!(answer, 42);
        assert_ne!(thread, caller, "the job must not have run on the caller's thread");
    }

    #[test]
    fn the_epoch_advances_which_is_what_arms_a_deadline() {
        let executor = WasmExecutor::start(1, 1).expect("a pool");
        let before = executor.epoch().now();
        // Four ticks, so the sleep is the only thing that can move it. A ticker that never ran would leave this at
        // `before`, and every wall-clock budget in the process would be a number nothing acts on.
        thread::sleep(EPOCH_PERIOD * 4);
        assert!(executor.epoch().now() > before, "the ticker is not advancing");
        assert!(executor.enforces_timeouts());
    }

    #[test]
    fn a_deadline_lands_after_the_budget_and_never_at_once() {
        let epoch = Epoch::new();
        // A budget shorter than one tick still gets one tick: the alternative is a deadline of "now", which every call
        // fails against — the intermittent timeout that only shows up under load.
        assert_eq!(epoch.deadline_in(Duration::from_millis(1)), 1);
        assert_eq!(epoch.deadline_in(Duration::from_millis(10)), 1);
        // Rounded up, so a call given 11ms gets two ticks rather than 10ms.
        assert_eq!(epoch.deadline_in(Duration::from_millis(11)), 2);
        assert_eq!(epoch.deadline_in(Duration::from_millis(25)), 3);
    }

    #[test]
    fn stopping_the_ticker_is_visible() {
        let executor = WasmExecutor::start(1, 1).expect("a pool");
        assert!(executor.enforces_timeouts());
        executor.stop_ticker();
        // ★ The host asks this before running untrusted code. A value that stayed true after the ticker stopped would
        // make every timeout a budget with nothing behind it.
        assert!(!executor.enforces_timeouts());
        // And the pool is still usable, because a stopped ticker is a degraded executor rather than a dead one.
        assert_eq!(executor.run(|| 1_u8).expect("a thread"), 1);
    }

    #[test]
    fn the_pool_runs_more_than_one_job_at_a_time() {
        let executor = Arc::new(WasmExecutor::start(4, 8).expect("a pool"));
        let concurrent = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let executor = Arc::clone(&executor);
            let concurrent = Arc::clone(&concurrent);
            let peak = Arc::clone(&peak);
            handles.push(thread::spawn(move || {
                let _ = executor.run(move || {
                    let live = concurrent.fetch_add(1, Ordering::AcqRel) + 1;
                    peak.fetch_max(live, Ordering::AcqRel);
                    thread::sleep(Duration::from_millis(30));
                    concurrent.fetch_sub(1, Ordering::AcqRel);
                });
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
        // One thread would give a peak of 1 and still pass every other test here, so the concurrency is the assertion.
        assert!(peak.load(Ordering::Acquire) > 1, "the pool ran jobs one at a time");
    }

    #[test]
    fn a_saturated_pool_refuses_rather_than_queueing_for_ever() {
        // One thread, one queued job: the third call has nowhere to go, and the answer is a refusal the caller can
        // report rather than a wait with no bound.
        let executor = Arc::new(WasmExecutor::start(1, 1).expect("a pool"));
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let busy = {
            let executor = Arc::clone(&executor);
            thread::spawn(move || {
                let _ = executor.run(move || {
                    let _ = hold.recv();
                });
            })
        };
        // Long enough for the first job to take the only thread.
        thread::sleep(Duration::from_millis(50));
        // The second fills the queue.
        let queued = {
            let executor = Arc::clone(&executor);
            thread::spawn(move || executor.run(|| ()))
        };
        thread::sleep(Duration::from_millis(50));
        // The third is refused.
        let refused = executor.run(|| ());
        assert!(
            matches!(refused, Err(ExecutorRefusal::Saturated { threads: 1, .. })),
            "{refused:?}"
        );

        drop(release);
        let _ = busy.join();
        let _ = queued.join();
    }

    #[test]
    fn dropping_the_executor_lets_running_jobs_finish() {
        // A pool that killed its threads would leave a plugin's activation half-written, and the next start would read
        // whatever it found.
        let finished = Arc::new(AtomicBool::new(false));
        {
            let executor = WasmExecutor::start(2, 2).expect("a pool");
            let flag = Arc::clone(&finished);
            let _ = executor.run(move || {
                thread::sleep(Duration::from_millis(30));
                flag.store(true, Ordering::Release);
            });
        }
        assert!(finished.load(Ordering::Acquire), "the job did not run to completion");
    }
}
