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

use parking_lot::Mutex;

mod epoch;
mod pool;

pub use epoch::{EPOCH_PERIOD, Epoch, EpochTicker};
pub(super) use epoch::ticks_for;
#[cfg(test)]
pub(super) use epoch::next_tick;
pub use pool::{ExecutorRefusal, MAX_THREADS, ThreadPool};

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
    /// [`ExecutorRefusal::ThreadsUnavailable`] when a thread cannot be started.
    pub fn start(threads: usize, queue_per_thread: usize) -> Result<Self, ExecutorRefusal> {
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
mod tests;
