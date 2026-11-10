use std::sync::Arc;
use std::thread;

use parking_lot::Mutex;

/// The most threads an executor will start.
///
/// A ceiling rather than a validation: the concurrency an engine can usefully reach is bounded by cores, and a caller
/// asking for a thousand threads is a caller with a bug that would otherwise become a thousand stacks.
pub const MAX_THREADS: usize = 64;

/// A unit of work for the executor.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Why the executor would not take a job.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExecutorRefusal {
    /// A thread could not be started.
    ///
    /// # Why this is not `std::io::Error`
    ///
    /// Because this crate is semi-stable, and a public signature naming a foreign error is a promise about *that*
    /// crate's version: a `std::io::Error` that gained a variant, or changed what its `kind` reports, would be a
    /// breaking change to this crate's API without this crate having changed a line. The detail is kept as a string —
    /// which the stability rules allow precisely here, for a foreign failure that this side cannot act on differently.
    #[error("a plugin thread could not be started: {detail}")]
    ThreadsUnavailable {
        /// What the operating system said.
        detail: String,
    },

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
    /// [`ExecutorRefusal::ThreadsUnavailable`] when a thread cannot be started. Returned rather than ignored because an
    /// executor with fewer threads than asked for has a concurrency the caller did not agree to.
    pub fn new(threads: usize, queue_per_thread: usize) -> Result<Self, ExecutorRefusal> {
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
                })
                // The operating system's reason is kept as a *string*, which is what the stability rules ask for: a
                // foreign error in a public signature would be a promise about another crate's version.
                .map_err(|error| ExecutorRefusal::ThreadsUnavailable { detail: error.to_string() })?;
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
