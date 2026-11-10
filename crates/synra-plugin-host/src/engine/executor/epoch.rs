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

/// Converts a timeout to whole ticks, rounding up and allowing at least one tick.
pub(in crate::engine) fn ticks_for(timeout: Duration) -> u64 {
    let period = EPOCH_PERIOD.as_nanos().max(1);
    let ticks = timeout.as_nanos().div_ceil(period);
    u64::try_from(ticks).unwrap_or(u64::MAX).max(1)
}

/// Something to run whenever the epoch moves, given the new value.
///
/// A named alias rather than the type written out in the field, because `clippy::type_complexity` is right about one
/// thing: `Arc<Mutex<Vec<Arc<dyn Fn(u64) + Send + Sync>>>>` is a sentence nobody parses on the first read, and the name
/// is the part that says why it is nested this way — shared, locked, many, and callable from the ticker's thread.
type Observer = Arc<dyn Fn(u64) + Send + Sync>;

/// The epoch a running engine checks its deadlines against.
///
/// Cheap to clone — an `Arc` and an atomic — because the store, the ticker and every instance hold one.
///
/// # ★ Why this carries observers
///
/// Because the counter alone was never enough, and the gap was invisible from both ends.
///
/// [`Epoch::advance`] moved *this* counter. The wasmtime engine has a counter of its own, and it is the one a deadline
/// is actually measured against — it only moves when `Engine::increment_epoch` is called. Nothing called it: at the time
/// this was written the name appeared nowhere in the workspace. So the store was told "your deadline is tick 25", the
/// ticker moved `Epoch` from 0 to 25 over a quarter of a second, and wasmtime's own counter stayed at zero forever. A
/// guest blocked inside a host call — consuming no instructions, so fuel never runs out — could not be interrupted by
/// anything, which is the one thing this layer exists to do.
///
/// The tests did not catch it because they watched `Epoch::now`, the counter that *was* moving. The seam between the two
/// counters had no test on either side of it.
///
/// An observer is how an engine says "when the epoch moves, move this too", so there is one counter to advance and the
/// engine cannot be left behind by an advance that forgot about it.
#[derive(Clone)]
pub struct Epoch {
    current: Arc<AtomicU64>,
    /// Called on every advance, with the new value.
    ///
    /// Behind the same lock as the push, and never called while it is held — an observer that registered another
    /// observer would otherwise deadlock a thread that is holding the lock its own registration needs.
    observers: Arc<Mutex<Vec<Observer>>>,
}

impl std::fmt::Debug for Epoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The observers are closures, which have no useful `Debug`. Their number is the part a reader needs: a ticker
        // advancing an epoch with no observers is the shape of the bug this type was changed to make impossible.
        formatter
            .debug_struct("Epoch")
            .field("now", &self.now())
            .field("observers", &self.observers.lock().len())
            .finish()
    }
}

impl Epoch {
    /// A new epoch at zero.
    #[must_use]
    pub fn new() -> Self {
        Self { current: Arc::new(AtomicU64::new(0)), observers: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Registers something to move whenever this epoch moves.
    ///
    /// The observer is called with the new value, on the thread that advanced the epoch.
    pub fn observe(&self, observer: impl Fn(u64) + Send + Sync + 'static) {
        let mut observers = self.observers.lock();
        // A no-op if the lock is already held by this thread would be a lost observer, which is the failure being
        // prevented. `parking_lot::Mutex` is not reentrant, so a caller that reached here from inside an observer would
        // deadlock rather than lose it — which is why `advance` does not hold the lock while calling them.
        observers.push(Arc::new(observer));
    }

    /// The current value.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// Advances by one and returns the new value.
    pub fn advance(&self) -> u64 {
        let next = self.current.fetch_add(1, Ordering::AcqRel).saturating_add(1);

        // The observers are copied out and the lock released before any of them runs. An observer that called back into
        // this epoch — registering another, or reading `now` — would deadlock a non-reentrant lock, and the cost of
        // avoiding it is one `Arc` clone per observer per tick.
        let observers: Vec<_> = self.observers.lock().clone();
        for observer in observers {
            observer(next);
        }

        next
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
        self.now().saturating_add(ticks_for(after))
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


/// Observe the next actual tick with a channel that cannot block the ticker.
#[cfg(test)]
pub(in crate::engine) fn next_tick(epoch: &Epoch) -> std::sync::mpsc::Receiver<u64> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    epoch.observe(move |tick| {
        let _ = sender.try_send(tick);
    });
    receiver
}
