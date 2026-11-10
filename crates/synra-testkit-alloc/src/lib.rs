//! A counting global allocator, so a performance claim can be a test rather than a hope.
//!
//! # Why this is a separate crate
//!
//! It contains the workspace's only `unsafe` code, and the workspace forbids `unsafe` everywhere else with a
//! `forbid`. `forbid` cannot be relaxed locally — that is the point of it — and a `deny` relaxed by a local `allow`
//! would put the exception somewhere a reader has to hunt for. So the exception is a crate, and its whole surface is
//! small enough to read in one sitting.
//!
//! What it does is forward every call to the system allocator and, if a counter is installed on this thread, record
//! that it happened. The forwarding is the entire unsafe surface: the contract is the caller's, passed through
//! unchanged.
//!
//! # Why the allocation counting belongs with the allocator
//!
//! The counter and the allocator have to agree about what a thread-local is and when it is on, and splitting them
//! across a crate boundary would mean either an API surface for that agreement or two copies of it. They are one
//! thing: a measurement, with the hook at one end and the guard at the other.
//!
//! # Why an application would not want this
//!
//! Two relaxed atomic operations per allocation. That is nothing for a test and not nothing for a frame loop, which
//! is why it is a fixture rather than a default. The counting is *off* unless a guard is installed, so the cost when
//! unused is the thread-local read and the branch.

#![warn(missing_docs)]

// The exception is declared in `Cargo.toml` rather than here, because a crate-root attribute cannot overrule a
// workspace `forbid` — the `[lints]` table is where the exception has to live, and putting it there makes it a
// property of this crate that is visible without opening a source file.

/// Records an allocation, if counting is on for this thread.
///
/// Called from the allocator, so it must not allocate and must not panic. Both hold: the thread-local is a
/// `RefCell` of integers and every operation saturates — an allocation counter that panicked inside the allocator
/// would abort the process with no output at all, which is the least debuggable failure there is.
pub fn record_allocation(bytes: usize) {
    COUNTERS.with(|counters| {
        // `try_borrow_mut` rather than `borrow_mut`: the allocator can be called while the counter is already
        // borrowed — formatting a value inside this function would do it — and panicking there is a process abort.
        if let Ok(mut counters) = counters.try_borrow_mut()
            && counters.active
        {
            counters.allocations = counters.allocations.saturating_add(1);
            counters.bytes = counters.bytes.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        }
    });
}

/// Records a free, if counting is on for this thread.
pub fn record_free() {
    COUNTERS.with(|counters| {
        if let Ok(mut counters) = counters.try_borrow_mut()
            && counters.active
        {
            counters.frees = counters.frees.saturating_add(1);
        }
    });
}

/// How many allocations were counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocationCount {
    /// The number of allocating calls.
    pub allocations: u64,
    /// The number of freeing calls.
    pub frees: u64,
    /// The total bytes requested, for the allocations that were counted.
    pub bytes: u64,
}

impl AllocationCount {
    /// Nothing was counted.
    pub const ZERO: Self = Self { allocations: 0, frees: 0, bytes: 0 };

    /// The net allocations, which may be negative for a scope that freed more than it allocated.
    ///
    /// Negative is ordinary rather than a defect: freeing memory that was allocated before the measurement started is
    /// exactly what a scope that drops a buffer does.
    #[must_use]
    pub const fn net(self) -> i64 {
        // Cast through `i64` deliberately: both counts are far below `i64::MAX` for any test, and a subtraction in
        // `u64` would wrap to an enormous positive number — the direction that hides a leak.
        (self.allocations as i64) - (self.frees as i64)
    }

    /// Whether anything was allocated.
    #[must_use]
    pub const fn allocated_anything(self) -> bool {
        self.allocations > 0
    }
}

impl core::fmt::Display for AllocationCount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} allocation(s), {} free(s), {} bytes",
            self.allocations, self.frees, self.bytes
        )
    }
}

/// The per-thread counters.
///
/// A thread-local rather than a global: a global counter would count the test harness's own allocations and every
/// other test running in parallel, which makes the number meaningless in exactly the situation these tests run in.
#[derive(Debug, Default)]
struct Counters {
    allocations: u64,
    frees: u64,
    bytes: u64,
    /// How deep the installation is, so a nested guard does not uninstall the outer one.
    depth: u32,
    /// Whether the counting is on.
    active: bool,
}

thread_local! {
    static COUNTERS: core::cell::RefCell<Counters> = const { core::cell::RefCell::new(Counters {
        allocations: 0,
        frees: 0,
        bytes: 0,
        depth: 0,
        active: false,
    }) };
}

/// A process-wide count of how many guards are installed, for a test asserting that nesting works.
static INSTALLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Counts allocations on this thread for as long as it lives.
///
/// # The counters are read from the guard, not from the allocator
///
/// The allocator is the only place that can see every allocation, and it cannot reach a guard's fields — so it
/// updates a thread-local and the guard reads it. The guard holds the *baseline* rather than the totals, which is
/// what lets two guards nest and each report its own scope.
#[derive(Debug)]
pub struct CounterGuard {
    allocations: u64,
    frees: u64,
    bytes: u64,
    /// Whether this guard was the one that turned counting on.
    installed: bool,
}

impl CounterGuard {
    /// Starts counting on this thread.
    #[must_use]
    pub fn install() -> Self {
        let (allocations, frees, bytes, installed) = COUNTERS.with(|counters| {
            let mut counters = counters.borrow_mut();
            let installed = !counters.active;
            counters.active = true;
            counters.depth = counters.depth.saturating_add(1);
            (counters.allocations, counters.frees, counters.bytes, installed)
        });
        if installed {
            INSTALLED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        Self { allocations, frees, bytes, installed }
    }

    /// Runs a closure and reports what it allocated.
    ///
    /// # The measurement is of this thread
    ///
    /// A closure that spawns a worker and returns reads zero for the worker's allocations, because the thread-local
    /// is per-thread. That is a limitation of the approach rather than of the closure, and it is why a test asserting
    /// "this allocates nothing" must not do the work on another thread.
    pub fn counted<T>(body: impl FnOnce() -> T) -> (T, AllocationCount) {
        let guard = Self::install();
        let value = body();
        let count = guard.read();
        (value, count)
    }

    /// What has been counted since this guard started.
    #[must_use]
    pub fn read(&self) -> AllocationCount {
        COUNTERS.with(|counters| {
            let counters = counters.borrow();
            AllocationCount {
                allocations: counters.allocations.saturating_sub(self.allocations),
                frees: counters.frees.saturating_sub(self.frees),
                bytes: counters.bytes.saturating_sub(self.bytes),
            }
        })
    }

    /// Whether counting is currently on for this thread.
    #[must_use]
    pub fn is_active() -> bool {
        COUNTERS.with(|counters| counters.borrow().active)
    }

    /// How many guards are installed across the process.
    #[must_use]
    pub fn installed() -> u64 {
        INSTALLED.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        COUNTERS.with(|counters| {
            let mut counters = counters.borrow_mut();
            counters.depth = counters.depth.saturating_sub(1);
            // Only the outermost guard turns counting off, so a nested guard's scope is included in its parent's.
            if counters.depth == 0 {
                counters.active = false;
            }
        });
        if self.installed {
            INSTALLED.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// How large a count must be to be worth reporting in a diagnostic bundle.
///
/// A test asserting a hot path allocates nothing uses this to say what it measured rather than only that it passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationBudget {
    /// The most allocations allowed.
    pub allocations: u64,
    /// The most bytes allowed.
    pub bytes: u64,
}

impl AllocationBudget {
    /// Nothing at all, for a hot path.
    pub const NONE: Self = Self { allocations: 0, bytes: 0 };

    /// A budget in allocations and bytes.
    #[must_use]
    pub const fn new(allocations: u64, bytes: u64) -> Self {
        Self { allocations, bytes }
    }

    /// Whether a count fits.
    #[must_use]
    pub const fn allows(self, count: AllocationCount) -> bool {
        count.allocations <= self.allocations && count.bytes <= self.bytes
    }

    /// Why a count did not fit, as a sentence for an assertion message.
    #[must_use]
    pub fn explain(self, count: AllocationCount) -> String {
        if self.allows(count) {
            return format!("within budget: {count}");
        }
        format!(
            "over budget: {count}, and the budget is {} allocation(s) and {} bytes",
            self.allocations, self.bytes
        )
    }
}

mod allocator;
mod rng;

pub use allocator::CountingAllocator;
pub use rng::SeededRng;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
