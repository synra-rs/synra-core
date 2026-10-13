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

/// A deterministic pseudo-random source, for a fixture that must be reproducible.
///
/// Not a cryptographic generator and not pretending to be: a test failure has to be reproducible from its seed, so
/// the sequence must be a function of the seed and nothing else. A generator seeded from the clock is one whose
/// failure cannot be re-run.
#[derive(Debug, Clone)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// A generator from a seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        // A zero state is a fixed point of the mixing below, so it is replaced rather than accepted.
        Self { state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed } }
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        // splitmix64: the same mixing the reconnection jitter uses, so there is one generator in the codebase rather
        // than two that disagree about what "random" means.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A value below a bound, or zero when there is no room.
    #[must_use]
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    /// The seed this generator was built from.
    ///
    /// Reported so a failure can be re-run: a test that prints its seed is one whose failure is reproducible.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.state
    }
}

/// Forwards to the system allocator and tells the counter what happened.
pub struct CountingAllocator;

// SAFETY: every method forwards directly to `System`, which is the allocator that would have been used anyway. The
// counter's bookkeeping happens after the call and touches only a thread-local, so it neither changes the returned
// pointer or its size nor can fail.
unsafe impl core::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is this method's contract, forwarded unchanged.
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: core::alloc::Layout) {
        record_free();
        // SAFETY: the caller's contract for `dealloc` is this method's contract, forwarded unchanged. The layout is
        // the one the block was allocated with, which the caller guarantees.
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        // SAFETY: the caller's contract for `realloc` is this method's contract, forwarded unchanged.
        let new_pointer = unsafe { std::alloc::System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            // A realloc that moved counts as an allocation and the old block as a free, which is what a caller
            // measuring "did this grow" wants to see.
            record_allocation(new_size);
            record_free();
        }
        new_pointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allocator a test binary needs. A library cannot install one, so the counter's tests live in this crate —
    /// which is the same reason the crate exists.
    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    #[test]
    fn a_guard_of_nothing_allocating_counts_nothing() {
        // The property the hot paths are specified with, as a test that can actually be written.
        let (value, count) = CounterGuard::counted(|| 1 + 1);
        assert_eq!(value, 2);
        assert_eq!(count, AllocationCount::ZERO, "an addition allocated: {count}");
    }

    #[test]
    fn allocating_is_counted_when_the_counter_is_installed() {
        let guard = CounterGuard::install();
        assert!(CounterGuard::is_active());

        // Allocate something the optimiser cannot remove.
        let v: Vec<u8> = Vec::with_capacity(64);
        std::hint::black_box(&v);

        let count = guard.read();
        assert!(count.allocated_anything(), "a Vec::with_capacity was not counted");
        assert!(count.bytes >= 64, "the byte count is too small: {count}");
    }

    #[test]
    fn counting_is_off_outside_a_guard() {
        // Otherwise every test in the suite would count every other test's allocations, and the number would be
        // meaningless in exactly the situation these tests run in.
        assert!(!CounterGuard::is_active());
        let v: Vec<u8> = Vec::with_capacity(1_024);
        std::hint::black_box(&v);

        let guard = CounterGuard::install();
        // The guard's baseline is taken after that allocation, so it does not appear.
        assert_eq!(guard.read().allocations, 0);
    }

    #[test]
    fn nested_guards_each_report_their_own_scope() {
        // The outer guard's count includes the inner one's, and the inner one's does not include what came before it.
        let outer = CounterGuard::install();
        let before: Vec<u8> = Vec::with_capacity(10);
        std::hint::black_box(&before);

        let inner = CounterGuard::install();
        let inner_before = inner.read();
        let inside: Vec<u8> = Vec::with_capacity(20);
        std::hint::black_box(&inside);
        let inner_count = inner.read();
        assert!(
            inner_count.allocations > inner_before.allocations,
            "the inner guard saw nothing: {inner_count}"
        );

        // The outer guard is still counting after the inner one finishes.
        drop(inner);
        assert!(CounterGuard::is_active(), "the inner guard turned counting off");
        assert!(outer.read().allocations >= inner_count.allocations);
    }

    #[test]
    fn freeing_is_counted() {
        // A count of allocations alone cannot tell a leak from a churn, and the net is what a caller compares.
        let guard = CounterGuard::install();
        {
            let v: Vec<u8> = Vec::with_capacity(128);
            std::hint::black_box(&v);
        }
        let count = guard.read();
        assert!(count.frees > 0, "a dropped Vec was not counted as a free: {count}");
        assert!(count.net() < count.allocations as i64, "the net did not fall: {count}");
    }

    #[test]
    fn the_outermost_guard_turns_counting_off() {
        let guard = CounterGuard::install();
        assert!(CounterGuard::is_active());
        drop(guard);
        assert!(!CounterGuard::is_active());
        assert_eq!(CounterGuard::installed(), 0);
    }

    #[test]
    fn a_net_count_can_be_negative() {
        // Freeing memory allocated before the measurement is ordinary, and a `u64` subtraction would wrap to an
        // enormous positive number — the direction that hides a leak.
        let count = AllocationCount { allocations: 1, frees: 3, bytes: 10 };
        assert_eq!(count.net(), -2);
        assert_eq!(AllocationCount::ZERO.net(), 0);
    }

    #[test]
    fn a_count_displays_itself() {
        let count = AllocationCount { allocations: 2, frees: 1, bytes: 128 };
        let text = count.to_string();
        assert!(text.contains("2 allocation(s)"), "{text}");
        assert!(text.contains("128 bytes"), "{text}");
    }

    #[test]
    fn a_zero_budget_allows_only_nothing() {
        assert!(AllocationBudget::NONE.allows(AllocationCount::ZERO));
        assert!(!AllocationBudget::NONE.allows(AllocationCount { allocations: 1, frees: 0, bytes: 0 }));
        assert!(!AllocationBudget::NONE.allows(AllocationCount { allocations: 0, frees: 0, bytes: 1 }));
    }

    #[test]
    fn a_budget_explains_a_failure() {
        // The message is what an assertion prints, so it has to say what was measured rather than only that it was
        // too much.
        let budget = AllocationBudget::new(0, 0);
        let count = AllocationCount { allocations: 3, frees: 3, bytes: 96 };
        let message = budget.explain(count);
        assert!(message.contains("over budget"), "{message}");
        assert!(message.contains("3 allocation(s)"), "{message}");
        assert!(budget.explain(AllocationCount::ZERO).contains("within budget"));
    }

    #[test]
    fn the_same_seed_gives_the_same_sequence() {
        // A test failure has to be reproducible from its seed, so the sequence must be a function of the seed and
        // nothing else.
        let mut first = SeededRng::new(42);
        let mut second = SeededRng::new(42);
        for _ in 0..20 {
            assert_eq!(first.next_u64(), second.next_u64());
        }

        // And a different seed diverges.
        let mut other = SeededRng::new(43);
        assert_ne!(SeededRng::new(42).next_u64(), other.next_u64());
    }

    #[test]
    fn a_zero_seed_is_not_a_fixed_point() {
        // Zero is a fixed point of the mixing, so it is replaced rather than accepted — otherwise every test that
        // passed zero would get the same constant sequence and the generator would look broken in a way that is easy
        // to miss.
        let mut rng = SeededRng::new(0);
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(first, second);
        assert_ne!(first, 0);
    }

    #[test]
    fn a_bound_is_respected() {
        let mut rng = SeededRng::new(1);
        for _ in 0..1_000 {
            assert!(rng.below(10) < 10);
        }
        // A bound of zero has no room and gives zero rather than dividing by it.
        assert_eq!(rng.below(0), 0);
        assert_eq!(rng.below(1), 0);
    }

    #[test]
    fn the_generator_reports_its_state_for_a_re_run() {
        // A test that prints its seed is one whose failure is reproducible.
        assert_eq!(SeededRng::new(7).seed(), 7);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The generator's values are a function of its seed alone, for any seed and any number of draws. A generator
        /// that mixed in the clock would be one whose failure cannot be re-run.
        #[test]
        fn the_sequence_is_a_function_of_the_seed(seed in any::<u64>(), draws in 1usize..50) {
            let mut first = SeededRng::new(seed);
            let mut second = SeededRng::new(seed);
            for _ in 0..draws {
                prop_assert_eq!(first.next_u64(), second.next_u64());
            }
        }

        /// A bounded draw is always below its bound, and a bound of zero gives zero rather than dividing by it.
        #[test]
        fn a_bounded_draw_respects_its_bound(seed in any::<u64>(), bound in 0u64..10_000) {
            let mut rng = SeededRng::new(seed);
            for _ in 0..20 {
                let value = rng.below(bound);
                if bound == 0 {
                    prop_assert_eq!(value, 0);
                }
                else {
                    prop_assert!(value < bound);
                }
            }
        }

        /// A net count is the difference of the two counts, whatever they are. Computed in the signed domain, because
        /// a `u64` subtraction would wrap to an enormous positive number — the direction that hides a leak.
        #[test]
        fn a_net_count_is_the_difference(allocations in 0u64..1_000_000, frees in 0u64..1_000_000) {
            let count = AllocationCount { allocations, frees, bytes: 0 };
            prop_assert_eq!(count.net(), allocations as i64 - frees as i64);
        }

        /// A budget allows a count exactly when both limits are met, for any pair. An off-by-one here would let a hot
        /// path allocate one object per frame and pass.
        #[test]
        fn a_budget_allows_exactly_within_its_limits(
            limit_allocations in 0u64..100,
            limit_bytes in 0u64..10_000,
            allocations in 0u64..110,
            bytes in 0u64..11_000,
        ) {
            let budget = AllocationBudget::new(limit_allocations, limit_bytes);
            let count = AllocationCount { allocations, frees: 0, bytes };
            let expected = allocations <= limit_allocations && bytes <= limit_bytes;
            prop_assert_eq!(budget.allows(count), expected);
        }
    }
}
