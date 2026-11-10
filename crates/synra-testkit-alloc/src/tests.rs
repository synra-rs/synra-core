use super::{AllocationBudget, AllocationCount, CounterGuard, CountingAllocator, SeededRng};

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
