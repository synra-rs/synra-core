use super::*;

/// ★ The check that gives the rest of this file its meaning.
///
/// Every other test here asserts a count of zero. This one requires a count to be **positive**, from a
/// construction that certainly allocates. If the allocator above stops being installed, this fails and the other
/// nine stop meaning anything — which is exactly the state this file was in when that line was added.
#[test]
fn the_counter_counts_an_allocation_that_definitely_happens() {
    warm_the_counter();

    warm_the_counter();
    let (built, count) = CounterGuard::counted(|| format!("{}", 1_234u32));

    assert_eq!(built, "1234", "the sample allocation must produce what it should");
    assert!(
        count.allocations > 0,
        "building a String allocated, and the counter reported {} — so every zero in this file proves nothing",
        count.allocations
    );
}
