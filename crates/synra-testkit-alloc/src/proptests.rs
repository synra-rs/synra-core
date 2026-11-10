use proptest::prelude::*;

use super::{AllocationBudget, AllocationCount, SeededRng};

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
