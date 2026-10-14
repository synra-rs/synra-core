//! The schema module's property tests.

use super::*;
use proptest::prelude::*;
proptest! {
    /// Whatever version is recorded, the result is either a usable state with the right pending steps or a
    /// refusal. No version produces a state that claims to be usable and lists steps backwards.
    #[test]
    fn a_recorded_version_always_yields_a_coherent_state(recorded in proptest::option::of(0u32..20)) {
        let state = schema_state(recorded);
        match state {
            SchemaState::Empty => {
                prop_assert!(state.is_usable());
                prop_assert_eq!(state.pending().len(), MIGRATIONS.len());
            }
            SchemaState::At { version } => {
                prop_assert!(state.is_usable());
                prop_assert!(version <= latest_version());
                // Every pending step is above the recorded version, and the set is contiguous up to the
                // latest — a gap would mean a shape nobody defined.
                let pending: Vec<u32> = state.pending().iter().map(|m| m.version).collect();
                let expected: Vec<u32> = ((version + 1)..=latest_version()).collect();
                prop_assert_eq!(pending, expected);
            }
            SchemaState::Newer { found, known } => {
                prop_assert!(!state.is_usable());
                prop_assert!(found > known);
                prop_assert!(state.pending().is_empty());
            }
        }
    }

    /// Applying is idempotent in the sense that matters: running it twice from the version it reached runs
    /// nothing the second time. A migration that ran twice would fail on the second device that resumed.
    #[test]
    fn applying_twice_runs_nothing_the_second_time(from in 0u32..=5) {
        let first = apply(Some(from), &mut |_| Ok(())).expect("applies");
        let mut second_count = 0usize;
        let second = apply(Some(first.version), &mut |_| {
            second_count += 1;
            Ok(())
        })
        .expect("applies");

        prop_assert_eq!(second_count, 0);
        prop_assert!(!second.changed_anything());
        prop_assert_eq!(second.version, latest_version());
    }

    /// The statement count an application runs matches the steps it reports, so the outcome cannot claim to
    /// have applied a migration whose statements never ran.
    #[test]
    fn the_reported_versions_match_the_statements_that_ran(from in 0u32..=5) {
        let mut count = 0usize;
        let outcome = apply(Some(from), &mut |_| {
            count += 1;
            Ok(())
        })
        .expect("applies");

        let expected: usize = outcome
            .applied
            .iter()
            .filter_map(|version| MIGRATIONS.iter().find(|m| m.version == *version))
            .map(|migration| migration.statements.len())
            .sum();
        prop_assert_eq!(count, expected);
    }
}
