use proptest::prelude::*;

use super::{Claim, HEARTBEAT_STALE_AFTER_MS, LOCK_FORMAT_VERSION, LockError, LockFile, LockOwner, decide};

proptest! {
    /// A heartbeat is live exactly when its age is below the threshold, for any pair of readings. The boundary is
    /// where this goes wrong in practice, and one millisecond of disagreement is a daemon that will not start or
    /// two that do.
    #[test]
    fn a_heartbeat_is_live_exactly_below_the_threshold(beat in 0u64..1_000_000, now in 0u64..2_000_000) {
        let owner = LockOwner {
            pid: 1,
            version: "0".to_owned(),
            claimed_at_ms: 0,
            heartbeat_ms: beat,
            clean: false,
        };
        let age = now.saturating_sub(beat);
        prop_assert_eq!(owner.heartbeat_age_ms(now), age);
        prop_assert_eq!(owner.is_live(now), age < HEARTBEAT_STALE_AFTER_MS);
    }

    /// Whatever the previous claim's state, a decision either lets this instance run or refuses it — never
    /// neither, and never both. A decision that returned `Held` for a stale owner is two daemons over one
    /// database; one that reclaimed a live owner is the same.
    #[test]
    fn a_decision_agrees_with_liveness(
        version in 0u32..4,
        beat in 0u64..200_000,
        now in 0u64..400_000,
    ) {
        let file = LockFile {
            version,
            owner: LockOwner {
                pid: 1,
                version: "0".to_owned(),
                claimed_at_ms: 0,
                heartbeat_ms: beat,
                clean: false,
            },
        };
        let decision = decide(Some(&file), now, "/lock");

        if version > LOCK_FORMAT_VERSION {
            prop_assert!(
                matches!(decision, Err(LockError::FromTheFuture { .. })),
                "{:?}",
                decision.err(),
            );
            return Ok(());
        }

        let claim = decision.expect("a readable lock decides");
        let live = file.owner.is_live(now);
        // A claim marked clean is one nobody owns, whatever its heartbeat says: staleness across two processes is
        // not decidable from a timestamp, which is why the flag exists.
        prop_assert_eq!(claim.may_run(), file.owner.clean || !live);
        match claim {
            Claim::Held { .. } => prop_assert!(live, "held a stale claim"),
            Claim::Reclaimed { .. } => prop_assert!(!live, "reclaimed a live claim"),
            Claim::Clean { .. } => prop_assert!(true),
            Claim::Taken => prop_assert!(false, "an existing lock was reported as absent"),
        }
    }
}
