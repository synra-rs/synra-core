use core::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use super::tests::tracker;
use super::{DeathReason, HeartbeatAction, LinkHealth};

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/liveness.txt"
        )))),
        ..ProptestConfig::default()
    })]
    /// Whatever the times, a link is never declared dead while something arrived within the timeout. The
    /// converse — declaring a live link dead — is the failure that costs a user their connection.
    #[test]
    fn a_link_is_never_declared_dead_early(
        start in 0u64..1_000,
        inbound in 0u64..1_000,
        check in 0u64..2_000,
    ) {
        let mut liveness = tracker(start);
        liveness.record_inbound(inbound);
        let timeout_ms = 250u64;

        if check.saturating_sub(inbound) < timeout_ms {
            prop_assert!(
                !matches!(liveness.poll(check), HeartbeatAction::DeclareDead(DeathReason::Silent { .. })),
                "declared dead at {} with the last frame at {}",
                check,
                inbound,
            );
        }
    }

    /// An inbound frame always moves the deadline forward, never backward. A frame that shortened the deadline
    /// would make a busy link more likely to be declared dead than an idle one.
    #[test]
    fn an_inbound_frame_never_shortens_the_deadline(
        start in 0u64..1_000,
        first in 0u64..1_000,
        second in 0u64..2_000,
    ) {
        let mut liveness = tracker(start);
        liveness.record_inbound(first);
        let after_first = liveness.dead_at_ms();
        liveness.record_inbound(second);
        let after_second = liveness.dead_at_ms();

        // The deadline only ever moves forward. A frame whose timestamp is earlier than an earlier frame's is a
        // defect in the caller's clock, and accepting it would make a link that just received a frame more
        // likely to be declared dead than one that did not.
        prop_assert!(after_second >= after_first);
        prop_assert_eq!(after_second, first.max(second).max(start).saturating_add(250));
        prop_assert_eq!(liveness.last_inbound_ms(), first.max(second).max(start));
    }

    /// Any queue depth below capacity is either healthy or merely congested, never an overflow. Reporting an
    /// overflow for a queue that has room would close working links.
    #[test]
    fn an_overflow_needs_a_full_queue(queued in 0usize..256, capacity in 1usize..=256) {
        let health = LinkHealth::classify(queued, capacity, 0, Duration::from_secs(1));
        if queued < capacity {
            prop_assert_ne!(health, LinkHealth::Overflow);
            prop_assert!(health.is_usable());
        }
        else {
            prop_assert_eq!(health, LinkHealth::Overflow);
            prop_assert!(health.should_close());
        }
    }
}
