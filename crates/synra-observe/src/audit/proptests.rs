use synra_capability::Capability;
use synra_protocol::PluginId;

use super::*;
use proptest::prelude::*;

fn arbitrary_outcome() -> impl Strategy<Value = AuditOutcome> {
    prop::sample::select(vec![
        AuditOutcome::Allowed,
        AuditOutcome::Denied,
        AuditOutcome::QuotaExceeded,
        AuditOutcome::RateLimited,
        AuditOutcome::Failed,
    ])
}

fn arbitrary_capability_text() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "log:debug",
        "device:list",
        "device:send:@pc",
        "network:fetch:api.github.com",
        "network:fetch:api.x.com:POST",
        "fs:read:/data/**",
        "platform:open-url",
    ])
}

proptest! {
    /// The ring never holds more than its capacity, and never loses a record it has not overwritten. An
    /// unbounded audit buffer is a memory leak with the user's own data in it.
    #[test]
    fn the_ring_stays_within_its_capacity(
        capacity in 0usize..16,
        records in proptest::collection::vec((0i64..1000, arbitrary_capability_text(), arbitrary_outcome()), 0..50),
    ) {
        let plugin = PluginId::parse("@synra-plugin/chat").expect("valid");
        let mut ring = AuditRing::with_capacity(capacity);
        for (at_ms, capability, outcome) in &records {
            ring.record(AuditEntry::new(
                *at_ms,
                plugin.clone(),
                Capability::parse(capability).expect("valid"),
                *outcome,
                None,
            ));
        }

        prop_assert!(ring.len() <= capacity);
        prop_assert_eq!(ring.len() + ring.evicted() as usize, records.len());
        prop_assert_eq!(ring.count_for_plugin(&plugin), records.len() as u64);
    }

    /// Every refusal recorded for a plugin is a refusal, and no refusal is kept out. The list is what the
    /// user reads to find out that something was blocked.
    #[test]
    fn refusals_are_exactly_the_refused_records(
        outcomes in proptest::collection::vec(arbitrary_outcome(), 0..30),
    ) {
        let plugin = PluginId::parse("@synra-plugin/chat").expect("valid");
        let mut ring = AuditRing::with_capacity(64);
        let mut expected = 0usize;
        for (index, outcome) in outcomes.iter().enumerate() {
            if outcome.is_refusal() {
                expected += 1;
            }
            ring.record(AuditEntry::new(
                index as i64,
                plugin.clone(),
                Capability::parse("device:list").expect("valid"),
                *outcome,
                None,
            ));
        }

        let refusals = ring.refusals_for_plugin(&plugin);
        prop_assert_eq!(refusals.len(), expected);
        prop_assert!(refusals.iter().all(|entry| entry.outcome.is_refusal()));
    }

    /// Records come back in time order whatever order they arrived in. A UI that showed them shuffled
    /// would make a sequence of events unreadable, which is the one thing the trail is for.
    #[test]
    fn records_replay_in_time_order(
        times in proptest::collection::vec(0i64..10_000, 1..40),
    ) {
        let plugin = PluginId::parse("@synra-plugin/chat").expect("valid");
        let mut ring = AuditRing::with_capacity(64);
        for at_ms in &times {
            ring.record(AuditEntry::new(
                *at_ms,
                plugin.clone(),
                Capability::parse("device:list").expect("valid"),
                AuditOutcome::Allowed,
                None,
            ));
        }

        let ordered = ring.all();
        prop_assert_eq!(ordered.len(), times.len());
        prop_assert!(ordered.windows(2).all(|pair| pair[0].at_ms <= pair[1].at_ms));
    }

    /// A record survives the wire format with every field intact. The trail is written by the kernel and
    /// read by the interface, and anything lost in between is a call the user cannot see.
    #[test]
    fn records_round_trip(
        at_ms in 0i64..2_000_000_000_000,
        capability in arbitrary_capability_text(),
        outcome in arbitrary_outcome(),
    ) {
        let record = AuditEntry::new(
            at_ms,
            PluginId::parse("@synra-plugin/chat").expect("valid"),
            Capability::parse(capability).expect("valid"),
            outcome,
            Some(1),
        );
        let json = serde_json::to_string(&record).expect("serialises");
        let back: AuditEntry = serde_json::from_str(&json).expect("deserialises");
        prop_assert_eq!(back, record);
    }
}
