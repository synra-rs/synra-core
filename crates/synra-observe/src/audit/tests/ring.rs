use super::*;

#[test]
fn the_ring_holds_records_in_time_order() {
    let ring_plugin = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(16);
    ring.record(entry(3_000, &ring_plugin, "device:list", AuditOutcome::Allowed));
    ring.record(entry(1_000, &ring_plugin, "device:list", AuditOutcome::Allowed));
    ring.record(entry(2_000, &ring_plugin, "device:list", AuditOutcome::Allowed));

    let times: Vec<i64> = ring.all().into_iter().map(|e| e.at_ms).collect();
    assert_eq!(times, vec![1_000, 2_000, 3_000]);
}

#[test]
fn the_ring_overwrites_the_oldest_when_full() {
    let ring_plugin = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(3);
    for index in 0..5i64 {
        ring.record(entry(index * 1_000, &ring_plugin, "device:list", AuditOutcome::Allowed));
    }

    assert_eq!(ring.len(), 3);
    assert_eq!(ring.evicted(), 2);
    let times: Vec<i64> = ring.all().into_iter().map(|e| e.at_ms).collect();
    assert_eq!(times, vec![2_000, 3_000, 4_000], "the newest three survive");
}

#[test]
fn a_full_ring_keeps_recording_in_order() {
    // More than one full wrap, so the write cursor's arithmetic is exercised rather than assumed.
    let ring_plugin = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(3);
    for index in 0..10i64 {
        ring.record(entry(index, &ring_plugin, "device:list", AuditOutcome::Allowed));
    }

    assert_eq!(ring.len(), 3);
    assert_eq!(ring.evicted(), 7);
    let times: Vec<i64> = ring.all().into_iter().map(|e| e.at_ms).collect();
    assert_eq!(times, vec![7, 8, 9]);
}

#[test]
fn a_zero_capacity_ring_counts_without_holding() {
    // A configuration that turns the audit view off must not silently report zero activity: the count is
    // what the plugin's page shows.
    let ring_plugin = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(0);
    for index in 0..4i64 {
        ring.record(entry(index, &ring_plugin, "device:list", AuditOutcome::Allowed));
    }

    assert!(ring.is_empty());
    assert_eq!(ring.evicted(), 4);
    assert_eq!(ring.count_for_plugin(&ring_plugin), 4);
}

#[test]
fn the_ring_separates_plugins() {
    let chat = plugin("@synra-plugin/chat");
    let notes = plugin("@synra-plugin/notes");
    let mut ring = AuditRing::with_capacity(16);

    ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
    ring.record(entry(2_000, &notes, "log:debug", AuditOutcome::Allowed));
    ring.record(entry(3_000, &chat, "network:fetch:api.github.com", AuditOutcome::Denied));

    assert_eq!(ring.for_plugin(&chat).len(), 2);
    assert_eq!(ring.for_plugin(&notes).len(), 1);
    assert_eq!(ring.count_for_plugin(&chat), 2);
    assert_eq!(ring.count_for_plugin(&notes), 1);
    assert_eq!(ring.count_for_plugin(&plugin("@synra-plugin/other")), 0);
}

#[test]
fn refusals_are_kept_apart_from_ordinary_records() {
    // The list the interface puts first: a refusal is the moment the capability system did its job.
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(16);

    ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
    ring.record(entry(2_000, &chat, "network:fetch:evil.com", AuditOutcome::Denied));
    ring.record(entry(3_000, &chat, "log:debug", AuditOutcome::Failed));
    ring.record(entry(4_000, &chat, "network:fetch:api.x.com", AuditOutcome::RateLimited));

    let refusals = ring.refusals_for_plugin(&chat);
    assert_eq!(refusals.len(), 2);
    assert_eq!(refusals[0].destination(), Some("evil.com"));
    assert_eq!(refusals[1].outcome, AuditOutcome::RateLimited);
    // A permitted call that then failed is not a refusal.
    assert!(!refusals.iter().any(|e| e.outcome == AuditOutcome::Failed));
}

#[test]
fn the_count_is_of_what_happened_not_of_what_is_held() {
    // A number that silently decreased as the ring wrapped would be worse than no number.
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(2);
    for index in 0..10i64 {
        ring.record(entry(index, &chat, "device:list", AuditOutcome::Allowed));
    }

    assert_eq!(ring.len(), 2, "only two are held");
    assert_eq!(ring.count_for_plugin(&chat), 10, "but ten happened");
}

#[test]
fn clearing_one_plugin_leaves_the_others() {
    let chat = plugin("@synra-plugin/chat");
    let notes = plugin("@synra-plugin/notes");
    let mut ring = AuditRing::with_capacity(16);
    ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
    ring.record(entry(2_000, &notes, "log:debug", AuditOutcome::Allowed));

    ring.clear_plugin(&chat);
    assert!(ring.for_plugin(&chat).is_empty());
    assert_eq!(ring.count_for_plugin(&chat), 0, "a cleared history reports no total");
    assert_eq!(ring.for_plugin(&notes).len(), 1, "another plugin is untouched");

    // And the ring still works afterwards.
    ring.record(entry(3_000, &notes, "log:info", AuditOutcome::Allowed));
    assert_eq!(ring.for_plugin(&notes).len(), 2);
}

#[test]
fn clearing_removes_everything() {
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(16);
    ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));
    ring.clear();

    assert!(ring.is_empty());
    assert_eq!(ring.count_for_plugin(&chat), 0);
}

#[test]
fn the_default_capacity_is_the_documented_one() {
    let ring = AuditRing::new();
    assert_eq!(ring.len(), 0);
    assert_eq!(MEMORY_CAPACITY, 10_000);
}
