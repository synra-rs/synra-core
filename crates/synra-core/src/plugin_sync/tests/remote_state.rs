use synra_protocol::ids::DeviceId;

use super::super::*;
use super::{plugin, theirs};

#[test]
fn the_table_says_what_each_device_has() {
    let mut table = SyncTable::new();
    assert!(table.is_empty());
    let laptop = DeviceId::new();
    let phone = DeviceId::new();
    table.record(laptop, theirs("1.0.0", "a"));
    table.record(phone, RemoteState::absent(plugin("@acme/chat")));

    assert_eq!(table.len(), 2);
    assert_eq!(
        table
            .state_of(&plugin("@acme/chat"), laptop)
            .and_then(|state| state.version.as_deref()),
        Some("1.0.0")
    );
    assert!(
        table
            .state_of(&plugin("@acme/chat"), phone)
            .is_some_and(|state| !state.has_it())
    );
    assert_eq!(table.for_plugin(&plugin("@acme/chat")).len(), 2);
    assert!(table.for_plugin(&plugin("@other/thing")).is_empty());
}

#[test]
fn recording_a_device_twice_replaces_what_was_known() {
    // A device's version changes, and the table is a cache of the last thing it said.
    let mut table = SyncTable::new();
    let laptop = DeviceId::new();
    table.record(laptop, theirs("1.0.0", "a"));
    table.record(laptop, theirs("1.1.0", "b"));

    assert_eq!(table.len(), 1);
    assert_eq!(
        table
            .state_of(&plugin("@acme/chat"), laptop)
            .and_then(|state| state.version.as_deref()),
        Some("1.1.0")
    );
}

#[test]
fn a_record_says_what_happened_and_why() {
    let peer = DeviceId::new();
    let pushed = SyncRecord::new(
        plugin("@acme/chat"),
        peer,
        SyncAction::Push {
            why: "the other device does not have this plugin".to_owned(),
        },
        1_000,
    );
    assert!(pushed.describe().contains("push"), "{}", pushed.describe());
    assert!(
        pushed.describe().contains("does not have"),
        "{}",
        pushed.describe()
    );
    assert_eq!(pushed.started_at_ms, 1_000);

    let asked = SyncRecord::new(
        plugin("@acme/chat"),
        peer,
        SyncAction::Ask {
            ours: "1.0.0".to_owned(),
            theirs: None,
        },
        1_000,
    );
    assert!(asked.describe().contains("ask"), "{}", asked.describe());
    assert!(asked.describe().contains("nothing"), "{}", asked.describe());
}

#[test]
fn every_refusal_explains_itself() {
    let refusals = [
        SyncError::WrongSession {
            theirs: "round-2".to_owned(),
            ours: "round-1".to_owned(),
        },
        SyncError::ChunkOutOfRange { index: 9, total: 4 },
        SyncError::NoChunks,
        SyncError::DigestMismatch {
            declared: "sha256-a".to_owned(),
            found: "sha256-b".to_owned(),
        },
        SyncError::Incomplete {
            missing: 2,
            indexes: vec![1, 3],
        },
    ];
    for refusal in &refusals {
        let sentence = refusal.to_string();
        assert!(sentence.len() > 20, "{refusal:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
    }
    assert!(refusals[0].to_string().contains("round-2"));
    assert!(refusals[3].to_string().contains("sha256-b"));
}
