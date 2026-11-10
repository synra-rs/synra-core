use synra_protocol::ids::{DeviceId, TransferId};

use super::super::*;
use super::{opened, plugin, session};

#[test]
fn a_chunk_from_another_round_is_refused() {
    // ★ The isolation rule. A chunk from a previous round has the same index and different bytes, and absorbing one
    // would corrupt the package in a way no digest catches until the end — or, worse, in a way it does.
    let mut opened = opened();
    match opened.absorb(&session("round-2"), 0) {
        Err(SyncError::WrongSession { theirs, ours }) => {
            assert_eq!(theirs, "round-2");
            assert_eq!(ours, "round-1");
        }
        other => panic!("expected a session refusal, got {other:?}"),
    }
    assert_eq!(opened.received(), 0, "nothing was absorbed");
}

#[test]
fn a_chunk_beyond_the_package_is_refused() {
    let mut opened = opened();
    match opened.absorb(&session("round-1"), 4) {
        Err(SyncError::ChunkOutOfRange { index, total }) => {
            assert_eq!(index, 4);
            assert_eq!(total, 4);
        }
        other => panic!("expected a range refusal, got {other:?}"),
    }
}

#[test]
fn a_session_with_no_chunks_is_not_a_session() {
    match SyncSession::open(
        session("empty"),
        plugin("@acme/chat"),
        DeviceId::new(),
        TransferId::new(),
        "1.0.0",
        "sha256-x",
        0,
    ) {
        Err(SyncError::NoChunks) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn chunks_are_counted_once_and_a_resend_is_not_an_error() {
    // A re-sent chunk is what a resumption *is*: a receiver that refused one would make a retry after a lost
    // acknowledgement look like corruption.
    let mut opened = opened();
    assert!(opened.absorb(&session("round-1"), 0).expect("a chunk"));
    assert!(
        !opened.absorb(&session("round-1"), 0).expect("a duplicate"),
        "the second is not new"
    );
    assert_eq!(opened.received(), 1);
    assert_eq!(opened.duplicates(), 1);

    let _ = opened.absorb(&session("round-1"), 3);
    assert_eq!(opened.missing(), vec![1, 2]);
    assert!(!opened.is_complete());
}

#[test]
fn a_complete_session_has_nothing_missing() {
    let mut opened = opened();
    for index in 0..4 {
        let _ = opened.absorb(&session("round-1"), index);
    }
    assert!(opened.is_complete());
    assert!(opened.missing().is_empty());
    assert_eq!(opened.received(), 4);
    assert_eq!(opened.declared_version(), "1.0.0");
    assert_eq!(opened.declared_digest(), "sha256-declared");
    assert_eq!(opened.plugin_id(), &plugin("@acme/chat"));
}

#[test]
fn a_transfer_declared_complete_with_a_hole_is_refused_and_names_the_hole() {
    // ★ "Complete" is the sender's claim, and the receiver's own count is what decides. A sender that skipped a chunk
    // would otherwise have its word taken for the package.
    let mut opened = opened();
    let _ = opened.absorb(&session("round-1"), 0);
    let _ = opened.absorb(&session("round-1"), 2);
    let _ = opened.absorb(&session("round-1"), 3);

    match opened.conclude("sha256-declared", "sha256-declared") {
        Err(SyncError::Incomplete { missing, indexes }) => {
            assert_eq!(missing, 1);
            assert_eq!(indexes, vec![1]);
        }
        other => panic!("expected an incomplete refusal, got {other:?}"),
    }
}

#[test]
fn a_tampered_package_is_refused_by_the_digest_the_receiver_computes() {
    // ★ The rule from the design document's security table: the receiving device checks the whole package's digest
    // itself. A device that trusted the sender's word about the bytes would be one where compromising a single
    // machine compromises every machine it can reach.
    let mut opened = opened();
    for index in 0..4 {
        let _ = opened.absorb(&session("round-1"), index);
    }
    // Every chunk arrived, and the assembled bytes are not what was promised: one chunk was substituted in transit.
    match opened.conclude("sha256-declared", "sha256-something-else") {
        Err(SyncError::DigestMismatch { declared, found }) => {
            assert_eq!(declared, "sha256-declared");
            assert_eq!(found, "sha256-something-else");
        }
        other => panic!("expected a digest refusal, got {other:?}"),
    }
    // And the same bytes as declared are accepted, so the check is not one that refuses everything.
    assert_eq!(
        opened.conclude("sha256-declared", "sha256-declared"),
        Ok(())
    );
}

#[test]
fn the_missing_list_is_in_order_so_a_retransmit_is_deterministic() {
    // The sender is asked for exactly these, and a list that reordered between reads would make two retransmits of the
    // same hole ask different questions.
    let mut opened = opened();
    let _ = opened.absorb(&session("round-1"), 2);
    assert_eq!(opened.missing(), vec![0, 1, 3]);
    assert_eq!(opened.missing(), vec![0, 1, 3]);
}
