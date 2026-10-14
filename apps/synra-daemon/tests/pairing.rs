//! The pairing decision, against a real database.
//!
//! # Why these use a database rather than a stub
//!
//! Because the two things that can go wrong here are a lookup that reads the wrong row and a decision that reads the
//! wrong column — and a stub would have neither. The interesting assertion is that a token written by `pair_device`
//! comes back as `Current` and one written for a different device does not, which only a real table can answer.

// An integration test is its own crate, so it does not inherit the relaxation the library sets for its `#[cfg(test)]`
// modules. The same reasoning applies: an `expect` that fires here is reporting a broken expectation, which is what a
// test is for.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use synra_daemon::state_for;
use synra_protocol::handshake::{LinkToken, PairingState};
use synra_protocol::ids::DeviceId;
use synra_store::SynraDb;

/// A migrated in-memory database.
fn db() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db
}

/// A token from a repeated byte, so two of them are obviously different.
fn token(byte: u8) -> LinkToken {
    LinkToken::from_bytes([byte; LinkToken::LEN])
}

/// A device identifier, which is a UUID and not a name: parsing rejects anything else.
fn device(text: &str) -> DeviceId {
    text.parse().expect("a valid device id")
}

/// Two identifiers that differ only in the last character, so a test cannot pass by matching the wrong row.
const DEVICE_A: &str = "01a139a9-8f3c-72ce-9c96-2b2c81f14551";
const DEVICE_B: &str = "01a139a9-8f3c-72ce-9c96-2b2c81f14552";

#[test]
fn a_dialler_with_no_token_is_asked_to_pair() {
    let db = db();
    assert_eq!(state_for(&db, device(DEVICE_A), None), PairingState::Unknown);
}

#[test]
fn a_dialler_whose_token_matches_is_trusted() {
    let db = db();
    let ours = token(0x11);
    db.pair_device(DEVICE_A, "Laptop", "windows", "[]", &ours.to_hex(), 1_000).expect("pairs");

    assert_eq!(state_for(&db, device(DEVICE_A), Some(&ours)), PairingState::Current);
    assert!(state_for(&db, device(DEVICE_A), Some(&ours)).is_trusted());
}

#[test]
fn a_dialler_whose_token_does_not_match_is_asked_to_pair_again() {
    let db = db();
    db.pair_device(DEVICE_A, "Laptop", "windows", "[]", &token(0x11).to_hex(), 1_000).expect("pairs");

    let state = state_for(&db, device(DEVICE_A), Some(&token(0x22)));
    assert_eq!(state, PairingState::Stale);
    assert!(!state.is_trusted(), "a token this device did not issue must never open a link");
}

#[test]
fn a_token_issued_to_another_device_does_not_open_this_one() {
    // The lookup is by device id, so the row for one device must not answer for another. A bug here would let a paired
    // peer's token open a link as a different device, which is the whole trust model failing.
    let db = db();
    let ours = token(0x33);
    db.pair_device(DEVICE_A, "Laptop", "windows", "[]", &ours.to_hex(), 1_000).expect("pairs");

    assert_eq!(state_for(&db, device(DEVICE_A), Some(&ours)), PairingState::Current);
    assert_eq!(state_for(&db, device(DEVICE_B), Some(&ours)), PairingState::Stale);
    assert_eq!(state_for(&db, device(DEVICE_B), None), PairingState::Unknown);
}
