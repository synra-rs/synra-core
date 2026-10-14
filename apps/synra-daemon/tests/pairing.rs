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

/// The whole chain: a pairing accepted through the session is one a later handshake recognises.
///
/// # Why this test exists on top of the two it crosses
///
/// Each half is tested where it lives — the session in `synra-core`, the decision here — and both passed while the token
/// they exchanged was fiction. What neither could check is that the value one writes is the value the other reads, in
/// the spelling the wire uses. That is exactly the seam where the column sat orphaned for a round: storage and lookup,
/// both correct, with nothing in between producing a real value.
#[test]
fn a_pairing_accepted_through_the_session_is_recognised_on_the_next_link() {
    use std::cell::RefCell;

    use synra_core::pairing::{Offer, PairingDesk};
    use synra_protocol::session::{PairRequest, PairResponse, PeerProfile, PlatformKind};
    use synra_store::SynraDb;

    let mut db = SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");

    // The dialer asks the shared desk, which is the path a real connection takes.
    let desk = PairingDesk::new(
        device(DEVICE_B),
        synra_protocol::session::SessionTimeouts::default().pairing,
    );
    let request_id = synra_protocol::ids::RequestId::new();
    let request = PairRequest {
        profile: PeerProfile {
            device_id: device(DEVICE_A),
            display_name: "Laptop".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "0.1.0".to_owned(),
        },
        user_hint: None,
    };
    let Offer::Waiting(waiter) = desk.offer(request_id, request, 1_000) else {
        panic!("it waits for a user");
    };

    // The user accepts, and the record is written where a later handshake will look for it. This is the same call the
    // transport will make, so the chain under test is the chain that runs.
    let written = RefCell::new(Vec::new());
    let answer = desk
        .answer(request_id, true, |record| {
            db.pair_device(
                &record.device_id.to_string(),
                &record.display_name,
                &record.platform.to_string(),
                "[]",
                &record.link_token,
                1_000,
            )
            .map_err(|error| error.to_string())?;
            written.borrow_mut().push(record.link_token.clone());
            Ok(())
        })
        .expect("an answer");

    // The connection blocked on the socket is released by the same decision, not by a second one.
    assert!(waiter.wait(std::time::Duration::from_millis(50)).accepted);
    assert!(answer.accepted, "the pairing was recorded, so it may be answered as accepted");
    let PairResponse { link_token, .. } = &answer;
    let issued = link_token.as_deref().expect("an acceptance issues a token");

    // What the dialer stores is what the answer carried, spelled as the wire spells it.
    let dialer_holds = LinkToken::from_hex(issued).expect("the issued token is hex");
    assert_eq!(
        state_for(&db, device(DEVICE_A), Some(&dialer_holds)),
        PairingState::Current,
        "the token issued at pairing must be the token a later link is trusted by"
    );

    // And a device that took part in none of this is still asked to pair.
    assert_eq!(state_for(&db, device(DEVICE_B), Some(&dialer_holds)), PairingState::Stale);
}

/// The code the two devices show is the same code.
///
/// # Why this is the test that matters for the prompt
///
/// The prompt exists so a user can tell that the device asking is the device they meant. That works only if the two
/// screens agree: a derivation that read the identifiers in a different order on each side would produce two different
/// codes for the same honest pair, and every user would be trained to ignore the difference — which is the same as having
/// no check at all.
#[test]
fn both_ends_of_a_pairing_derive_the_same_verification_code() {
    // The dialer computes it as (peer, self); the acceptor as (self, peer). Both must land on one string.
    let dialers_view = synra_core::pairing::verification_code(device(DEVICE_B), device(DEVICE_A));
    let acceptors_view = synra_core::pairing::verification_code(device(DEVICE_A), device(DEVICE_B));
    assert_eq!(dialers_view, acceptors_view, "the two screens must show one code");
}

/// A different device produces a different code.
///
/// This is what the code is *for*: a device on the same network that asks while claiming to be somebody else must not
/// produce the code the other screen shows.
#[test]
fn a_different_device_produces_a_different_verification_code() {
    let third = "01a139a9-8f3c-72ce-9c96-2b2c81f14553".parse::<DeviceId>().expect("a valid device id");

    let honest = synra_core::pairing::verification_code(device(DEVICE_A), device(DEVICE_B));
    let impostor = synra_core::pairing::verification_code(third, device(DEVICE_B));
    assert_ne!(honest, impostor);
}

/// The code is always six characters, lowercase, and never reads as a number.
#[test]
fn a_verification_code_is_six_characters_and_not_all_digits() {
    let code = synra_core::pairing::verification_code(device(DEVICE_A), device(DEVICE_B));
    assert_eq!(code.chars().count(), 6, "{code}");
    assert!(code.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{code}");
    assert!(
        code.chars().next().is_some_and(|c| c.is_ascii_alphabetic()),
        "a code that begins with a digit is one people drop: {code}"
    );
}

/// The prompt a pairing produces carries the code, so the interface has something to show.
#[test]
fn the_pending_request_carries_the_verification_code() {
    use synra_core::pairing::{Offer, PairingDesk};
    use synra_protocol::session::{PairRequest, PeerProfile, PlatformKind};

    let desk = PairingDesk::new(
        device(DEVICE_B),
        synra_protocol::session::SessionTimeouts::default().pairing,
    );
    let request_id = synra_protocol::ids::RequestId::new();
    let request = PairRequest {
        profile: PeerProfile {
            device_id: device(DEVICE_A),
            display_name: "Laptop".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "0.1.0".to_owned(),
        },
        user_hint: None,
    };
    assert!(matches!(desk.offer(request_id, request, 1_000), Offer::Waiting(_)));

    let pending = desk.request_of(request_id).expect("the request is waiting");
    assert_eq!(
        pending.verification_code,
        synra_core::pairing::verification_code(device(DEVICE_A), device(DEVICE_B)),
        "the code on the prompt is the code the other screen derives"
    );
    assert_eq!(pending.verification_code.chars().count(), 6);
}