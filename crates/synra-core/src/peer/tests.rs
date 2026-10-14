//! The peer layer's tests: a real dialer against a real acceptor, over a real loopback socket.
//!
//! The types here are the ones that cross the wire, so a test that stubbed the transport would be a test of the stub
//! - and the bug this layer can have is a mismatch between what one side writes and the other reads.

use std::net::{Ipv4Addr, TcpListener, TcpStream};

use synra_protocol::frame::{Frame, FrameDecoder, FrameError, FrameKind};
use synra_protocol::handshake::{
    Agreed, Feature, Hello, HelloAck, LinkToken, PROTOCOL_VERSION, PairingState, SessionNonce,
};
use synra_protocol::ids::DeviceId;
use synra_protocol::limits;
use synra_protocol::session::PlatformKind;

use super::config::Flags;
use super::errors::HandshakeError;
use super::host::LocalPeer;
use super::link::{accept, dial};
use super::negotiate::{Negotiated, agree};
use super::pairing::pairing_state;
use super::wire::{hello_ack_frame, hello_frame, json_payload, read_frame, write_frame};


fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

/// Two identifiers, so a test can name both ends.
const DIALER: &str = "11111111-1111-4111-8111-111111111111";
const ACCEPTOR: &str = "22222222-2222-4222-8222-222222222222";

fn peer(id: &str, name: &str, platform: PlatformKind) -> LocalPeer {
    LocalPeer::new(device(id), name, platform, "0.1.0-test")
}

/// A listener on a free loopback port.
fn listener() -> TcpListener {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds a loopback port")
}

// ── The two ends together ─────────────────────────────────────────────────────────────────────

#[test]
fn a_dialer_and_an_acceptor_complete_a_handshake() {
    // ★ The end-to-end test, on a real loopback socket. The types here are the ones that cross the wire, so a test
    // that stubbed the transport would be a test of the stub — and the bug this layer can have is a mismatch between
    // what one side writes and what the other reads.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
    });

    let (stream, negotiated) =
        dial(address, &theirs, None, 1, Flags::no_timeout()).expect("completes");
    drop(stream);
    let (_, accepted) = serving.join().expect("the thread finished").expect("accepts");

    // Each side learned the other.
    assert_eq!(negotiated.device_id, device(ACCEPTOR));
    assert_eq!(negotiated.display_name, "Laptop");
    assert_eq!(negotiated.platform, PlatformKind::Desktop);
    assert_eq!(accepted.device_id, device(DIALER));
    assert_eq!(accepted.display_name, "Phone");
    assert_eq!(accepted.platform, PlatformKind::Android);
}

#[test]
fn both_ends_agree_on_the_same_features() {
    // ★ The computation is the same on both sides, and a dialer and an acceptor that disagreed would each believe a
    // different set is available — with the failure landing at the first transfer that used one of them.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
    });
    let (stream, mine) = dial(address, &theirs, None, 1, Flags::no_timeout()).expect("completes");
    drop(stream);
    let (_, theirs_side) = serving.join().expect("finished").expect("accepts");

    assert_eq!(mine.agreed, theirs_side.agreed);
    assert!(mine.is_usable());
    assert!(!mine.agreed.common.is_empty(), "no features in common");
}

#[test]
fn the_dialers_token_is_offered_to_the_acceptor() {
    // ★ The pairing decision is the acceptor's, and it is made from the token the dialer presented. A layer that
    // dropped the token would make every reconnection look like a first connection, and every pairing would be
    // re-prompted.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);
    let token = LinkToken::from_bytes([7u8; LinkToken::LEN]);
    let offered = token.clone();

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), move |seen, _| {
            // The assertion is inside the acceptor, because the token only exists there.
            assert_eq!(seen, Some(&offered), "the token did not arrive");
            PairingState::Current
        })
    });
    let (stream, negotiated) =
        dial(address, &theirs, Some(token), 1, Flags::no_timeout()).expect("completes");
    drop(stream);
    serving.join().expect("finished").expect("accepts");

    // And the dialer learns how its token was read, which is what tells it whether the pairing survived.
    assert_eq!(negotiated.pairing, Some(PairingState::Current));
}

#[test]
fn an_acceptor_reports_no_pairing_state_because_it_decided_it() {
    // The `pairing` field is the dialer's to read: the acceptor made the decision, so it has nothing to learn.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
    });
    let (stream, _) = dial(address, &theirs, None, 1, Flags::no_timeout()).expect("completes");
    drop(stream);
    let (_, accepted) = serving.join().expect("finished").expect("accepts");
    assert_eq!(accepted.pairing, None);
}

#[test]
fn a_peer_that_hangs_up_before_saying_hello_is_reported_as_closed() {
    // ★ The ordinary shape of a port scan and of a user who closed a laptop. A caller that could not tell it from a
    // decode error would log a fault for every scan.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
    });

    // A connection that sends nothing and closes.
    let probe = TcpStream::connect(address).expect("connects");
    drop(probe);

    match serving.join().expect("finished") {
        Err(HandshakeError::Closed) => {}
        other => panic!("expected a closed connection, got {other:?}"),
    }
}

#[test]
fn a_dialer_that_reaches_a_socket_that_says_nothing_reports_closed_rather_than_waiting() {
    // The other direction: a listener that accepts and does nothing. With a timeout the dialer gives up; the
    // assertion here uses the closed path, because `TcpStream` on a loopback cannot be made to time out reliably.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accepts");
        // Say nothing, then close.
        drop(stream);
    });

    match dial(address, &theirs, None, 1, Flags::no_timeout()) {
        Err(HandshakeError::Closed) => {}
        other => panic!("expected a closed connection, got {other:?}"),
    }
    serving.join().expect("finished");
}

#[test]
fn a_hello_that_is_not_a_hello_is_refused() {
    // A peer that opens with the wrong frame is one this exchange cannot continue with, and the message names what
    // was expected.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
    });

    let mut stream = TcpStream::connect(address).expect("connects");
    write_frame(&mut stream, &Frame::empty(FrameKind::Ping)).expect("writes");

    match serving.join().expect("finished") {
        Err(HandshakeError::Unexpected { expected, .. }) => assert_eq!(expected, "Hello"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_hello_carrying_an_unreasonable_endpoint_list_is_refused() {
    // ★ The announcement is attacker-controlled input, and an unbounded endpoint list would be an unbounded amount
    // of dialling on this device's behalf. The validation is what bounds it.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout(), |_, _| PairingState::Unknown)
    });

    let mut stream = TcpStream::connect(address).expect("connects");
    let mut hello = peer(DIALER, "Phone", PlatformKind::Android).hello(SessionNonce::random(), 1);
    hello.endpoints = (0..Hello::MAX_ENDPOINTS + 4).map(|i| format!("10.0.0.{i}:47100")).collect();
    write_frame(&mut stream, &hello_frame(&hello).expect("encodes"))
        .expect("writes");

    match serving.join().expect("finished") {
        Err(HandshakeError::Invalid { why }) => assert!(!why.is_empty()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_refusal_from_the_acceptor_reaches_the_dialer() {
    // A refusal is a complete answer, and the dialer reports it rather than building a session on a declined link.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut decoder = FrameDecoder::new();
        let _ = read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello");
        // A refusal, which the protocol says is a complete answer in itself.
        let ack = HelloAck::refuse(
            device(ACCEPTOR),
            "Laptop",
            PlatformKind::Desktop,
            "0.1.0-test",
            SessionNonce::random(),
            synra_protocol::handshake::RefusalReason::Malformed,
        );
        write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
            .expect("writes");
    });

    match dial(address, &theirs, None, 1, Flags::no_timeout()) {
        Err(HandshakeError::Refused { reason }) => assert!(!reason.is_empty()),
        other => panic!("expected a refusal, got {other:?}"),
    }
    serving.join().expect("finished");
}

#[test]
fn an_ack_echoing_a_different_nonce_is_refused() {
    // ★ The nonce ties an answer to the attempt that asked for it. An answer carrying a different one is a recorded
    // or mis-routed message, and continuing would build a session on a reply to somebody else's question.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut decoder = FrameDecoder::new();
        let _ = read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello");
        // A fresh nonce rather than the one that arrived.
        let ack = ours.hello_ack(SessionNonce::random(), PairingState::Unknown, 1);
        write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
            .expect("writes");
    });

    match dial(address, &theirs, None, 1, Flags::no_timeout()) {
        Err(HandshakeError::NonceMismatch) => {}
        other => panic!("expected a nonce mismatch, got {other:?}"),
    }
    serving.join().expect("finished");
}

#[test]
fn an_ack_naming_a_different_protocol_is_refused() {
    // A peer speaking another version is refused here rather than failing on the third message with a decode error
    // about a field neither end can name.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut decoder = FrameDecoder::new();
        let hello: Hello =
            json_payload(&read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello"), "Hello")
                .expect("reads");
        let mut ack = ours.hello_ack(hello.nonce, PairingState::Unknown, 1);
        ack.protocol = PROTOCOL_VERSION + 1;
        write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
            .expect("writes");
    });

    match dial(address, &theirs, None, 1, Flags::no_timeout()) {
        Err(HandshakeError::VersionMismatch { theirs, ours }) => {
            assert_eq!(theirs, PROTOCOL_VERSION + 1);
            assert_eq!(ours, PROTOCOL_VERSION);
        }
        other => panic!("expected a version mismatch, got {other:?}"),
    }
    serving.join().expect("finished");
}

// ── Feature agreement ─────────────────────────────────────────────────────────────────────────

#[test]
fn features_in_common_are_the_intersection() {
    let ours = LocalPeer {
        features: vec![Feature::EventStream, Feature::ClipboardSync],
        requires: Vec::new(),
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[]);
    assert_eq!(agreed.common, vec![Feature::EventStream]);
    assert!(agreed.is_usable());
}

#[test]
fn a_required_feature_the_peer_lacks_is_reported() {
    // Our own requirement.
    let ours = LocalPeer {
        requires: vec![Feature::TransferResume],
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[], &[]);
    assert_eq!(agreed.missing_required, vec![Feature::TransferResume]);
    assert!(!agreed.is_usable());
}

#[test]
fn a_required_feature_the_peer_needs_and_we_lack_is_reported_too() {
    // ★ Both directions. A link where the peer requires something we lack is as unusable as the reverse — and a
    // check that looked only at our own list would let us start work the peer will refuse.
    let ours = LocalPeer {
        features: vec![Feature::EventStream],
        requires: Vec::new(),
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[Feature::PluginMirroring]);
    assert_eq!(agreed.missing_required, vec![Feature::PluginMirroring]);
    assert!(!agreed.is_usable());
}

#[test]
fn a_requirement_both_sides_meet_is_not_missing() {
    let ours = LocalPeer {
        features: vec![Feature::EventStream],
        requires: vec![Feature::EventStream],
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[Feature::EventStream]);
    assert!(agreed.missing_required.is_empty());
    assert!(agreed.is_usable());
}

#[test]
fn a_requirement_is_reported_once_even_when_both_sides_name_it() {
    // Two entries for one feature would make a report say a link is missing two things when it is missing one.
    let ours = LocalPeer {
        features: vec![Feature::EventStream],
        requires: vec![Feature::PluginMirroring],
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[Feature::PluginMirroring]);
    assert_eq!(agreed.missing_required, vec![Feature::PluginMirroring]);
}

#[test]
fn an_announcement_carries_the_port_it_was_given() {
    // ★ The port is the **connection** port, and this type does not hold it. A `LocalPeer` that guessed would
    // announce a port nothing is listening on — a device that appears in every list and cannot be connected to.
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let announcement = ours.announcement(47_100);
    assert_eq!(announcement.port, 47_100);
    assert_eq!(announcement.device_id, device(ACCEPTOR));
    assert_eq!(announcement.display_name, "Laptop");
    assert_eq!(announcement.platform, Some(PlatformKind::Desktop));
    assert_eq!(announcement.protocol, PROTOCOL_VERSION);
}

#[test]
fn an_announcement_passes_the_protocols_own_validation() {
    // The announcement is encoded and broadcast, and the receiving end validates it. One this build produces that
    // its own parser refuses would be a device that can never be found.
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    assert!(ours.announcement(47_100).validate().is_ok());
}

#[test]
fn the_default_features_are_the_protocols_own_catalogue() {
    // ★ A build that forgot to announce a feature it implements would be one whose peers decline to use it, and
    // nothing would say why. Asserted against the catalogue so the two cannot drift.
    assert_eq!(LocalPeer::default_features(), Feature::ALL.to_vec());
    assert!(!LocalPeer::default_features().is_empty());
}

#[test]
fn a_local_peer_builds_a_hello_and_an_ack_that_agree_with_each_other() {
    // The two messages carry the same facts, so a field set in one and not the other is a peer that looks different
    // depending on which end dialled.
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let nonce = SessionNonce::random();
    let hello = ours.hello(nonce, 3);
    let ack = ours.hello_ack(nonce, PairingState::Unknown, 3);

    assert_eq!(hello.device_id, ack.device_id);
    assert_eq!(hello.display_name, ack.display_name);
    assert_eq!(hello.platform, ack.platform);
    assert_eq!(hello.app_version, ack.app_version);
    assert_eq!(hello.protocol, ack.protocol);
    assert_eq!(hello.nonce, ack.nonce);
    assert_eq!(hello.sequence, ack.sequence);
    assert_eq!(hello.features, ack.features);
}

// ── Flags ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_production_flags_use_the_protocols_hello_timeout() {
    // The timeout is the protocol's constant rather than a figure chosen here, so a link is abandoned at the moment
    // every other part of the kernel believes it should be.
    assert_eq!(Flags::production().timeout, Some(limits::HELLO_TIMEOUT));
    assert_eq!(Flags::no_timeout().timeout, None);
    assert_eq!(Flags::default(), Flags::production());
}

// ── Errors ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_error_explains_itself() {
    let errors = [
        HandshakeError::Transport { why: "reset".to_owned() },
        HandshakeError::Closed,
        HandshakeError::Frame(FrameError::Poisoned),
        HandshakeError::Unexpected {
            expected: "Hello",
            found: "Ping".to_owned(),
        },
        HandshakeError::Payload { message: "Hello", why: "missing field".to_owned() },
        HandshakeError::VersionMismatch { theirs: 9, ours: 1 },
        HandshakeError::Refused { reason: "busy".to_owned() },
        HandshakeError::NonceMismatch,
        HandshakeError::Invalid { why: "too many endpoints".to_owned() },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And the version mismatch names both, because "incompatible" alone leaves a user with nothing.
    let text = errors[5].to_string();
    assert!(text.contains('9') && text.contains('1'), "{text}");
}

#[test]
fn a_negotiated_link_knows_whether_it_is_usable() {
    let usable = Negotiated {
        device_id: device(DIALER),
        display_name: "P".to_owned(),
        platform: PlatformKind::Android,
        app_version: "0.1.0".to_owned(),
        agreed: Agreed { common: vec![Feature::EventStream], missing_required: Vec::new() },
        pairing: None,
    };
    assert!(usable.is_usable());

    let unusable = Negotiated {
        agreed: Agreed { common: Vec::new(), missing_required: vec![Feature::TransferResume] },
        ..usable
    };
    assert!(!unusable.is_usable());
}


// ── Which pairing state a token produces ──────────────────────────────────────────────────────

/// A token built from a repeated byte, so two distinct tokens are obviously distinct.
fn token(byte: u8) -> LinkToken {
    LinkToken::from_bytes([byte; LinkToken::LEN])
}

#[test]
fn a_token_that_matches_the_record_is_current() {
    let stored = token(0x11).to_hex();
    assert_eq!(pairing_state(Some(&stored), Some(&token(0x11))), PairingState::Current);
    assert!(pairing_state(Some(&stored), Some(&token(0x11))).is_trusted());
}

#[test]
fn a_token_that_does_not_match_the_record_is_stale_rather_than_refused() {
    // The distinction matters to a user: "pair again" is an action, "refused" is not.
    let stored = token(0x11).to_hex();
    let state = pairing_state(Some(&stored), Some(&token(0x22)));
    assert_eq!(state, PairingState::Stale);
    assert!(state.needs_pairing());
    assert!(!state.is_trusted(), "a token this device did not issue must never open a link");
}

#[test]
fn a_token_with_no_record_at_all_is_stale() {
    // One device was reset or reinstalled while the other still believed the pair existed. Reporting it lets the dialer
    // re-pair, which is the only thing the user can act on.
    let state = pairing_state(None, Some(&token(0x11)));
    assert_eq!(state, PairingState::Stale);
    assert!(!state.is_trusted());
}

#[test]
fn a_link_with_no_token_is_a_first_time_pairing() {
    assert_eq!(pairing_state(None, None), PairingState::Unknown);
    // And a record this device holds does not make a tokenless dialler trusted: it presented nothing to compare.
    let stored = token(0x11).to_hex();
    assert_eq!(pairing_state(Some(&stored), None), PairingState::Unknown);
    assert!(!pairing_state(Some(&stored), None).is_trusted());
}

#[test]
fn the_stored_token_is_compared_without_regard_to_case() {
    // The column holds lowercase hex and `to_hex` produces lowercase, so the case only matters for a record written by
    // hand. Accepting either is cheaper than a rule about which is correct.
    let upper = token(0xab).to_hex().to_uppercase();
    assert_eq!(pairing_state(Some(&upper), Some(&token(0xab))), PairingState::Current);
}

#[test]
fn an_empty_stored_token_never_matches() {
    // The shape a half-written row would have. `Stale` is the safe answer: it asks the user to pair again rather than
    // trusting a record that says nothing.
    assert_eq!(pairing_state(Some(""), Some(&token(0x11))), PairingState::Stale);
}

#[test]
fn a_token_round_trips_through_hex() {
    // The comparison above is text-based, so the text has to survive the round trip that puts a token in the database.
    let original = token(0x5a);
    let parsed = LinkToken::from_hex(&original.to_hex()).expect("a hex token parses back");
    assert_eq!(parsed, original);
    assert_eq!(pairing_state(Some(&original.to_hex()), Some(&parsed)), PairingState::Current);
}
