use super::*;

fn a_peer() -> DeviceId {
    DeviceId::new()
}

fn desk() -> Desk {
    Desk::new()
}

#[test]
fn a_new_desk_is_idle() {
    assert_eq!(desk().phase(), Phase::Idle);
}

#[test]
fn beginning_shows_a_code_and_waits() {
    let mut desk = desk();
    let peer = a_peer();
    let offer = desk
        .begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
        .expect("an empty desk accepts a request");
    assert_eq!(desk.phase(), Phase::Waiting);
    assert_eq!(offer.code, desk.offer().expect("an offer").code);
    assert_eq!(offer.peer, peer);
}

#[test]
fn a_second_request_is_refused_while_one_is_on_the_table() {
    let mut desk = desk();
    let now = Instant::now();
    desk.begin(a_peer(), "Pixel", PlatformKind::Android, false, now)
        .expect("first");
    assert_eq!(
        desk.begin(a_peer(), "Laptop", PlatformKind::Desktop, false, now),
        Err(Refused::Busy)
    );
}

#[test]
fn an_asking_peer_gets_a_desk_only_when_it_is_empty() {
    let mut desk = desk();
    let now = Instant::now();
    desk.begin(a_peer(), "Pixel", PlatformKind::Android, false, now)
        .expect("first");
    assert_eq!(
        desk.receive(
            PairCode::new(123_456).expect("in range"),
            a_peer(),
            "Laptop",
            PlatformKind::Desktop,
            false,
            now
        ),
        Err(Refused::Busy)
    );
}

#[test]
fn accepting_answers_with_the_peer_and_clears_the_desk() {
    let mut desk = desk();
    let peer = a_peer();
    let now = Instant::now();
    desk.receive(
        PairCode::new(42).expect("in range"),
        peer,
        "Laptop",
        PlatformKind::Desktop,
        false,
        now,
    )
    .expect("an empty desk");
    assert_eq!(desk.accept(), Ok(Outcome::Accepted { peer }));
    assert_eq!(desk.accept(), Err(Refused::NothingToAnswer));
}

#[test]
fn refusing_answers_without_recording_anything() {
    let mut desk = desk();
    let peer = a_peer();
    desk.receive(
        PairCode::new(42).expect("in range"),
        peer,
        "Laptop",
        PlatformKind::Desktop,
        false,
        Instant::now(),
    )
    .expect("an empty desk");
    assert_eq!(desk.refuse(), Ok(Outcome::Declined { peer }));
    assert_eq!(desk.accept(), Err(Refused::NothingToAnswer));
}

#[test]
fn only_the_initiator_can_cancel() {
    let mut desk = desk();
    let now = Instant::now();
    let peer = a_peer();
    assert_eq!(desk.cancel(), Err(Refused::NothingToAnswer));
    desk.receive(
        PairCode::new(1).expect("in range"),
        peer,
        "Laptop",
        PlatformKind::Desktop,
        false,
        now,
    )
    .expect("an empty desk");
    // The peer asked us, so we can refuse but not "cancel": cancelling is the initiator's move,
    // and pretending otherwise would send the other side a message it is not waiting for.
    assert_eq!(desk.cancel(), Err(Refused::NothingToAnswer));
    assert_eq!(desk.refuse(), Ok(Outcome::Declined { peer }));
}

#[test]
fn cancelling_after_beginning_answers_the_peer() {
    let mut desk = desk();
    let peer = a_peer();
    desk.begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
        .expect("an empty desk");
    assert_eq!(desk.cancel(), Ok(Outcome::Cancelled { peer }));
    assert_eq!(desk.phase(), Phase::Done);
}

#[test]
fn an_acceptance_completes_the_waiting_request() {
    let mut desk = desk();
    let peer = a_peer();
    desk.begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
        .expect("an empty desk");
    assert_eq!(desk.answered(true), Ok(Outcome::Completed { peer }));
}

#[test]
fn a_request_expires_after_its_ttl() {
    let mut desk = desk();
    let now = Instant::now();
    desk.begin(a_peer(), "Pixel", PlatformKind::Android, false, now)
        .expect("an empty desk");
    assert!(!desk.expire(now + Duration::from_secs(1)));
    assert!(desk.expire(now + PAIR_REQUEST_TTL));
    assert_eq!(desk.phase(), Phase::Idle);
}

#[test]
fn an_already_paired_peer_is_refused_before_a_code_is_wasted() {
    let mut desk = desk();
    let now = Instant::now();
    assert_eq!(
        desk.begin(a_peer(), "Pixel", PlatformKind::Android, true, now),
        Err(Refused::AlreadyPaired)
    );
    assert_eq!(
        desk.receive(
            PairCode::new(1).expect("in range"),
            a_peer(),
            "Pixel",
            PlatformKind::Android,
            true,
            now
        ),
        Err(Refused::AlreadyPaired)
    );
    assert_eq!(desk.phase(), Phase::Idle);
}
