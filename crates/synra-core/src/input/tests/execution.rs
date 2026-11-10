use super::*;

#[test]
fn real_tcp_input_waits_for_consent_then_executes_in_order_and_releases() {
    let mut h = Harness::start();
    let accepted = h.approve();
    let commands = vec![
        Command::Move { dx: 4.0, dy: -3.0 },
        Command::LeftClick,
        Command::RightClick,
        Command::Scroll { dx: 0.0, dy: 40.0 },
        Command::LeftDown,
        Command::Move { dx: 2.0, dy: 0.0 },
        Command::LeftUp,
    ];
    assert_eq!(h.packet(&accepted, 1, commands.clone()), wire::ACK);
    let effects = Arc::clone(&h.effects);
    h.close();
    let expected: Vec<_> = [Effect::Created]
        .into_iter()
        .chain(commands.into_iter().map(Effect::Apply))
        .chain([Effect::Released])
        .collect();
    assert_eq!(*effects.lock(), expected);
}

#[test]
fn refusing_consent_never_initializes_native_input() {
    let mut h = Harness::start();
    let pending = h.pending();
    assert!(h.receiver.decide(pending.session, false));
    assert_eq!(h.link.receive().unwrap().event.as_str(), wire::ERROR);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert!(effects.lock().is_empty());
}

#[test]
fn cancelling_before_consent_removes_the_pending_request_without_input() {
    let h = Harness::start();
    let _ = h.pending();
    let receiver = Arc::clone(&h.receiver);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(receiver.snapshot().unwrap().phase, Phase::Ended);
    assert!(effects.lock().is_empty());
}

#[test]
fn a_replayed_click_is_refused_before_the_os_and_ends_the_session() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftClick]), wire::ACK);
    assert_eq!(
        h.packet(&accepted, 1, vec![Command::LeftClick]),
        wire::ERROR
    );
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(
        effects
            .lock()
            .iter()
            .filter(|effect| **effect == Effect::Apply(Command::LeftClick))
            .count(),
        1
    );
}
