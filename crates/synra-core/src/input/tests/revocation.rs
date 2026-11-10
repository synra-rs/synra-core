use super::*;

#[test]
fn revocation_releases_a_drag_even_without_more_phone_input() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    h.policy.revision.fetch_add(1, Ordering::AcqRel);
    assert_eq!(h.link.receive().unwrap().event.as_str(), wire::ERROR);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
}

#[test]
fn a_quiet_but_open_tcp_connection_cannot_keep_a_drag_held() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    let response = h.link.receive().unwrap();
    assert_eq!(response.event.as_str(), wire::ERROR);
    assert!(
        wire::read::<String>(&response)
            .unwrap()
            .contains("lease expired")
    );
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
}
