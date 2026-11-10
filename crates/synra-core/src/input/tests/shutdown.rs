use super::*;

#[test]
fn deliberate_host_shutdown_waits_for_native_button_release() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    assert!(h.receiver.shutdown());
    assert_eq!(h.effects.lock().last(), Some(&Effect::Released));
    h.close();
}

#[test]
fn host_stop_releases_before_a_late_packet_can_execute() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    h.receiver.stop(accepted.session);
    // The receiver is polling without requiring a final message from the controller.
    assert_eq!(h.link.receive().unwrap().event.as_str(), wire::ERROR);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
}
