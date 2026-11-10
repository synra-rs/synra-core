use super::*;

#[test]
fn an_expectation_holds_when_the_frame_was_sent() {
    let pair = pair();
    pair.send(Side::Near, envelope("device.hello")).expect("sends");
    assert_eq!(check(&pair, &[Expectation::event(Side::Near, "device.hello")]), Ok(()));
}

#[test]
fn a_missing_expectation_names_what_was_expected() {
    // A failure message that says "the predicate was false" sends a reader looking for the predicate.
    let pair = pair();
    match check(&pair, &[Expectation::event(Side::Near, "device.hello")]) {
        Err(ExpectationError::NeverArrived { from, expected }) => {
            assert_eq!(from, "near");
            assert_eq!(expected, "device.hello");
        }
        other => panic!("expected a missing expectation, got {other:?}"),
    }
}

#[test]
fn a_wrong_event_is_distinguished_from_a_missing_frame() {
    // The usual cause of a failed handshake assertion: the frame arrived and carried something else.
    let pair = pair();
    pair.send(Side::Near, envelope("device.bye")).expect("sends");
    match check(&pair, &[Expectation::event(Side::Near, "device.hello")]) {
        Err(ExpectationError::WrongEvent { found, expected, .. }) => {
            assert_eq!(found, "device.bye");
            assert_eq!(expected, "device.hello");
        }
        other => panic!("expected a wrong event, got {other:?}"),
    }
}

#[test]
fn every_expectation_is_checked_in_order() {
    let pair = pair();
    pair.send(Side::Near, envelope("a")).expect("sends");
    pair.send(Side::Near, envelope("b")).expect("sends");
    assert_eq!(
        check(
            &pair,
            &[Expectation::event(Side::Near, "a"), Expectation::event(Side::Near, "b")]
        ),
        Ok(())
    );

    // The failure names the envelope that *did* arrive, because that is the usual cause of a failed handshake
    // assertion: the frame came and carried something else. A test wanting "no envelope at all" asserts against an
    // empty record, which is the case below.
    match check(
        &pair,
        &[Expectation::event(Side::Near, "a"), Expectation::event(Side::Near, "missing")],
    ) {
        Err(ExpectationError::WrongEvent { found, expected, .. }) => {
            assert_eq!(found, "a", "the message should name what arrived");
            assert_eq!(expected, "missing");
        }
        other => panic!("expected the second to fail, got {other:?}"),
    }

    // And with nothing recorded at all, the failure is that nothing arrived — a different message, and the
    // difference is what tells a reader whether the handshake did not happen or happened differently. Built
    // inline rather than through `pair()`, because the local binding has shadowed that function's name.
    let nothing_recorded = KernelPair::with_clock(|_clock, _link| {
        (FakeKernel { name: "near" }, FakeKernel { name: "far" })
    });
    match check(&nothing_recorded, &[Expectation::event(Side::Near, "anything")]) {
        Err(ExpectationError::NeverArrived { expected, .. }) => assert_eq!(expected, "anything"),
        other => panic!("expected a missing frame, got {other:?}"),
    }
}

#[test]
fn a_frame_expectation_does_not_need_an_event() {
    let pair = pair();
    pair.send(Side::Near, Frame::empty(FrameKind::Ping)).expect("sends");
    assert_eq!(check(&pair, &[Expectation::frame(Side::Near, FrameKind::Ping)]), Ok(()));
}

#[test]
fn expectation_errors_explain_themselves() {
    let errors = [
        ExpectationError::NeverArrived { from: "near", expected: "device.hello".to_owned() },
        ExpectationError::WrongEvent {
            from: "near",
            kind: "envelope",
            found: "device.bye".to_owned(),
            expected: "device.hello".to_owned(),
        },
        ExpectationError::Refused(TransportError::Closed),
        ExpectationError::Clock(crate::clock::ClockError::Backwards { from: 2, to: 1 }),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
