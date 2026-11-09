use super::*;
use crate::intent::{Choice, IntentSource};

fn device(id: &str) -> DeviceId {
    id.parse().expect("a device id")
}

fn local() -> DeviceId {
    device("11111111-1111-4111-8111-111111111111")
}

fn peer() -> DeviceId {
    device("22222222-2222-4222-8222-222222222222")
}

/// A candidate named outright, which is the state a restored dispatch is in.
fn direct(target: DeviceId) -> IntentSource {
    IntentSource::Direct {
        plugin_id: PluginId::parse("@acme/opener").expect("a plugin id"),
        action: "open".to_owned(),
        params: serde_json::json!({"url": "https://example.com"}),
        target,
    }
}

#[test]
fn a_restored_dispatch_is_rebuilt_as_the_invocation_it_was() {
    // ★ The whole reason this function exists: the request id is the receiving side's idempotency key. A rebuilt
    // envelope with a fresh id is a second request, and the receiver's cache would run the action twice.
    let mut board = Board::new();
    let request_id = synra_protocol::ids::RequestId::new();
    let (id, trace, created) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(request_id),
        1_000,
    );
    assert!(created, "a direct source is raised rather than matched");

    let outbound =
        resume(board.get(id).expect("raised"), local(), 2_000).expect("work this device sent");

    assert_eq!(outbound.to, peer());
    assert_eq!(outbound.request_id, request_id);
    assert_eq!(outbound.envelope.from, local());
    assert_eq!(outbound.envelope.target, peer());
    assert_eq!(outbound.envelope.trace_id, trace);
    assert_eq!(
        outbound.envelope.event.as_str(),
        synra_protocol::event::events::INTENT_INVOKE
    );
    assert_eq!(
        outbound.envelope.request_id, request_id,
        "the id is the idempotency key"
    );

    let asked = crate::intent::remote::invoke_from(&outbound.envelope).expect("readable");
    assert_eq!(asked.plugin_id.as_str(), "@acme/opener");
    assert_eq!(asked.action, "open");
    assert_eq!(asked.args["url"], "https://example.com");
}

#[test]
fn work_that_never_travelled_is_not_sent_again() {
    let mut board = Board::new();
    // An intent a peer asked this device to run: re-sending it would ask the peer to run it again.
    let (from_peer, ..) = board.raise(
        direct(peer()),
        Choice::Automatic,
        Some(peer()),
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    assert!(resume(board.get(from_peer).expect("raised"), local(), 2_000).is_none());

    // A target that is this device: nothing ever left, so there is nothing to re-send.
    let (here, ..) = board.raise(
        direct(local()),
        Choice::Automatic,
        None,
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    assert!(resume(board.get(here).expect("raised"), local(), 2_000).is_none());

    // A dispatch past the window in which a late answer can still arrive: `expire_unanswered` ends these, this does
    // not re-send them.
    let (stale, ..) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    let late = 1_000 + crate::late_queue::MAX_AGE_MS;
    assert!(resume(board.get(stale).expect("raised"), local(), late).is_none());
}

#[test]
fn a_failed_intent_carries_its_error_into_the_view() {
    // ★ The board has held the error since `Failed` was written; the view dropped it, so the interface's "why did it
    // fail?" line read `null` for every real failure.
    let mut board = Board::new();
    let (id, ..) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    board
        .conclude(
            id,
            Err(synra_protocol::SynraError::new(
                synra_protocol::ErrorCode::Internal,
                "the plugin trapped",
            )),
            3,
        )
        .expect("ended");
    let board = Arc::new(Mutex::new(board));

    let view = snapshot(&board, &id.to_string()).expect("a view");
    let error = view.error.as_ref().expect("the failure is carried");
    assert_eq!(error.code, synra_protocol::ErrorCode::Internal);
    assert_eq!(error.message, "the plugin trapped");
    assert_eq!(
        view.created_at_ms, 1_000,
        "the raising time is carried, not the reading time"
    );
    assert_eq!(view.to_json()["error"]["code"], "internal");
    assert_eq!(view.to_json()["createdAtMs"], 1_000);
}

#[test]
fn a_remote_result_keeps_the_code_it_reports() {
    // ★ The sender used to answer `Internal` for every remote failure because `InvokeResult.error` carried only a
    // sentence. The code is what the interface branches on, so it has to survive the wire and reach the board.
    let mut board = Board::new();
    let request = synra_protocol::ids::RequestId::new();
    let (id, trace, _) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(request),
        1_000,
    );
    let mut reply = crate::intent::remote::result(
        peer(),
        local(),
        &crate::intent::remote::InvokeResult::Failed {
            error: synra_protocol::SynraError::new(
                synra_protocol::ErrorCode::CapabilityDenied,
                "the plugin is not allowed to open that".to_owned(),
            )
            .with_trace("spoofed-trace")
            .with_details(serde_json::json!({"cleanupPending":true}))
            .with_action(synra_protocol::error::SuggestedAction::RequestCapability {
                capability: "platform:open-url".to_owned(),
            }),
            elapsed_ms: 2,
        },
        trace,
        2_000,
    )
    .expect("a result");
    reply.reply_to = Some(request);
    let board = Arc::new(Mutex::new(board));

    assert_eq!(apply_result(&board, &reply).expect("applied"), Some(id));
    let view = snapshot(&board, &id.to_string()).expect("a view");
    let error = view.error.as_ref().expect("the failure is carried");
    assert_eq!(error.code, synra_protocol::ErrorCode::CapabilityDenied);
    assert_eq!(error.message, "the plugin is not allowed to open that");
    assert_eq!(error.trace_id, Some(trace.to_string()));
    assert_eq!(
        error.details.as_deref(),
        Some(&serde_json::json!({"cleanupPending":true}))
    );
    assert_eq!(error.actions.len(), 1);
    assert!(!error.retryable);
}

#[test]
fn a_timed_out_intent_says_how_long_it_waited() {
    // ★ "Timed out" is a state word, not a reason: it does not say whether the matching window closed or a device never
    // answered, and it does not say for how long. The wait is the fact, and the code is what the page translates.
    let mut board = Board::new();
    let (id, ..) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    let _ = board.time_out(id);
    let board = Arc::new(Mutex::new(board));

    let view = snapshot(&board, &id.to_string()).expect("a view");
    assert_eq!(view.state, "timedOut");
    let error = view.error.as_ref().expect("the wait is carried");
    assert_eq!(error.code, synra_protocol::ErrorCode::Timeout);
    assert_eq!(error.message, "nothing answered within 400 ms");
}

#[test]
fn a_refused_intent_carries_the_check_that_refused_it() {
    // ★ "Refused" without a reason is the same failure as "Failed" without one: the refusal type documents its detail
    // as a sentence the interface can show, and the view was dropping both it and its code.
    let mut board = Board::new();
    let (id, ..) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    board.refuse(
        id,
        crate::admission::AdmissionRefusal {
            step: crate::admission::AdmissionStep::PluginActive,
            detail: "the plugin is not active".to_owned(),
            code: synra_protocol::ErrorCode::PluginNotInstalled,
        },
    );
    let board = Arc::new(Mutex::new(board));

    let view = snapshot(&board, &id.to_string()).expect("a view");
    assert_eq!(view.state, "refused");
    let error = view
        .error
        .as_ref()
        .expect("the refusal's sentence is carried");
    assert_eq!(error.code, synra_protocol::ErrorCode::PluginNotInstalled);
    assert_eq!(error.message, "the plugin is not active");
}

#[test]
fn a_successful_intent_has_no_error_to_show() {
    let mut board = Board::new();
    let (id, ..) = board.raise(
        direct(peer()),
        Choice::Automatic,
        None,
        Some(synra_protocol::ids::RequestId::new()),
        1_000,
    );
    board
        .conclude(id, Ok(serde_json::json!("opened")), 1)
        .expect("ended");
    let board = Arc::new(Mutex::new(board));

    let view = snapshot(&board, &id.to_string()).expect("a view");
    assert!(view.error.is_none());
    assert!(view.to_json()["error"].is_null());
}
