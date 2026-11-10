use super::super::{PROTOCOL_VERSION, Request, Response};
use super::round_trip;

#[test]
fn a_message_round_trips() {
    let request = Request::Devices {
        include_unpaired: true,
        scan_ms: None,
    };
    assert_eq!(round_trip(&request), request);
}

#[test]
fn every_request_round_trips() {
    // Each variant, because a `deny_unknown_fields` on the wrong side of a rename is a variant that decodes to
    // nothing — and the failure appears only for the one request a user happened to send.
    let requests = [
        Request::Hello {
            version: PROTOCOL_VERSION,
        },
        Request::Status,
        Request::Devices {
            include_unpaired: false,
            scan_ms: None,
        },
        Request::SendText {
            to: "dev_a".to_owned(),
            text: "hi".to_owned(),
        },
        Request::SendFile {
            to: "dev_a".to_owned(),
            path: "/tmp/a".to_owned(),
        },
        Request::Plugins,
        Request::PluginRemove {
            plugin_id: "@acme/x".to_owned(),
            remove_data: true,
        },
        Request::Logs {
            lines: 50,
            verbose: true,
            trace: None,
        },
    ];
    for request in requests {
        assert_eq!(round_trip(&request), request, "{}", request.kind());
    }
}

#[test]
fn every_response_round_trips() {
    let responses = [
        Response::Hello {
            version: PROTOCOL_VERSION,
            kernel: "0.1.0".to_owned(),
        },
        Response::ok(serde_json::json!({"devices": []})),
        Response::failed("device_offline", "the device is not reachable", true),
    ];
    for response in responses {
        assert_eq!(round_trip(&response), response, "{response:?}");
    }
}

#[test]
fn every_request_has_a_distinct_name() {
    // The name reaches a log line and a test, so two requests sharing one would make a diagnostic ambiguous.
    let requests = [
        Request::Hello { version: 1 },
        Request::Status,
        Request::Devices {
            include_unpaired: false,
            scan_ms: None,
        },
        Request::SendText {
            to: String::new(),
            text: String::new(),
        },
        Request::SendFile {
            to: String::new(),
            path: String::new(),
        },
        Request::Plugins,
        Request::Logs {
            lines: 1,
            verbose: false,
            trace: None,
        },
    ];
    let mut names: Vec<&str> = requests.iter().map(Request::kind).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), requests.len(), "a request name repeats");
}

#[test]
fn a_response_knows_whether_it_succeeded() {
    assert!(Response::ok(serde_json::json!(null)).is_ok());
    let failed = Response::failed("timeout", "it timed out", true);
    assert!(!failed.is_ok());
    assert_eq!(failed.error_code(), Some("timeout"));
    assert_eq!(
        Response::Hello {
            version: 1,
            kernel: "k".to_owned()
        }
        .error_code(),
        None
    );
}

#[test]
fn a_refusal_carries_a_code_a_sentence_and_whether_to_retry() {
    // ★ Three fields for three readers: a script branches on the code, a person reads the sentence, and the retry
    // flag decides whether a client offers the same request again. A channel with only the sentence would make every
    // script match on prose.
    let failed = Response::failed("device_offline", "the device is not reachable", true);
    match failed {
        Response::Failed {
            code,
            message,
            retryable,
        } => {
            assert_eq!(code, "device_offline");
            assert!(message.contains("reachable"));
            assert!(retryable);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}
