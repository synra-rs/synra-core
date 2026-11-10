use super::*;

#[test]
fn each_request_reaches_its_own_kernel_method() {
    // A `match` with a copy-paste mistake routes two requests to one method, and the symptom is a client that asks
    // for the log and gets the device list.
    let kernel = Fake::ok();
    let (responses, _) = run(
        &kernel,
        &[
            hello(),
            Request::Devices {
                include_unpaired: true,
                scan_ms: Some(750),
            },
            Request::Logs {
                lines: 25,
                verbose: true,
                trace: None,
            },
        ],
    );
    assert_eq!(
        responses[1],
        Response::ok(serde_json::json!({"devices": []}))
    );
    assert_eq!(responses[2], Response::ok(serde_json::json!({"lines": []})));

    // And the operands arrived rather than being dropped by the routing.
    let asked = kernel.asked.borrow();
    assert_eq!(
        asked[0],
        (true, 750, false),
        "devices did not get its flag and its scan budget"
    );
    assert_eq!(asked[1], (false, 25, true), "logs did not get its operands");
}



#[test]
fn a_kernels_refusal_becomes_a_response_with_its_code_and_retryability() {
    // ★ The code and the retryable flag both come from the protocol's `ErrorCode`, so a kernel cannot report a code
    // whose retryability disagrees with what every other part of the system believes about it.
    for code in [
        ErrorCode::DeviceOffline,
        ErrorCode::NotPaired,
        ErrorCode::Internal,
    ] {
        let (responses, state) = run(&Fake::refusing(code), &[hello(), Request::Status]);
        assert_eq!(
            state,
            SessionState::Open,
            "a refusal is not a reason to close"
        );
        match &responses[1] {
            Response::Failed {
                code: reported,
                retryable,
                ..
            } => {
                assert_eq!(reported, code.as_str());
                assert_eq!(
                    *retryable,
                    code.retryable(),
                    "{} retryability",
                    code.as_str()
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn a_refusal_does_not_end_the_connection() {
    // ★ One failing command must not take the connection with it: a script that runs five commands and gets a
    // refusal for the third has to be able to read the other four answers. A handler that closed on a refusal would
    // leave the client with a framing error for the message it never received.
    let (responses, state) = run(
        &Fake::refusing(ErrorCode::DeviceOffline),
        &[
            hello(),
            Request::Status,
            Request::Plugins,
            Request::Logs {
                lines: 1,
                verbose: false,
                trace: None,
            },
        ],
    );
    assert_eq!(state, SessionState::Open);
    assert_eq!(responses.len(), 4);
    assert!(
        responses[0].is_ok(),
        "the handshake should not be refused: {:?}",
        responses[0]
    );
    for response in &responses[1..] {
        assert!(!response.is_ok(), "{response:?}");
    }
}

#[test]
fn a_path_that_is_not_a_file_is_the_kernels_refusal_rather_than_the_channels() {
    // The channel carries a string and does not look at the filesystem: whether a path is readable is the kernel's
    // question, because the kernel is what knows which directories a client may name.
    let (responses, _) = run(
        &Fake::refusing(ErrorCode::InvalidArgument),
        &[
            hello(),
            Request::SendFile {
                to: "d".to_owned(),
                path: "nope".to_owned(),
            },
        ],
    );
    assert_eq!(responses[1].error_code(), Some("invalid_argument"));
}
