use super::{ErrorCode, Refusal, Response};

#[test]
fn a_refusal_reads_its_retryability_from_its_code() {
    // Stored rather than derived, a refusal could claim to be retryable when its code says otherwise — and a script
    // would repeat a call that cannot succeed.
    assert!(Refusal::new(ErrorCode::DeviceOffline, "gone").is_retryable());
    assert!(!Refusal::new(ErrorCode::NotPaired, "not paired").is_retryable());
    // `Internal` is retryable in the kernel, and this is where that shows.
    assert!(Refusal::new(ErrorCode::Internal, "unexpected").is_retryable());
}

#[test]
fn a_refusal_converts_to_the_response_a_client_reads() {
    let response: Response = Refusal::new(ErrorCode::NotPaired, "pair first").into();
    match response {
        Response::Failed {
            code,
            message,
            retryable,
        } => {
            assert_eq!(code, ErrorCode::NotPaired.as_str());
            assert_eq!(message, "pair first");
            assert!(!retryable);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_refusal_explains_itself() {
    let text =
        Refusal::new(ErrorCode::DeviceOffline, "the device is not reachable").to_string();
    assert!(text.contains("not reachable"), "{text}");
    assert!(!text.contains('{'), "{text}");
}
