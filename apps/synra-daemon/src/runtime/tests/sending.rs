use super::*;

#[test]
fn sending_to_a_device_nothing_is_called_is_refused_before_anything_is_dialled() {
    // ★ "Nothing is called that" is a question about the *text of the argument*, and answering it costs no network at
    // all. A kernel that dialled first would spend a handshake to produce the same refusal.
    let dir = TempDir::new("send-unknown");
    let runtime = runtime(dir.path());
    match runtime.send_text("Nobody", "hello") {
        Err(refusal) => {
            assert_eq!(refusal.code, ErrorCode::NotPaired);
            assert!(refusal.message.contains("Nobody"), "{}", refusal.message);
            // And it says how to find out what there is.
            assert!(refusal.message.contains("devices"), "{}", refusal.message);
        }
        Ok(value) => panic!("expected a refusal, got {value}"),
    }
}

#[test]
fn sending_empty_text_is_refused_as_an_argument_rather_than_a_network_failure() {
    // ★ The user typed nothing. That is a mistake at the shell, and the *code* says which kind of mistake — a client
    // shows "there is no text to send" rather than offering to try again.
    let dir = TempDir::new("send-empty");
    let runtime = runtime(dir.path());
    for text in ["", "   "] {
        match runtime.send_text("anyone", text) {
            Err(refusal) => assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{text:?}"),
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }
}

#[test]
fn text_too_large_for_one_message_gets_the_protocols_own_code() {
    // ★ The protocol has a code for exactly this, and a client can act on it — the next step is to send a file rather
    // than to retry. Reported as `InvalidArgument` it would read as a typo.
    let dir = TempDir::new("send-huge");
    let runtime = runtime(dir.path());
    let huge = "a".repeat(200 * 1024 * 1024);
    match runtime.send_text("anyone", &huge) {
        Err(refusal) => {
            assert_eq!(refusal.code, ErrorCode::PayloadTooLarge);
            assert!(refusal.message.contains("file"), "{}", refusal.message);
        }
        Ok(value) => panic!("expected a refusal, got {value}"),
    }
}

#[test]
fn file_sending_checks_the_file_before_it_looks_for_the_device() {
    // ★ The same order `send --text` uses, and for the same reason: a path that does not exist is a mistake in the
    // argument the user just typed. Reporting it as an unknown device would send them to check a device list for a
    // problem that is not there.
    let dir = TempDir::new("send-file-missing");
    let runtime = runtime(dir.path());
    match runtime.send_file("nobody", "/definitely/not/here.bin") {
        Err(refusal) => {
            assert_eq!(refusal.code, ErrorCode::InvalidArgument);
            assert!(
                refusal.message.contains("not/here.bin"),
                "{}",
                refusal.message
            );
        }
        Ok(value) => panic!("expected a refusal, got {value}"),
    }
}

#[test]
fn file_sending_to_a_device_nothing_is_called_is_refused_after_the_file_passes() {
    // The other side of the same order: a real file and an unknown device is a device problem, and that is the code
    // the client gets. The two checks are separate so the message is about the thing the user got wrong.
    let dir = TempDir::new("send-file-unknown");
    let source = dir.path().join("real.bin");
    std::fs::write(&source, b"contents").expect("writes");
    let runtime = runtime(dir.path());
    match runtime.send_file("nobody", &source.to_string_lossy()) {
        Err(refusal) => assert_eq!(refusal.code, ErrorCode::NotPaired),
        Ok(value) => panic!("expected a refusal, got {value}"),
    }
}

#[test]
fn text_sending_no_longer_refuses_for_a_missing_layer() {
    // ★ `send --text` must fail for a reason about the *device*, not about a missing layer. This is what would break
    // first if the two commands were ever wired to the same refusal again.
    let dir = TempDir::new("send-text-real");
    let runtime = runtime(dir.path());
    match runtime.send_text("d", "x") {
        Err(refusal) => {
            // The text path refuses for a reason about the device, not about a missing layer.

            assert_eq!(refusal.code, ErrorCode::NotPaired);
        }
        Ok(value) => panic!("expected a refusal, got {value}"),
    }
}

#[test]
fn a_missing_argument_is_not_retryable() {
    // ★ A refusal about the argument is not retryable, and that is the right answer: repeating the call with the same
    // argument will keep failing. A retryable flag would have a client offer a retry that cannot work.
    //
    // `Unsupported` used to be the example here, for the layer that was not written. Nothing refuses with `Unsupported`
    // any more — the transfer path exists — so the example is an argument the user can fix.
    let dir = TempDir::new("retryable");
    match runtime(dir.path()).send_file("d", "/definitely/not/here.bin") {
        Err(refusal) => {
            assert_eq!(refusal.code, ErrorCode::InvalidArgument);
            assert!(!refusal.is_retryable());
        }
        Ok(value) => panic!("expected a refusal, got {value}"),
    }
}
