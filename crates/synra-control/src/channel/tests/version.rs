use super::super::{ChannelError, PROTOCOL_VERSION, Request, check_version};

#[test]
fn the_same_version_is_accepted() {
    assert!(check_version(PROTOCOL_VERSION).is_ok());
}

#[test]
fn a_different_version_names_both() {
    // ★ A client and a kernel are separate binaries that may be upgraded separately — a user who upgrades one and
    // not the other. The sentence has to say both versions, because "incompatible" alone leaves the user with
    // nothing to do.
    match check_version(PROTOCOL_VERSION + 1) {
        Err(ChannelError::VersionMismatch { client, kernel }) => {
            assert_eq!(client, PROTOCOL_VERSION + 1);
            assert_eq!(kernel, PROTOCOL_VERSION);
        }
        other => panic!("expected a mismatch, got {other:?}"),
    }
    // And an older client is refused the same way, rather than being assumed compatible.
    assert!(check_version(PROTOCOL_VERSION - 1).is_err());
}

// ── Shapes ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_handshake_is_the_one_request_a_kernel_answers_before_checking_the_version() {
    // It has to be: the answer to `Hello` is *how* a client learns the version it should have sent.
    assert!(Request::Hello { version: 99 }.is_handshake());
    for request in [
        Request::Status,
        Request::Devices {
            include_unpaired: false,
            scan_ms: None,
        },
        Request::Plugins,
        Request::Logs {
            lines: 1,
            verbose: false,
            trace: None,
        },
    ] {
        assert!(!request.is_handshake(), "{}", request.kind());
    }
}
