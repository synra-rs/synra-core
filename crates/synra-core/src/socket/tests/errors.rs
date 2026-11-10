use std::net::SocketAddr;
use super::super::SocketError;

#[test]
fn every_error_explains_itself() {
    let errors = [
        SocketError::Bind {
            address: SocketAddr::from(([0, 0, 0, 0], 32101)),
            why: "in use".to_owned(),
        },
        SocketError::Send {
            address: SocketAddr::from(([255, 255, 255, 255], 32101)),
            why: "no route".to_owned(),
        },
        SocketError::Receive {
            why: "timed out".to_owned(),
        },
        SocketError::Malformed {
            why: "not utf8".to_owned(),
        },
        SocketError::Encode {
            why: "name too long".to_owned(),
        },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And a bind failure names the address, because "already in use" leaves a user with nothing to act on.
    assert!(errors[0].to_string().contains("32101"), "{}", errors[0]);
}
