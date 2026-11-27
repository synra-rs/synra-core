use std::sync::Arc;

use synra_plugin_host::host_calls::{CallError, Host as _};
use synra_protocol::ErrorCode;

use super::{host_with, id};

#[test]
fn a_concrete_grant_is_required_for_the_actual_host_and_method() {
    let plugin = id("@acme/notes");
    let read = r#"{"url":"http://api.example.test/"}"#;
    for grants in [
        vec![],
        vec![("network:fetch:*", true)],
        vec![("network:fetch:**", true)],
    ] {
        let refused = host_with(&grants)
            .fetch(&plugin, read)
            .expect_err("no concrete grant");
        assert_eq!(refused.code, CallError::CAPABILITY_DENIED);
        assert!(
            refused
                .message
                .contains("network:fetch:api.example.test:GET")
        );
    }

    let host = host_with(&[
        ("network:fetch:api.example.test:GET", true),
        ("network:fetch:**", true),
    ]);
    let write = r#"{"url":"http://api.example.test/","method":"POST"}"#;
    assert_eq!(
        host.fetch(&plugin, write).unwrap_err().code,
        CallError::CAPABILITY_DENIED
    );
    assert_eq!(
        host.fetch(&plugin, read).unwrap_err().code,
        ErrorCode::SchemeNotAllowed.as_str()
    );
}

#[test]
fn replacing_grants_keeps_the_same_client_and_uses_the_new_scope() {
    let host = host_with(&[("network:fetch:api.example.test:GET", true)]);
    let plugin = id("@acme/notes");
    let before = host.fetch_clients.get(&plugin);
    host.db
        .lock()
        .record_grants(
            plugin.as_str(),
            &[
                ("network:fetch:api.example.test:GET".to_owned(), false),
                ("network:fetch:another.example.test:POST".to_owned(), true),
            ],
            2,
            "scope change",
        )
        .unwrap();

    assert!(Arc::ptr_eq(&before, &host.fetch_clients.get(&plugin)));
    let revoked = r#"{"url":"http://api.example.test/","method":"GET"}"#;
    assert_eq!(
        host.fetch(&plugin, revoked).unwrap_err().code,
        CallError::CAPABILITY_DENIED
    );
    let new_scope = r#"{"url":"http://another.example.test/","method":"POST"}"#;
    assert_eq!(
        host.fetch(&plugin, new_scope).unwrap_err().code,
        ErrorCode::SchemeNotAllowed.as_str()
    );
}
