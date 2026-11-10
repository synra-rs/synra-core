use std::sync::Arc;

use synra_plugin_host::host_calls::{CallError, Host as _};
use synra_protocol::ids::PluginId;

use super::super::network::{fetcher_for, host_of};
use super::{host_with, id};

#[test]
fn a_capability_names_a_host_or_it_names_nothing() {
    // The parsing rule, on its own, because everything below depends on it being the fail-closed reading.
    assert_eq!(host_of("network:fetch:api.github.com").as_deref(), Some("api.github.com"));
    // A method qualifier is not part of the host: the guard decides *where*, and the method travels as sent.
    assert_eq!(host_of("network:fetch:api.github.com:POST").as_deref(), Some("api.github.com"));

    // ★ `*` is the family spelling the **gate** uses, not a hostname. Reading it as one would build a guard for a
    // machine literally called `*`, and reading it as "anything" would be the capability an SSRF guard exists to make
    // deliberate — so it names nothing.
    assert_eq!(host_of("network:fetch:*"), None);
    assert_eq!(host_of("network:fetch:"), None);
    assert_eq!(host_of("network:fetch"), None);
    assert_eq!(host_of("fs:read:/data/**"), None);
}

#[test]
fn a_plugin_with_no_host_grant_is_told_which_spelling_it_needs() {
    // Nothing granted at all: `capabilityDenied`, because the answer is "ask the user", not "that host is not one of
    // them" — and a plugin author can act on the first.
    let host = host_with(&[]);
    let refused = fetcher_for(&host, &id("@acme/notes")).expect_err("no grant");

    assert_eq!(refused.code, CallError::CAPABILITY_DENIED);
    assert!(refused.message.contains("network:fetch:"), "and it says what to ask for: {}", refused.message);
}

#[test]
fn a_family_grant_with_a_star_is_not_a_grant_to_reach_everything() {
    // ★ The whole point of the guard, at the host: `network:fetch:*` passes the **gate** — it is the family — and it
    // must not become "every host on the internet". So it reaches nothing.
    let host = host_with(&[("network:fetch:*", true)]);
    let refused = fetcher_for(&host, &id("@acme/notes")).expect_err("no host named");

    assert_eq!(refused.code, CallError::CAPABILITY_DENIED, "{refused}");
}

#[test]
fn a_granted_host_gives_a_client_and_withdrawing_it_takes_the_client_away() {
    // ★ This is the test the cache needs: a client built for a grant must not outlive the grant. If the cache were
    // keyed on the plugin alone, the call after the withdrawal would hand back the client built for the first grant —
    // and a user who withdrew a host would keep reaching it.
    let host = host_with(&[("network:fetch:api.github.com", true)]);
    assert!(fetcher_for(&host, &id("@acme/notes")).is_ok(), "granted");
    assert!(fetcher_for(&host, &id("@acme/notes")).is_ok(), "and again");

    host.db
        .lock()
        .record_grants("@acme/notes", &[("network:fetch:api.github.com".to_owned(), false)], 2, "d2")
        .expect("the decision is recorded");
    let refused = fetcher_for(&host, &id("@acme/notes")).expect_err("withdrawn");

    assert_eq!(refused.code, CallError::CAPABILITY_DENIED, "{refused}");
}

#[test]
fn a_cached_client_rechecks_stored_method_grants_for_each_request() {
    let host = host_with(&[("network:fetch:127.0.0.1:GET", true)]);
    let plugin = PluginId::parse("@acme/notes").unwrap();
    let before = fetcher_for(&host, &plugin).unwrap();
    let error = host
        .fetch(&plugin, r#"{"url":"https://127.0.0.1:1/","method":"POST"}"#)
        .unwrap_err();
    assert_eq!(error.code, CallError::CAPABILITY_DENIED);
    host.db
        .lock()
        .record_grants(
            plugin.as_str(),
            &[
                ("network:fetch:127.0.0.1:GET".to_owned(), false),
                ("network:fetch:127.0.0.1:POST".to_owned(), true),
            ],
            2,
            "method change",
        )
        .unwrap();
    assert!(Arc::ptr_eq(&before, &fetcher_for(&host, &plugin).unwrap()));
    let error = host
        .fetch(&plugin, r#"{"url":"https://127.0.0.1:1/","method":"GET"}"#)
        .unwrap_err();
    assert_eq!(error.code, CallError::CAPABILITY_DENIED);
}
