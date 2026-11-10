use synra_plugin_host::host_calls::Host as _;

use super::{host_with, id};

#[test]
fn gated_platform_calls_reach_headless_policy_and_refuse_without_effects() {
    use synra_plugin_host::{
        host_calls::HostCalls,
        quota::{Budget, Quota},
    };

    let host = host_with(&[]);
    let mut grants = synra_capability::CapabilitySet::new();
    grants.insert_str("platform:open-url").expect("grant");
    grants.insert_str("platform:read-clipboard").expect("grant");
    let budget = Budget::new(Quota::default());
    let mut audit = Vec::new();
    let mut calls = HostCalls::new(&host, id("@acme/notes"), &grants, &budget, &mut audit);
    for (function, argument, expected) in [
        ("platform-open-url", "javascript:alert(1)", "badArgument"),
        ("platform-open-url", "https://example.com", "notImplemented"),
        ("platform-read-clipboard", "", "notImplemented"),
    ] {
        let error = calls
            .call(&format!("synra:plugin/host#{function}"), argument)
            .expect_err("headless refusal");
        assert_eq!(error.code, expected, "{error:?}");
    }
}

#[test]
fn can_answers_from_what_the_user_actually_granted() {
    // ★ `env-can` is a question a plugin asks about **itself**, so the answer has to agree with the gate that will
    // judge its calls. Reading the same consent table is what makes that true rather than merely likely.
    let host = host_with(&[("log:*", true), ("device:list", false)]);

    assert!(host.can(&id("@acme/notes"), "log:info"), "a granted wildcard covers the specific");
    assert!(!host.can(&id("@acme/notes"), "device:list"), "a denied capability is denied");
    assert!(!host.can(&id("@acme/notes"), "storage:local:read"), "and one never asked about");
    assert!(!host.can(&id("@acme/other"), "log:info"), "an unknown plugin holds nothing");
}

#[test]
fn a_malformed_capability_is_not_a_grant() {
    // The gate parses before it matches, so a string that is not a capability cannot be held. Answering `true` here
    // would tell a plugin it may do something the gate would then refuse.
    let host = host_with(&[("log:*", true)]);
    assert!(!host.can(&id("@acme/notes"), "not a capability"));
    assert!(!host.can(&id("@acme/notes"), ""));
}

#[test]
fn the_groups_this_build_does_not_implement_refuse_with_one_code() {
    // ★ Refusing is not a placeholder. A plugin branches on the code, and `NOT_IMPLEMENTED` says "this host cannot
    // do that" rather than "you are not allowed" — which is the difference between a plugin hiding a feature and a
    // user hunting for a permission they already granted.
    let host = host_with(&[]);
    let plugin = id("@acme/notes");

    for refusal in [
        host.device_send(&plugin, "d", "x", "{}"),
        host.secret_get(&plugin, "k").map(|_| ()),
        host.transfer_status(&plugin, "t").map(|_| ()),
        host.action_list(&plugin).map(|_| ()),
    ] {
        let error = refusal.expect_err("this build does not implement it");
        // ★ Read from the contract rather than spelled here. This assertion used to compare against the literal
        // `"NOT_IMPLEMENTED"`, which this host had invented — upper case with an underscore, when every code the
        // contract defines is camelCase. A test that asserts the implementation's own spelling cannot catch the
        // implementation spelling it wrong.
        assert_eq!(error.code, synra_plugin_host::host_calls::CallError::NOT_IMPLEMENTED, "{error:?}");
    }

    // ★ Storage is **not** in that list any more, and its absence is the point: it was the largest group in it, and a
    // plugin could not persist a byte. Asserted positively here, so that removing it from the loop cannot be mistaken
    // for removing the feature.
    assert_eq!(host.storage_get(&plugin, "k").expect("reads"), None, "an empty store reads as absent");
    host.storage_set(&plugin, "k", "v").expect("writes");
    assert_eq!(host.storage_get(&plugin, "k").expect("reads").as_deref(), Some("v"));
    assert_eq!(host.storage_used(&plugin).expect("measures"), 1);
    assert_eq!(host.storage_keys(&plugin, None).expect("lists"), vec!["k".to_owned()]);
    host.storage_delete(&plugin, "k").expect("removes");
    assert_eq!(host.storage_used(&plugin).expect("measures"), 0);

    // ★ And network is not in that list either. Asserted positively the same way: the refusal below is a **capability**
    // answer rather than a "this build cannot" one, which is the difference this test exists to protect — and it is
    // reachable without a network, because the guard refuses before anything is sent.
    let refused = host.fetch(&plugin, r#"{"url":"https://api.github.com/"}"#).expect_err("no grant");
    assert_eq!(refused.code, synra_plugin_host::host_calls::CallError::CAPABILITY_DENIED, "{refused:?}");
}

#[test]
fn a_bad_address_is_the_plugins_mistake_rather_than_a_missing_feature() {
    // ★ The ordering, which is the whole reason this host delegates to `HeadlessPlatform`.
    //
    // This host answered every platform call with `notImplemented` — including one whose URL was garbage. A plugin that
    // supplied `javascript:` was then told the *installation* lacked a browser, which is a fact about the machine rather
    // than about its own argument, and its author had nothing to act on.
    //
    // `HeadlessPlatform` runs the guard and *then* refuses, so a caller learns about the first thing it can fix.
    let host = host_with(&[]);
    let plugin = id("@acme/notes");

    // The plugin's mistake: `badArgument`, because the address is the thing that is wrong.
    let refused = host
        .platform(
            &plugin,
            synra_plugin_host::PlatformAction::OpenUrl,
            "javascript:alert(1)",
        )
        .expect_err("the guard refuses this scheme");
    assert_eq!(refused.code, "badArgument", "{refused:?}");
    assert!(
        refused.message.contains("javascript"),
        "{}",
        refused.message
    );

    // The installation's limitation: `notImplemented`, for an address that is perfectly fine.
    let refused = host
        .platform(
            &plugin,
            synra_plugin_host::PlatformAction::OpenUrl,
            "https://example.com",
        )
        .expect_err("a headless host has no browser");
    assert_eq!(refused.code, "notImplemented", "{refused:?}");
}

#[test]
fn the_answers_that_exist_are_the_daemons_own() {
    let host = host_with(&[]);

    assert_eq!(host.sdk_version(), "9.9.9", "the version this host was built at");
    assert_eq!(host.host_kind(), "headless", "the daemon has no window, and saying desktop would be a claim");
    // ★ Empty rather than invented. A list of plausible platform capabilities would be a promise a plugin could
    // build a feature on, and this build has no platform integration to keep it.
    assert!(host.platform_capabilities().is_empty());
    // A fresh database has paired with nothing, so the list is empty — and it is empty because it is true.
    assert!(host.devices().is_empty());
}
