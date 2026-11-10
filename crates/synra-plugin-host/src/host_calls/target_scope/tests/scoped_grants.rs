use super::*;

#[test]
fn device_grants_authorize_the_canonical_target_and_keep_event_ownership() {
    let exact = format!("device:send:{DEVICE}");
    for (grant, target, event, expected) in [
        (exact.as_str(), DEVICE, "_plugin.@acme/chat.ready", None),
        (
            exact.as_str(),
            OTHER,
            "_plugin.@acme/chat.ready",
            Some(CallError::CAPABILITY_DENIED),
        ),
        ("device:send:*", OTHER, "_plugin.@acme/chat.ready", None),
        ("device:**", OTHER, "_plugin.@acme/chat.ready", None),
        (
            "device:send:*",
            "@self",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            "Laptop",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            "*",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            "00000000000040008000000000000001",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            DEVICE,
            "_plugin.@other/chat.ready",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "device:send:*",
            DEVICE,
            "_plugin.chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
    ] {
        check_call(
            grant,
            "device-send",
            serde_json::json!({"target":target,"event":event,"payload":"{}"}),
            expected,
        );
    }
}

#[test]
fn action_grants_bind_the_full_package_and_a_literal_action() {
    for (grant, plugin, name, expected) in [
        (
            "action:invoke:@acme/formatter:format-date",
            "@acme/formatter",
            "format-date",
            None,
        ),
        (
            "action:invoke:@acme/formatter:format-date",
            "@other/formatter",
            "format-date",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "action:invoke:@acme/formatter:format-date",
            "@acme/formatter",
            "other",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "action:invoke:@acme/formatter:*",
            "@acme/formatter",
            "other",
            None,
        ),
        (
            "action:invoke:*:format-date",
            "@other/formatter",
            "format-date",
            None,
        ),
        ("action:invoke:*:*", "@acme/formatter", "format-date", None),
        ("action:invoke:**", "@acme/formatter", "format-date", None),
        (
            "action:invoke:*",
            "@acme/formatter",
            "format-date",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "action:invoke:*:*",
            "formatter",
            "format-date",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/*",
            "format-date",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/formatter",
            "*",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/formatter",
            "a:b",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/formatter",
            "",
            Some(CallError::BAD_ARGUMENT),
        ),
    ] {
        check_call(
            grant,
            "action-invoke",
            serde_json::json!({"plugin":plugin,"name":name,"args":"{}"}),
            expected,
        );
    }
    check_call(
        "action:declare:*",
        "action-declare",
        serde_json::json!({"name":"*","schema":"{}"}),
        Some(CallError::BAD_ARGUMENT),
    );
}
