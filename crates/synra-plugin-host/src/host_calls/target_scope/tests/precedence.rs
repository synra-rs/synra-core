use super::*;

#[test]
fn authorization_precedes_rate_limits_and_refusals_name_the_actual_scope() {
    let host = Stub::default();
    let held = grants(&[
        &format!("device:send:{DEVICE}"),
        "action:invoke:@acme/formatter:format-date",
        "action:declare:format-date",
    ]);
    let budget = Budget::new(Quota {
        device_sends_per_sec: 0,
        host_calls_per_sec: 0,
        host_calls_burst: 0,
        ..Quota::default()
    });
    let mut audit = Vec::new();
    let mut calls = HostCalls::new(
        &host,
        PluginId::parse("@acme/chat").expect("plugin"),
        &held,
        &budget,
        &mut audit,
    );
    for (import, denied, allowed, missing) in [
        (
            "action-declare",
            serde_json::json!({"name":"other"}),
            serde_json::json!({"name":"format-date"}),
            "action:declare:other".to_owned(),
        ),
        (
            "device-send",
            serde_json::json!({"target":OTHER,"event":"_plugin.@acme/chat.ready"}),
            serde_json::json!({"target":DEVICE,"event":"_plugin.@acme/chat.ready"}),
            format!("device:send:{OTHER}"),
        ),
        (
            "action-invoke",
            serde_json::json!({"plugin":"@other/formatter","name":"format-date"}),
            serde_json::json!({"plugin":"@acme/formatter","name":"format-date"}),
            "action:invoke:@other/formatter:format-date".to_owned(),
        ),
    ] {
        let import = format!("synra:plugin/host#{import}");
        let refusal = calls
            .call(&import, &denied.to_string())
            .expect_err("wrong scope");
        assert_eq!(refusal.code, CallError::CAPABILITY_DENIED);
        assert!(refusal.details.expect("details").contains(&missing));
        assert_eq!(
            calls
                .call(&import, &allowed.to_string())
                .expect_err("zero rate")
                .code,
            CallError::RATE_LIMITED
        );
    }
    assert!(host.called().is_empty());
}
