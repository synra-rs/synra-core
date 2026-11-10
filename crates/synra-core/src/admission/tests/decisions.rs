use synra_capability::CapabilitySet;
use synra_platform::PlatformAction;
use synra_protocol::ErrorCode;
use super::super::{AdmissionContext, AdmissionStep, check};
use super::{capability, permissive};

#[test]
fn a_request_that_satisfies_every_check_is_accepted() {
    let context = permissive().with_required(vec![capability("device:send:peer")]);
    assert_eq!(check(&context), Ok(()));
}
#[test]
fn an_unpaired_sender_is_refused_first() {
    // An intent is not accepted from an unpaired source at all, so this is a refusal about identity rather than
    // about permission.
    let context = permissive()
        .with_sender_paired(false)
        .with_required(vec![capability("device:send:peer")]);
    match check(&context) {
        Err(refusal) => {
            assert_eq!(refusal.step, AdmissionStep::SenderPaired);
            assert_eq!(refusal.step.number(), 2);
            assert_eq!(refusal.code, ErrorCode::NotPaired);
            // And it is not transient: the sender cannot fix it by asking again.
            assert!(!refusal.is_transient());
        }
        Ok(()) => panic!("an unpaired sender should be refused"),
    }
}

#[test]
fn an_inactive_plugin_is_refused_before_its_grants_are_considered() {
    // Nothing below this means anything if the plugin is not there, and a plugin that is starting may succeed
    // later — which is why this one is transient.
    let context = AdmissionContext::new(CapabilitySet::new())
        .with_plugin_active(false)
        .with_required(vec![capability("device:send:peer")]);
    match check(&context) {
        Err(refusal) => {
            assert_eq!(refusal.step, AdmissionStep::PluginActive);
            assert_eq!(refusal.step.number(), 3);
            assert_eq!(refusal.code, ErrorCode::PluginNotInstalled);
            assert!(refusal.is_transient());
        }
        Ok(()) => panic!("an inactive plugin should be refused"),
    }
}

#[test]
fn an_undeclared_action_is_refused_before_its_grants_are_considered() {
    // A declared action is a promise; an undeclared one is a caller inventing an interface.
    let context = permissive()
        .with_action_declared(false)
        .with_required(vec![capability("device:send:peer")]);
    match check(&context) {
        Err(refusal) => {
            assert_eq!(refusal.step, AdmissionStep::ActionDeclared);
            assert_eq!(refusal.step.number(), 4);
            assert_eq!(refusal.code, ErrorCode::Unsupported);
        }
        Ok(()) => panic!("an undeclared action should be refused"),
    }
}

#[test]
fn a_missing_grant_is_refused_and_names_every_missing_capability() {
    // The refusal names the whole set, because a user granting one permission at a time should not have to trigger
    // the call repeatedly to discover the list.
    let context = AdmissionContext::new(CapabilitySet::new()).with_required(vec![
        capability("device:send:peer"),
        capability("platform:open-url"),
    ]);
    match check(&context) {
        Err(refusal) => {
            assert_eq!(refusal.step, AdmissionStep::PluginGrant);
            assert_eq!(refusal.step.number(), 5);
            assert_eq!(refusal.code, ErrorCode::CapabilityDenied);
            assert!(
                refusal.detail.contains("device:send:peer"),
                "{}",
                refusal.detail
            );
            assert!(
                refusal.detail.contains("platform:open-url"),
                "{}",
                refusal.detail
            );
            // Not transient: the sender cannot grant itself anything.
            assert!(!refusal.is_transient());
        }
        Ok(()) => panic!("a missing grant should be refused"),
    }
}

#[test]
fn a_host_that_cannot_do_it_is_refused_before_the_plugin_runs() {
    // The design document's "so the plugin does not run for nothing": a plugin started to do something this
    // machine cannot do has already done whatever it does before its first host call.
    let context = permissive()
        .with_required(vec![capability("platform:open-url")])
        .with_host_actions(Vec::new());
    match check(&context) {
        Err(refusal) => {
            assert_eq!(refusal.step, AdmissionStep::HostCapability);
            assert_eq!(refusal.step.number(), 6);
            assert_eq!(refusal.code, ErrorCode::Unsupported);
            // The text reaches a user, so it is the action's own sentence rather than the capability string.
            assert!(refusal.detail.contains("web page"), "{}", refusal.detail);
            assert!(!refusal.detail.contains("platform:"), "{}", refusal.detail);
            assert!(refusal.is_transient());
        }
        Ok(()) => panic!("a host without the action should refuse"),
    }
}

#[test]
fn a_host_with_the_action_admits_it() {
    let context = permissive()
        .with_required(vec![capability("platform:open-url")])
        .with_host_actions(vec![PlatformAction::OpenUrl]);
    assert_eq!(check(&context), Ok(()));
}

#[test]
fn a_host_with_no_network_refuses_a_network_capability() {
    let context = permissive()
        .with_required(vec![capability("network:fetch:api.example.com")])
        .with_host_network(false);
    match check(&context) {
        Err(refusal) => {
            assert_eq!(refusal.step, AdmissionStep::HostCapability);
            assert_eq!(refusal.code, ErrorCode::DeviceOffline);
            assert!(refusal.is_transient(), "a network may come back");
        }
        Ok(()) => panic!("a host with no network should refuse a network capability"),
    }
}

#[test]
fn a_host_with_no_network_still_admits_a_local_action() {
    // The network check applies to capabilities that need the network, not to every call: a plugin that writes to
    // local storage must work on a device that is offline.
    let context = permissive()
        .with_required(vec![capability("device:send:peer")])
        .with_host_network(false);
    assert_eq!(check(&context), Ok(()));
}

#[test]
fn the_checks_run_in_the_documented_order() {
    // Every check failing at once, and the refusal names the earliest. A sequence that reported the last failure
    // would tell a sender about a permission problem when the real answer is that the device is not paired.
    let context = AdmissionContext::new(CapabilitySet::new())
        .with_sender_paired(false)
        .with_plugin_active(false)
        .with_action_declared(false)
        .with_required(vec![capability("platform:open-url")])
        .with_host_actions(Vec::new())
        .with_host_network(false);
    match check(&context) {
        Err(refusal) => assert_eq!(refusal.step, AdmissionStep::SenderPaired),
        Ok(()) => panic!("everything was refused"),
    }
}

#[test]
fn each_step_is_reported_in_turn_as_the_earlier_ones_are_satisfied() {
    // The ladder, walked from the bottom: each fix reveals the next problem, and none is skipped.
    let mut context = AdmissionContext::new(CapabilitySet::new())
        .with_sender_paired(false)
        .with_plugin_active(false)
        .with_action_declared(false)
        .with_required(vec![capability("platform:open-url")]);

    let mut seen = Vec::new();
    for expected in [
        (AdmissionStep::SenderPaired, 2u8),
        (AdmissionStep::PluginActive, 3),
        (AdmissionStep::ActionDeclared, 4),
        (AdmissionStep::PluginGrant, 5),
        (AdmissionStep::HostCapability, 6),
    ] {
        let refusal = check(&context).expect_err("refused");
        assert_eq!((refusal.step, refusal.step.number()), expected);
        seen.push(refusal.step);
        match refusal.step {
            AdmissionStep::SenderPaired => context.sender_paired = true,
            AdmissionStep::PluginActive => context.plugin_active = true,
            AdmissionStep::ActionDeclared => context.action_declared = true,
            AdmissionStep::PluginGrant => context.granted = permissive().granted,
            AdmissionStep::HostCapability => {
                context.host_actions = vec![PlatformAction::OpenUrl]
            }
        }
    }
    assert_eq!(seen.len(), 5, "a step was skipped");
    assert_eq!(check(&context), Ok(()));
}
