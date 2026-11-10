use proptest::prelude::*;
use synra_capability::{Capability, CapabilitySet};
use synra_platform::PlatformAction;
use synra_protocol::ErrorCode;

use super::{AdmissionContext, AdmissionRefusal, AdmissionStep, admit, check, host_requirement};
use super::tests::{capability, invocation};

/// A set built from already-parsed capabilities.
///
/// The generators below produce capabilities rather than strings, so binding them through the string form would
/// re-parse what was just parsed. A generated capability is valid by construction, so an insertion cannot fail for
/// a reason the test would need to report.
fn set_of_capabilities(capabilities: Vec<Capability>) -> CapabilitySet {
    let mut set = CapabilitySet::new();
    for capability in capabilities {
        let _ = set.insert(capability);
    }
    set
}

/// A capability drawn from the set the admission checks care about.
fn arbitrary_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        Just(capability("device:send:peer")),
        Just(capability("platform:open-url")),
        Just(capability("platform:notify")),
        Just(capability("network:fetch:api.example.com")),
        Just(capability("storage:local:read")),
    ]
}

proptest! {
    /// An admitted intent is one whose every required capability the plugin holds. The property is the
    /// contrapositive of step 5 and the thing an attacker would try to defeat: no combination of grants and
    /// requirements produces an admission with a capability missing.
    #[test]
    fn an_admission_never_leaves_a_requirement_ungranted(
        granted in proptest::collection::vec(arbitrary_capability(), 0..5),
        required in proptest::collection::vec(arbitrary_capability(), 0..5),
        actions_mask in 0u8..128,
        has_network in any::<bool>(),
    ) {
        let granted_set = set_of_capabilities(granted);
        let host_actions: Vec<PlatformAction> = [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ]
        .into_iter()
        .enumerate()
        .filter(|(bit, _)| actions_mask & (1 << bit) != 0)
        .map(|(_, action)| action)
        .collect();

        let context = AdmissionContext::new(granted_set)
            .with_required(required.clone())
            .with_host_actions(host_actions.clone())
            .with_host_network(has_network);

        if check(&context).is_ok() {
            for capability in &required {
                prop_assert!(
                    context.granted.contains(capability),
                    "admitted without {:?}",
                    capability.to_string(),
                );
                if let Some(action) = host_requirement(capability) {
                    prop_assert!(
                        host_actions.contains(&action),
                        "admitted {} on a host without {}",
                        capability.to_string(),
                        action,
                    );
                }
                if capability.domain() == synra_capability::Domain::Network {
                    prop_assert!(has_network, "admitted a network call with no network");
                }
            }
        }
    }

    /// The refusal always names the earliest failing step, whatever combination of conditions is supplied. A
    /// sequence that reported a later step would tell a sender about a permission problem when the real answer is
    /// that the device is not paired.
    #[test]
    fn the_refusal_is_always_the_earliest_failing_step(
        paired in any::<bool>(),
        active in any::<bool>(),
        declared in any::<bool>(),
        granted in proptest::collection::vec(arbitrary_capability(), 0..4),
        required in proptest::collection::vec(arbitrary_capability(), 0..4),
        actions_mask in 0u8..128,
        has_network in any::<bool>(),
    ) {
        let granted_set = set_of_capabilities(granted);
        let context = AdmissionContext::new(granted_set)
            .with_sender_paired(paired)
            .with_plugin_active(active)
            .with_action_declared(declared)
            .with_required(required.clone())
            .with_host_actions(
                (0..7u8)
                    .filter(|bit| actions_mask & (1 << bit) != 0)
                    // An array rather than a `match` over the bit number: the bits are a mask over exactly these seven
            // actions, so the mapping is a lookup and every bit has an answer.
            .map(|bit| {
                const ACTIONS: [PlatformAction; 7] = [
                    PlatformAction::OpenUrl,
                    PlatformAction::OpenPath,
                    PlatformAction::RevealPath,
                    PlatformAction::SimulateKeys,
                    PlatformAction::ReadClipboard,
                    PlatformAction::WriteClipboard,
                    PlatformAction::Notify,
                ];
                ACTIONS[usize::from(bit).min(ACTIONS.len() - 1)]
            })
                    .collect(),
            )
            .with_host_network(has_network);

        let expectation = if !paired {
            Some(AdmissionStep::SenderPaired)
        } else if !active {
            Some(AdmissionStep::PluginActive)
        } else if !declared {
            Some(AdmissionStep::ActionDeclared)
        } else if required.iter().any(|capability| !context.granted.contains(capability)) {
            Some(AdmissionStep::PluginGrant)
        } else if required.iter().any(|capability| {
            host_requirement(capability).is_some_and(|action| !context.host_actions.contains(&action))
                || (capability.domain() == synra_capability::Domain::Network && !has_network)
        }) {
            Some(AdmissionStep::HostCapability)
        } else {
            None
        };

        match (check(&context), expectation) {
            (Ok(()), None) => {}
            (Err(refusal), Some(step)) => prop_assert_eq!(refusal.step, step),
            (Ok(()), Some(step)) => prop_assert!(false, "admitted but {} should have failed", step),
            (Err(refusal), None) => prop_assert!(false, "refused at {} but nothing should have failed", refusal.step),
        }
    }

    /// A transient refusal is one the sender could plausibly succeed after; a non-transient one never is. Only two
    /// steps are transient, and labelling more would have a sender retry against a wall.
    #[test]
    fn only_two_steps_are_transient(
        step_index in 0usize..5,
        detail in "[a-z ]{0,20}",
    ) {
        let steps = [
            AdmissionStep::SenderPaired,
            AdmissionStep::PluginActive,
            AdmissionStep::ActionDeclared,
            AdmissionStep::PluginGrant,
            AdmissionStep::HostCapability,
        ];
        let refusal = AdmissionRefusal {
            step: steps[step_index],
            detail,
            code: ErrorCode::Internal,
        };
        let expected = matches!(steps[step_index], AdmissionStep::PluginActive | AdmissionStep::HostCapability);
        prop_assert_eq!(refusal.is_transient(), expected);
    }

    /// The outcome and the check always agree: a successful outcome means `check` passed, and a failed one means it
    /// did not. A sender that received `ok: true` for a refused intent would proceed as if the action had happened.
    #[test]
    fn the_outcome_agrees_with_the_check(
        paired in any::<bool>(),
        granted in proptest::collection::vec(arbitrary_capability(), 0..4),
        required in proptest::collection::vec(arbitrary_capability(), 0..4),
    ) {
        let granted_set = set_of_capabilities(granted);
        let context = AdmissionContext::new(granted_set)
            .with_sender_paired(paired)
            .with_required(required);
        let invocation = invocation();
        let outcome = admit(&invocation, &context);

        prop_assert_eq!(outcome.ok, check(&context).is_ok());
        if outcome.ok {
            prop_assert!(outcome.error.is_none());
        }
        else {
            prop_assert!(outcome.error.is_some());
        }
    }
}
