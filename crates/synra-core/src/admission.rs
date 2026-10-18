//! Intent admission: the eight checks a cross-device action has to pass before anything runs.
//!
//! # Why the order is part of the design
//!
//! The checks are a sequence, and each one is cheaper and more fundamental than the next. Running them in order means
//! a malformed request is refused before the kernel looks anything up, and a request from an unpaired device is
//! refused before the kernel consults the plugin registry — which is the difference between a stream of junk costing
//! a hash lookup each and a stream of junk costing a database query each.
//!
//! The order also decides *which* refusal a caller sees, and that matters because the refusals are acted on
//! differently:
//!
//! 1. **Envelope** — already checked by the time this runs; a violation closes the link.
//! 2. **Is the sender paired?** An unpaired source is not a plugin's problem, and the answer is not "denied" but
//!    "who are you".
//! 3. **Is the plugin installed and active?** If not, nothing else can be true.
//! 4. **Does the plugin declare this action?** A declared action is a promise; an undeclared one is a caller
//!    inventing an interface.
//! 5. **Does the grant cover what the action needs?** The plugin's own permissions.
//! 6. **Can this host do it at all?** Checked *before* step 8, so a plugin is not started to do something this
//!    machine cannot do — the design document's "so the plugin does not run for nothing".
//! 7. **Is this a duplicate?** Answered from the reply cache when it is, without running anything.
//! 8. **Run it.**
//!
//! # Why the capabilities are resolved rather than stored per action
//!
//! An action's declaration carries a JSON Schema for its arguments, not a capability list. The capability an action
//! needs is derived from what it *does* — `platform:open-url` for a handler that opens a URL, `device:send:<target>`
//! for one that sends to a target — and the derivation is the plugin author's declaration in the manifest plus the
//! arguments. So the caller supplies the required capabilities, having resolved them, and this module decides whether
//! the host and the plugin can meet them.

use core::fmt;

use serde::{Deserialize, Serialize};
use synra_capability::{Capability, CapabilitySet};
use synra_platform::PlatformAction;
use synra_protocol::session::{IntentInvocation, IntentOutcome};
use synra_protocol::{ErrorCode, PluginId, SynraError};

/// What the kernel knows when an intent arrives.
///
/// A struct rather than a dozen parameters, because the checks read different parts of it and a caller assembling the
/// arguments at each call site would eventually pass them in the wrong order — and two of these are `bool`s.
#[derive(Debug, Clone)]
pub struct AdmissionContext {
    /// Whether the sender is a paired device.
    pub sender_paired: bool,
    /// Whether the plugin is installed and active on this device.
    pub plugin_active: bool,
    /// Whether the plugin's manifest declares the action.
    pub action_declared: bool,
    /// What the plugin has been granted.
    pub granted: CapabilitySet,
    /// What the plugin declared it needs for this call.
    ///
    /// Resolved by the caller from the action's declaration and the arguments, because the derivation needs the
    /// argument values — `device:send:<target>` names the target.
    pub required: Vec<Capability>,
    /// What this host can actually do.
    pub host_actions: Vec<PlatformAction>,
    /// Whether the host can reach the network at all, for a capability that needs it.
    pub host_has_network: bool,
}

impl AdmissionContext {
    /// A context for a paired sender and an active plugin that declares the action.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(granted: CapabilitySet) -> Self {
        Self {
            sender_paired: true,
            plugin_active: true,
            action_declared: true,
            granted,
            required: Vec::new(),
            host_actions: Vec::new(),
            host_has_network: true,
        }
    }

    /// Sets whether the sender is paired.
    #[must_use]
    pub const fn with_sender_paired(mut self, paired: bool) -> Self {
        self.sender_paired = paired;
        self
    }

    /// Sets whether the plugin is active.
    #[must_use]
    pub const fn with_plugin_active(mut self, active: bool) -> Self {
        self.plugin_active = active;
        self
    }

    /// Sets whether the action is declared.
    #[must_use]
    pub const fn with_action_declared(mut self, declared: bool) -> Self {
        self.action_declared = declared;
        self
    }

    /// Sets what the plugin needs.
    #[must_use]
    pub fn with_required(mut self, required: Vec<Capability>) -> Self {
        self.required = required;
        self
    }

    /// Sets what the host can do.
    #[must_use]
    pub fn with_host_actions(mut self, actions: Vec<PlatformAction>) -> Self {
        self.host_actions = actions;
        self
    }

    /// Sets whether the host has a network.
    #[must_use]
    pub const fn with_host_network(mut self, has: bool) -> Self {
        self.host_has_network = has;
        self
    }
}

/// Which check refused an intent.
///
/// Numbered to match the design document's sequence, so a log line or an audit record names the step and a reader can
/// find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AdmissionStep {
    /// The sender is not a paired device.
    SenderPaired,
    /// The plugin is not installed and active.
    PluginActive,
    /// The plugin does not declare the action.
    ActionDeclared,
    /// The plugin's grant does not cover what the action needs.
    PluginGrant,
    /// This host cannot do what the action needs.
    HostCapability,
}

impl AdmissionStep {
    /// The step's number in the design document's sequence.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::SenderPaired => 2,
            Self::PluginActive => 3,
            Self::ActionDeclared => 4,
            Self::PluginGrant => 5,
            Self::HostCapability => 6,
        }
    }

    /// A name for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SenderPaired => "sender-paired",
            Self::PluginActive => "plugin-active",
            Self::ActionDeclared => "action-declared",
            Self::PluginGrant => "plugin-grant",
            Self::HostCapability => "host-capability",
        }
    }
}

impl fmt::Display for AdmissionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {} ({})", self.number(), self.as_str())
    }
}

/// Why an intent was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("the intent was refused at step {step}: {detail}")]
pub struct AdmissionRefusal {
    /// Which check refused it.
    pub step: AdmissionStep,
    /// What was missing, in a sentence the interface can show.
    pub detail: String,
    /// The error code returned to the sender.
    pub code: ErrorCode,
}

impl AdmissionRefusal {
    /// Whether the sender could succeed by asking again later.
    ///
    /// Only two of these are transient: a plugin that is being installed, and a host whose network is down. The rest
    /// are conditions the sender cannot change, and telling it to retry would have it retry forever.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self.step,
            // A plugin that is not active may be starting or may have been disabled; either way the sender has no
            // way to tell, and the honest answer is that it might work later.
            AdmissionStep::PluginActive | AdmissionStep::HostCapability
        )
    }
}

/// Runs the admission checks and produces the outcome to send back.
///
/// The returned [`IntentOutcome`] is what the sender receives, so a refusal is a normal result rather than a protocol
/// error: the receiving device understood the request and decided not to perform it, and the sender should be told
/// why in a form it can show a user.
#[must_use]
pub fn admit(invocation: &IntentInvocation, context: &AdmissionContext) -> IntentOutcome {
    match check(context) {
        Ok(()) => IntentOutcome::ok(invocation.intent_id, None, 0),
        Err(refusal) => IntentOutcome::failed(
            invocation.intent_id,
            SynraError::new(refusal.code, refusal.detail),
            0,
        ),
    }
}

/// Runs the checks without producing an outcome.
///
/// # Errors
///
/// [`AdmissionRefusal`] naming the first check that failed.
pub fn check(context: &AdmissionContext) -> Result<(), AdmissionRefusal> {
    // Step 2. An intent is not accepted from an unpaired source at all, so this is a refusal about identity rather
    // than about permission — and the reason it comes first is that nothing below it means anything for a sender the
    // kernel does not know.
    if !context.sender_paired {
        return Err(AdmissionRefusal {
            step: AdmissionStep::SenderPaired,
            detail: "the sending device is not paired with this one".to_owned(),
            code: ErrorCode::NotPaired,
        });
    }

    // Step 3.
    if !context.plugin_active {
        return Err(AdmissionRefusal {
            step: AdmissionStep::PluginActive,
            detail: "the plugin is not installed and active on this device".to_owned(),
            code: ErrorCode::PluginNotInstalled,
        });
    }

    // Step 4. A declared action is a promise; an undeclared one is a caller inventing an interface.
    if !context.action_declared {
        return Err(AdmissionRefusal {
            step: AdmissionStep::ActionDeclared,
            detail: "the plugin does not declare that action".to_owned(),
            code: ErrorCode::Unsupported,
        });
    }

    // Step 5. Every capability is checked, not the first: the refusal names the whole set that is missing, because a
    // user granting one permission at a time should not have to trigger the call repeatedly to discover the list.
    let missing: Vec<String> = context
        .required
        .iter()
        .filter(|capability| !context.granted.contains(capability))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(AdmissionRefusal {
            step: AdmissionStep::PluginGrant,
            detail: format!("the plugin has not been granted {}", missing.join(", ")),
            code: ErrorCode::CapabilityDenied,
        });
    }

    // Step 6. Checked before the plugin runs, so a plugin is not started to do something this machine cannot do.
    let missing_host: Vec<&'static str> = context
        .required
        .iter()
        .filter_map(host_requirement)
        .filter(|action| !context.host_actions.contains(action))
        .map(PlatformAction::risk)
        .collect();
    if !missing_host.is_empty() {
        return Err(AdmissionRefusal {
            step: AdmissionStep::HostCapability,
            // The action's own description rather than the capability string: this text reaches a user, and
            // `platform:open-url` is a name for the manifest, not for a person. Each description already begins with
            // "can", so they are joined onto "this device" rather than each prefixed with "cannot".
            detail: format!("this device {}", missing_host.join("; ")),
            code: ErrorCode::Unsupported,
        });
    }
    if !context.host_has_network
        && context
            .required
            .iter()
            .any(|capability| capability.domain() == synra_capability::Domain::Network)
    {
        return Err(AdmissionRefusal {
            step: AdmissionStep::HostCapability,
            detail: "this device has no network connection".to_owned(),
            code: ErrorCode::DeviceOffline,
        });
    }

    Ok(())
}

/// The host action a capability needs, if it needs one.
///
/// Derived from the capability rather than looked up in a table of actions, because the capability string is what the
/// plugin was granted and the host action is what the machine does — and keeping the mapping in one function means a
/// new capability cannot be added without deciding whether it needs a host action.
#[must_use]
pub fn host_requirement(capability: &Capability) -> Option<PlatformAction> {
    if capability.domain() != synra_capability::Domain::Platform {
        return None;
    }
    let resource = capability.prefixes().first().map(synra_capability::Segment::as_str)?;
    match resource {
        "open-url" => Some(PlatformAction::OpenUrl),
        "open-path" => Some(PlatformAction::OpenPath),
        "reveal-path" => Some(PlatformAction::RevealPath),
        "simulate-keys" => Some(PlatformAction::SimulateKeys),
        "read-clipboard" => Some(PlatformAction::ReadClipboard),
        "write-clipboard" => Some(PlatformAction::WriteClipboard),
        "notify" => Some(PlatformAction::Notify),
        _ => None,
    }
}

/// A plugin's identifier as the kernel holds it.
///
/// A newtype rather than a bare `String`, so a device id cannot be passed where a plugin id is wanted — the two are
/// both opaque strings and would otherwise be interchangeable at every call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PluginKey(String);

impl PluginKey {
    /// Wraps an identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The plugin id as the protocol sees it.
    ///
    /// # Errors
    ///
    /// The parse error, if the key was not built from a validated id.
    pub fn to_plugin_id(&self) -> Result<PluginId, synra_protocol::ids::IdError> {
        PluginId::parse(&self.0)
    }
}

impl fmt::Display for PluginKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&PluginId> for PluginKey {
    fn from(id: &PluginId) -> Self {
        Self(id.as_str().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::ids::IntentId;

    fn capability(text: &str) -> Capability {
        Capability::parse(text).expect("a valid capability")
    }

    pub(super) fn invocation() -> IntentInvocation {
        IntentInvocation {
            intent_id: IntentId::new(),
            plugin_id: PluginId::parse("@synra-plugin/chat").expect("a valid id"),
            action: "send-message".to_owned(),
            args: serde_json::value::RawValue::from_string("{}".to_owned()).expect("valid JSON"),
            display: None,
        }
    }

    /// A capability set built from strings, failing the test rather than the caller if one is malformed.
    fn set_of(texts: &[&str]) -> CapabilitySet {
        let mut set = CapabilitySet::new();
        for text in texts {
            set.insert_str(text).expect("a valid capability");
        }
        set
    }

    /// A context whose plugin holds everything.
    fn permissive() -> AdmissionContext {
        AdmissionContext::new(set_of(&["device:send:*", "platform:open-url", "network:fetch:*"]))
    }

    // ── The sequence ──────────────────────────────────────────────────────────────────────────────

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
                assert!(refusal.detail.contains("device:send:peer"), "{}", refusal.detail);
                assert!(refusal.detail.contains("platform:open-url"), "{}", refusal.detail);
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
                AdmissionStep::HostCapability => context.host_actions = vec![PlatformAction::OpenUrl],
            }
        }
        assert_eq!(seen.len(), 5, "a step was skipped");
        assert_eq!(check(&context), Ok(()));
    }

    // ── Host requirements ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_platform_capability_maps_to_a_host_action() {
        // Keeping the mapping in one function means a new capability cannot be added without deciding whether it needs
        // a host action — and a capability that needed one and had none would be admitted on a host that cannot do it.
        let expected = [
            ("platform:open-url", PlatformAction::OpenUrl),
            ("platform:open-path", PlatformAction::OpenPath),
            ("platform:reveal-path", PlatformAction::RevealPath),
            ("platform:simulate-keys", PlatformAction::SimulateKeys),
            ("platform:read-clipboard", PlatformAction::ReadClipboard),
            ("platform:write-clipboard", PlatformAction::WriteClipboard),
            ("platform:notify", PlatformAction::Notify),
        ];
        for (text, action) in expected {
            assert_eq!(host_requirement(&capability(text)), Some(action), "{text}");
        }
    }

    #[test]
    fn a_non_platform_capability_needs_no_host_action() {
        // A device send or a filesystem read is not something the operating system has to be asked about, and reporting
        // one would refuse the call on a host with no platform actions at all.
        for text in ["device:send:peer", "storage:local:read", "network:fetch:api.example.com", "log:*"] {
            assert_eq!(host_requirement(&capability(text)), None, "{text}");
        }
    }

    #[test]
    fn a_platform_capability_with_no_action_is_not_a_host_requirement() {
        // `platform:*` is a grant over the domain with no specific action, so there is nothing for the host to be
        // asked about. It is still a capability the plugin must hold, which step 5 covers.
        assert_eq!(host_requirement(&capability("platform:*")), None);
        // A platform resource with no action this host knows: still a capability, still nothing to ask the OS about.
        assert_eq!(host_requirement(&capability("platform:unknown")), None);
    }

    #[test]
    fn every_step_explains_itself_for_a_log_line() {
        for step in [
            AdmissionStep::SenderPaired,
            AdmissionStep::PluginActive,
            AdmissionStep::ActionDeclared,
            AdmissionStep::PluginGrant,
            AdmissionStep::HostCapability,
        ] {
            assert!(!step.as_str().is_empty(), "{step:?}");
            assert!(!step.as_str().contains(' '), "{step:?}");
            assert!(step.number() >= 2 && step.number() <= 6, "{step:?}");
            // The display form names both, so a reader can find the step in the design document.
            let text = step.to_string();
            assert!(text.contains(step.as_str()), "{text}");
            assert!(text.contains(&step.number().to_string()), "{text}");
        }
    }

    #[test]
    fn a_refusal_displays_the_step_and_the_reason() {
        let refusal = AdmissionRefusal {
            step: AdmissionStep::PluginGrant,
            detail: "the plugin has not been granted device:send:peer".to_owned(),
            code: ErrorCode::CapabilityDenied,
        };
        let text = refusal.to_string();
        assert!(text.contains("step 5"), "{text}");
        assert!(text.contains("device:send:peer"), "{text}");
    }

    // ── Outcomes ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_accepted_intent_produces_a_successful_outcome() {
        let invocation = invocation();
        let outcome = admit(&invocation, &permissive());
        assert!(outcome.ok);
        assert_eq!(outcome.intent_id, invocation.intent_id);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn a_refused_intent_produces_a_structured_outcome_rather_than_a_protocol_error() {
        // The receiving device understood the request and decided not to perform it, so the sender is told why in a
        // form it can show a user — not given a protocol failure it would report as a connection problem.
        let invocation = invocation();
        let context = permissive().with_sender_paired(false);
        let outcome = admit(&invocation, &context);
        assert!(!outcome.ok);
        assert_eq!(outcome.intent_id, invocation.intent_id);
        let error = outcome.error.expect("an error report");
        assert_eq!(error.code, ErrorCode::NotPaired);
        assert!(!error.message.is_empty());
    }

    #[test]
    fn a_refusal_reaches_the_sender_with_its_reason() {
        // The message is what the sender shows, so a refusal that lost its detail would be a call the user cannot
        // diagnose.
        let invocation = invocation();
        let context = AdmissionContext::new(CapabilitySet::new())
            .with_required(vec![capability("device:send:peer")]);
        let outcome = admit(&invocation, &context);
        let error = outcome.error.expect("an error report");
        assert!(
            error.message.contains("device:send:peer"),
            "the refusal lost its detail: {}",
            error.message
        );
    }

    // ── Keys ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_key_round_trips_through_an_id() {
        let id = PluginId::parse("@synra-plugin/chat").expect("a valid id");
        let key = PluginKey::from(&id);
        assert_eq!(key.as_str(), "@synra-plugin/chat");
        assert_eq!(key.to_plugin_id().expect("parses"), id);
        assert_eq!(key.to_string(), "@synra-plugin/chat");
    }

    #[test]
    fn a_plugin_key_that_is_not_a_valid_id_says_so_rather_than_panicking() {
        // A key can be built from a stored string, and a stored string can be from an older version.
        let key = PluginKey::new("not an id");
        assert!(key.to_plugin_id().is_err());
        assert_eq!(key.as_str(), "not an id");
    }

    #[test]
    fn a_plugin_key_orders_deterministically() {
        // The key is used as a map key and, in the registry, as part of a sorted route list — so its ordering has to be
        // stable rather than depending on insertion order.
        let mut keys = [
            PluginKey::new("@b/plugin"),
            PluginKey::new("@a/plugin"),
            PluginKey::new("@c/plugin"),
        ];
        keys.sort();
        let names: Vec<&str> = keys.iter().map(PluginKey::as_str).collect();
        assert_eq!(names, vec!["@a/plugin", "@b/plugin", "@c/plugin"]);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// A capability from the set the admission checks care about.
    fn capability(text: &str) -> Capability {
        Capability::parse(text).expect("a valid capability")
    }

    /// An invocation, for a test that needs one.
    ///
    /// Bound through an alias so the qualified path is written once: the unit-test module is the only place an
    /// invocation is constructed, and repeating its path at every use makes the property tests harder to read than the
    /// thing they assert.
    fn invocation() -> IntentInvocation {
        use crate::admission::tests as fixtures;
        fixtures::invocation()
    }

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
}
