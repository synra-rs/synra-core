use core::fmt;

use serde::{Deserialize, Serialize};
use synra_capability::Capability;
use synra_platform::PlatformAction;
use synra_protocol::session::{IntentInvocation, IntentOutcome};
use synra_protocol::{ErrorCode, PluginId, SynraError};

use super::context::AdmissionContext;

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
    let resource = capability
        .prefixes()
        .first()
        .map(synra_capability::Segment::as_str)?;
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
