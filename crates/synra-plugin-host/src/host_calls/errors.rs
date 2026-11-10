use serde::{Deserialize, Serialize};
use synra_capability::CapabilitySet;

/// What a plugin is told when a call does not proceed.
///
/// # Why this is a value and not a trap
///
/// Because Wasm has no exceptions and a trap is for an unrecoverable bug. A plugin that asked for a capability it does
/// not hold has *failed*, which is something it can handle — hide a button, log a line, try another way. A host that
/// trapped here would turn a permission decision into a crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("{code}: {message}")]
pub struct CallError {
    /// A stable code a plugin branches on, rather than a sentence it parses.
    pub code: &'static str,
    /// What happened, for a log line and for a developer.
    pub message: String,
    /// Anything else that helps, as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl CallError {
    /// The plugin asked for a function this host does not have.
    pub const UNKNOWN_FUNCTION: &'static str = "unknownFunction";
    /// The plugin does not hold the capability the function needs.
    pub const CAPABILITY_DENIED: &'static str = "capabilityDenied";
    /// The plugin called faster than its rate limit allows.
    pub const RATE_LIMITED: &'static str = "rateLimited";
    /// The call would put the plugin over one of its quotas.
    ///
    /// # ★ Why this is not `rateLimited`
    ///
    /// Because a plugin's next step is different. A rate limit is about *how often* and its answer is to wait; a quota is
    /// about *how much* and its answer is to store less — retrying a quota overrun changes nothing. The design names this
    /// failure `PluginQuotaExceeded` in its own vocabulary, and folding it into the frequency code would tell a plugin to
    /// sleep when it should be tidying up.
    pub const QUOTA_EXCEEDED: &'static str = "quotaExceeded";
    /// The argument is not what the function takes.
    pub const BAD_ARGUMENT: &'static str = "badArgument";
    /// The host could not do it, for a reason that is not the plugin's fault.
    pub const HOST_FAILED: &'static str = "hostFailed";

    /// The host does not implement this at all.
    ///
    /// # ★ Why this is a code and not silence
    ///
    /// Because the difference between "not implemented here" and "you are not allowed" is the difference between a plugin
    /// hiding a feature and a user hunting for a permission they already granted. A host that cannot do something must
    /// say so in a way a plugin can branch on.
    ///
    /// It exists because a code was needed and none of the others fit: `hostFailed` says the host tried and could not,
    /// which is a different fact from "this build has no such feature at all".
    pub const NOT_IMPLEMENTED: &'static str = "notImplemented";

    /// The call would have a side effect, and this one may not.
    ///
    /// # ★ Why this is not `capabilityDenied`
    ///
    /// Because the plugin **holds** the capability — that is why the gate let the call through to this check. What it
    /// may not do is exercise it *here*, during a pure matching pass. Reporting `capabilityDenied` would send a user to a
    /// settings screen to grant something they already granted.
    pub const SIDE_EFFECT_NOT_ALLOWED: &'static str = "sideEffectNotAllowed";

    /// A refusal.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// The same refusal with more to say.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// The refusal for a capability the plugin does not hold.
    ///
    /// # ★ Why this takes the granted set as well as the missing capability
    ///
    /// Because the three things the design asks a refusal to carry are not answerable from the missing one alone. An author
    /// reading "you need `storage:local:write`" cannot tell whether their plugin is one permission short of something the
    /// user already trusts it with, or holds nothing in that domain at all — and those are different problems with
    /// different answers. `synra_capability::error::CapabilityDenied` derives all three, and the suggestion it produces is
    /// a fact about the two sets rather than a sentence somebody wrote by hand.
    #[must_use]
    pub fn denied(capability: &str, held: &CapabilitySet) -> Self {
        let refused = synra_capability::error::CapabilityDenied::of(capability, held);
        Self::new(Self::CAPABILITY_DENIED, refused.to_string()).with_details(refused.to_json())
    }

    /// The refusal for a function no host provides.
    #[must_use]
    pub fn unknown(import: &str) -> Self {
        Self::new(
            Self::UNKNOWN_FUNCTION,
            format!("`{import}` is not a host function"),
        )
    }
}

/// The JSON answer a host call returns, or the reason it was refused.
pub type CallResult = Result<String, CallError>;
