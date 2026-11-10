use synra_capability::{Capability, CapabilitySet};
use synra_platform::PlatformAction;

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
