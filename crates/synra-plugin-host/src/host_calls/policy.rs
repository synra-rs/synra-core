use super::{CallError, HostCalls, PluginId};

impl HostCalls<'_> {
/// A session that refuses the calls a pure function may not make.
    ///
    /// # ★ Why this is a separate constructor rather than a field a caller sets
    ///
    /// Because forgetting to set it would silently grant a plugin the side effects `can-handle` is not allowed to have,
    /// and the whole reason this exists is that the enforcement was missing once already. A constructor makes the
    /// question unskippable: a caller building host calls for a `can-handle` pass must say so, and the permissive one is
    /// named for what it is.
    ///
    /// The permissive default on [`HostCalls::new`] is for the calls that *are* allowed to act — `share.execute`,
    /// `lifecycle.*`, `actions.invoke` and the rest.
    #[must_use]
    pub const fn pure(mut self) -> Self {
        self.side_effects = false;
        self
    }

/// The host functions that change something outside the plugin.
    ///
    /// # ★ Why this list exists, and why it is written by hand
    ///
    /// Because "side effect" is not a property the gate table records. The generated table says which *capability* a function
    /// needs; whether the function merely reads or actually acts is a judgement about what it does, and only a reader of the
    /// contract can make it.
    ///
    /// The list is written with that in mind: it holds the functions whose whole purpose is an effect on the world — sending,
    /// writing, opening, fetching, transferring, invoking. What is deliberately **absent** is as important as what is here:
    /// `log` records a line in the kernel's own log, `env-*` reads a fact, `storage-get`
    /// and `secret-get` read. None of those is something a user would be surprised to learn happened while a share was being
    /// matched, and refusing them would break plugins that legitimately log or look up their own settings during matching.
    ///
    /// It is an associated constant rather than a free one because that is where it landed when it was written; the
    /// substance is unchanged. It is checked against the contract by a test, so a function added to the WIT file is either listed here or fails the
    /// suite — which is the only thing that keeps a hand-written list honest.
    pub(super) const ACTION_SHAPED: &'static [&'static str] = &[
        "event-emit",
        "device-send",
        "device-broadcast",
        "input-session",
        "storage-set",
        "storage-delete",
        "secret-set",
        "secret-delete",
        "network-fetch",
        "network-websocket",
        "transfer-send",
        "platform-open-url",
        "platform-open-path",
        "platform-reveal-path",
        "platform-simulate-keys",
        "platform-notify",
        "platform-write-clipboard",
        "action-declare",
        "action-invoke",
    ];

    /// Refuses an event a plugin may not emit.
    ///
    /// # ★ Why this exists, and why it is here
    ///
    /// Because `EventName::check_emittable_by` was written, tested and documented as the enforcement point — its own doc says
    /// *"The host calls this on every outbound plugin event. It is the difference between 'plugins have their own namespace'
    /// being true and it being a sentence in a document"* — and **the host did not call it**. Every one of its call sites was
    /// in its own test module.
    ///
    /// So the two things it exists to stop were both allowed:
    ///
    /// * a plugin emitting another plugin's event (`_plugin.<other>/something`), which is one plugin speaking as another;
    /// * a plugin emitting a host event (`_synra.device.changed`), which is a plugin telling the kernel, and every other
    ///   plugin, that something happened that did not.
    ///
    /// Both are the "forged events" threat design [11](11-design-principles.md) lists. Nothing was delivered to a plugin in
    /// this build, so there was no live exploit — and that is exactly why the check belongs here, in the host, before
    /// delivery exists rather than after.
    ///
    /// # Errors
    ///
    /// [`CallError::CAPABILITY_DENIED`] for foreign ownership or a host-reserved event;
    /// [`CallError::BAD_ARGUMENT`] when the name itself is malformed.
    pub(super) fn check_emittable(plugin: &PluginId, event: &str) -> Result<(), CallError> {
        let name = synra_protocol::event::EventName::parse(event)
            .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
        name.check_emittable_by(plugin)
            .map_err(|error| CallError::new(CallError::CAPABILITY_DENIED, error.to_string()))
    }
}
