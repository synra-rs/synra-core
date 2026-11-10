use synra_protocol::error::ErrorCode;

use super::Refusal;

/// What the kernel can be asked.
///
/// # Why the log is not a method
///
/// The log is the kernel's own, and a kernel that served it would be reading a file it is writing. The daemon supplies
/// it from [`synra_observe`]'s log directory, which is why it is a method here rather than a field: it may need to
/// re-read.
///
/// [`synra_observe`]: https://docs.rs/synra-observe
pub trait Kernel {
    /// The kernel's own version, for a bug report.
    fn version(&self) -> String;

    /// The kernel's state and its links, as one JSON value.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] when the kernel cannot answer — which is not "the kernel is not running", because a running kernel
    /// is the only thing that could have been asked.
    fn status(&self) -> Result<serde_json::Value, Refusal>;

    /// The devices the kernel has seen, as one JSON value.
    ///
    /// `scan_ms` is how long to look on the network before answering, and `None` means "answer from what you already
    /// know". It is a parameter rather than something the caller does because only the kernel holds a discovery socket.
    ///
    /// # Errors
    ///
    /// As [`Kernel::status`].
    fn devices(
        &self,
        include_unpaired: bool,
        scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal>;

    /// Sends text to a device.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::DeviceOffline`] and friends: the refusals a send produces are the kernel's, not this channel's.
    fn send_text(&self, to: &str, text: &str) -> Result<serde_json::Value, Refusal>;

    /// Sends a file to a device.
    ///
    /// # Errors
    ///
    /// As [`Kernel::send_text`], plus [`ErrorCode::InvalidArgument`] for a path that is not a readable file.
    fn send_file(&self, to: &str, path: &str) -> Result<serde_json::Value, Refusal>;

    /// Sends a plugin bundle to a device, for installation on the other side.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming what went wrong, or `ErrorCode::Unsupported` for a kernel that does not send bundles.
    fn send_bundle(
        &self,
        _to: &str,
        _path: &str,
        _plugin_id: &str,
        _version: &str,
    ) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not send plugin bundles"))
    }

    /// The installed plugins, as one JSON value.
    ///
    /// # Errors
    ///
    /// As [`Kernel::status`].
    fn plugins(&self) -> Result<serde_json::Value, Refusal>;

    /// Turns a plugin on or off.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when no plugin has that identifier, which is a different answer from "it was already in that state"
    /// — the second is a success, and a caller that could not tell them apart would report a typo as a no-op.
    fn plugin_set_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
    ) -> Result<serde_json::Value, Refusal>;

    /// Installs a plugin from a directory on this machine.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming the step that refused the package; [`ErrorCode::Unsupported`] by default.
    fn plugin_install(&self, _path: &str) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not install plugins"))
    }

    /// Installs a plugin the registry names.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Unsupported`] by default; the real kernel's refusals are the registry's and the installer's.
    fn plugin_install_package(
        &self,
        _package: &str,
        _version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not install plugins from a registry"))
    }

    /// Lists known publisher keys and trust decisions.
    ///
    /// # Errors
    /// Unsupported by default, or an implementation's storage error.
    fn plugin_publishers(&self) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not list publisher keys"))
    }

    /// Records the user's decision for the displayed publisher fingerprint.
    ///
    /// # Errors
    /// Unsupported by default, or invalid input, a stale key or a storage failure.
    fn plugin_publisher_decide(
        &self,
        _publisher_id: &str,
        _fingerprint: &str,
        _trust: &str,
    ) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not decide publisher trust"))
    }

    /// Reads or changes registry sources.
    ///
    /// # Errors
    /// Unsupported by default; implementations validate sources before writing.
    fn plugin_registry(&self, _urls: Option<&[String]>) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not configure plugin registries"))
    }

    /// Reads or changes background update policy.
    ///
    /// # Errors
    /// Unsupported by default; invalid policy names must be refused.
    fn plugin_update_policy(&self, _policy: Option<&str>) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not configure plugin updates"))
    }

    /// Checks metadata without automatically applying any candidate.
    ///
    /// # Errors
    /// Unsupported by default, or the implementation's source and target errors.
    fn plugin_check_updates(&self, _plugin: Option<&str>) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not check plugin updates"))
    }

    /// Updates an installed plugin through the normal verification and lifecycle path.
    ///
    /// # Errors
    /// Unsupported by default, or the implementation's verification and update refusals.
    fn plugin_update(
        &self,
        _plugin: &str,
        _version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not update plugins"))
    }

    /// Records the user's decision about a plugin's capabilities.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when no plugin has that identifier, or when a granted capability is one the plugin does not declare;
    /// [`ErrorCode::Unsupported`] by default.
    fn plugin_consent(
        &self,
        _plugin_id: &str,
        _granted: &[String],
    ) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not record plugin consent"))
    }

    /// Removes a plugin, and its data when `remove_data` is true.
    ///
    /// # Errors
    ///
    /// [`Refusal`] with [`ErrorCode::PluginNotInstalled`] when no plugin has that identifier, [`ErrorCode::Internal`] when
    /// the row or the files cannot be removed; [`ErrorCode::Unsupported`] by default.
    fn plugin_remove(
        &self,
        _plugin_id: &str,
        _remove_data: bool,
    ) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel does not remove plugins"))
    }

    /// Searches the plugin catalogue.
    ///
    /// # Why this has a default body
    ///
    /// Because a kernel without a catalogue is a kernel, not a broken one — and every implementor of this trait outside this
    /// workspace would otherwise stop compiling for a command it may never be asked. The default **refuses**, rather than
    /// answering with an empty list: "no plugins match" and "this kernel cannot search" are different facts, and a screen that
    /// could not tell them apart would show an empty catalogue for a host that has no registry configured at all.
    ///
    /// # The design's offline row
    ///
    /// The answer carries where it came from, because the design asks for a cached packument to be **used and announced**
    /// when no registry answers. A caller that could not tell a live answer from a seven-day-old one would be showing a
    /// catalogue it cannot vouch for.
    ///
    /// # Errors
    ///
    /// [`Refusal`] with [`ErrorCode::Unsupported`] by default; the daemon's implementation answers
    /// [`ErrorCode::DeviceOffline`] when nothing answered and nothing was cached.
    fn catalog_search(&self, _package: &str) -> Result<serde_json::Value, Refusal> {
        Err(unsupported("this kernel has no plugin catalogue"))
    }

    /// Hands the kernel something to route.
    ///
    /// # ★ Why this is the method that makes the kernel do its job
    ///
    /// Because routing is what the product is: something arrives — a link, a file, a line of text — and a plugin that
    /// can act on it is found, offered to the user, and run. `synra-core` implements every part of that and **nothing
    /// could reach it**: the control protocol had no intent request, so the matcher had no production caller, and a share
    /// that arrived became a file in an inbox rather than an action.
    ///
    /// # What the answer carries
    ///
    /// The candidates the plugins offered, plus the pass's own report — how many were asked, how many declined, and
    /// which of them misbehaved. Those together are what distinguish "nothing is installed" from "everything crashed",
    /// which look identical from a candidate list alone.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the item cannot be read into the shape a plugin is asked about.
    fn intent_dispatch(&self, mime: &str, text: &str) -> Result<serde_json::Value, Refusal>;

    /// What has become of an intent.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten.
    fn intent_snapshot(&self, intent: &str) -> Result<serde_json::Value, Refusal>;

    /// Applies the user's answer to a prompt, and runs what they chose.
    ///
    /// # ★ Why this is where an action finally happens
    ///
    /// Because everything before it is a question. `intent_dispatch` asks every plugin whether it can handle a share;
    /// this is the one place where the answer becomes an action, and it happens only for the plugin the user picked.
    /// Keeping the two apart is what stops "what can handle this?" from running third-party code as a side effect.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the intent is unknown, is not in a state that can be decided, or names a plugin that was not
    /// among the candidates — a choice that was never offered must not run.
    fn intent_decide(
        &self,
        intent: &str,
        plugin_id: Option<&str>,
        target: Option<&str>,
    ) -> Result<serde_json::Value, Refusal>;

    /// The user changed their mind.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the intent is unknown or has already finished. Cancelling something that is over is not a
    /// failure a user should see, but it is also not a cancellation, and the answer says which happened.
    fn intent_cancel(&self, intent: &str) -> Result<serde_json::Value, Refusal>;

    /// The tail of the kernel's log.
    ///
    /// # Errors
    ///
    /// As [`Kernel::status`].
    fn logs(
        &self,
        lines: usize,
        verbose: bool,
        trace: Option<&str>,
    ) -> Result<serde_json::Value, Refusal>;

}

fn unsupported(message: &str) -> Refusal {
    Refusal::new(ErrorCode::Unsupported, message)
}
