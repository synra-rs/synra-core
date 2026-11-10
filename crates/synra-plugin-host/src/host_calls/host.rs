use synra_protocol::ids::PluginId;

use super::{CallError, PlatformAction};

/// What a host can do for a plugin.
///
/// # Why every function here is semantic rather than mechanical
///
/// `storage_get` rather than "read these bytes at this offset". The mechanical layer is the plugin's own storage
/// implementation, and it is behind this trait: what the gate, the rate limit and the audit record are about is *what
/// the plugin asked for*, so that is the unit the host sees.
///
/// # Why the answers are `Result` rather than values
///
/// Because the implementations are fallible for reasons that are not the plugin's fault — a keychain that is locked, a
/// device that went away between the list and the send — and a trait that could not express that would have to make
/// those look like a plugin error. [`CallError::HOST_FAILED`] is what they become.
#[allow(clippy::missing_errors_doc)]
pub trait Host: Send + Sync {
    /// The host SDK's version.
    fn sdk_version(&self) -> String;
    /// What kind of host this is: `desktop`, `mobile` or `headless`.
    fn host_kind(&self) -> String;
    /// The user's locale, as a BCP 47 tag.
    fn locale(&self) -> String;
    /// Whether the interface is in a dark theme.
    fn dark_mode(&self) -> bool;
    /// Whether a plugin holds a capability, without using it.
    fn can(&self, plugin: &PluginId, capability: &str) -> bool;
    /// Which platform actions this host can perform at all.
    fn platform_capabilities(&self) -> Vec<String>;

    /// Write a line to the kernel's log.
    fn log(
        &self,
        plugin: &PluginId,
        level: &str,
        message: &str,
        context: Option<&str>,
    ) -> Result<(), CallError>;
    /// Publish an event to whoever subscribed.
    fn event_emit(&self, plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError>;

    /// Every device this kernel can see, as `(id, name, kind)`.
    fn devices(&self) -> Vec<(String, String, String)>;
    /// Send an event to one device.
    fn device_send(
        &self,
        plugin: &PluginId,
        target: &str,
        event: &str,
        payload: &str,
    ) -> Result<(), CallError>;
    /// Manage a bounded, leased real-time input connection owned by this plugin.
    /// # Errors
    /// Hosts without input session support refuse the operation.
    fn input_session(&self, _plugin: &PluginId, _request: &str) -> Result<String, CallError> {
        Err(CallError::unknown("input-session"))
    }
    /// Send an event to every paired device.
    fn device_broadcast(
        &self,
        plugin: &PluginId,
        event: &str,
        payload: &str,
    ) -> Result<(), CallError>;

    /// Read a value, or `None` when the key is absent.
    fn storage_get(&self, plugin: &PluginId, key: &str) -> Result<Option<String>, CallError>;
    /// Write a value.
    fn storage_set(&self, plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError>;
    /// Remove a value.
    fn storage_delete(&self, plugin: &PluginId, key: &str) -> Result<(), CallError>;
    /// Every key under a prefix, or every key when there is none.
    fn storage_keys(
        &self,
        plugin: &PluginId,
        prefix: Option<&str>,
    ) -> Result<Vec<String>, CallError>;
    /// How many bytes the plugin's storage is holding.
    ///
    /// # ★ Why usage and not a `(used, allowed)` pair
    ///
    /// Because the *allowed* half is not the host's to know. A plugin's storage ceiling is part of its quota, the quota is
    /// what [`CallBudget`] was built from, and this layer already holds that budget — so a host that reported its own
    /// limit would be a **second source** for a number the kernel has already decided. The first version of this method
    /// took that shape, and the two would have disagreed the first time a plugin's quota was tightened or a host was built
    /// with a different limit.
    fn storage_used(&self, plugin: &PluginId) -> Result<u64, CallError>;

    /// Read a secret from the OS keychain.
    fn secret_get(&self, plugin: &PluginId, key: &str) -> Result<Option<String>, CallError>;
    /// Write a secret to the OS keychain.
    fn secret_set(&self, plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError>;
    /// Remove a secret.
    fn secret_delete(&self, plugin: &PluginId, key: &str) -> Result<(), CallError>;

    /// Perform an HTTP request, as a JSON request object.
    fn fetch(&self, plugin: &PluginId, request_json: &str) -> Result<String, CallError>;

    /// Begin a transfer, returning its identifier.
    fn transfer_send(
        &self,
        plugin: &PluginId,
        kind: &str,
        target: &str,
        meta_json: &str,
    ) -> Result<String, CallError>;
    /// How a transfer is going.
    fn transfer_status(&self, plugin: &PluginId, transfer_id: &str) -> Result<String, CallError>;

    /// Perform a platform action.
    ///
    /// The action is typed so callers and adapters cannot disagree about its spelling.
    /// Clipboard reads return raw optional text, preserving `Some("")`; the shared dispatcher JSON-encodes
    /// that value exactly once. Commands with no return value answer `None`.
    fn platform(
        &self,
        plugin: &PluginId,
        action: PlatformAction,
        argument: &str,
    ) -> Result<Option<String>, CallError>;

    /// Declare an action other plugins may call.
    fn action_declare(
        &self,
        plugin: &PluginId,
        name: &str,
        schema_json: &str,
    ) -> Result<(), CallError>;
    /// Every action this kernel knows about, as a JSON array.
    fn action_list(&self, plugin: &PluginId) -> Result<String, CallError>;
    /// Call another plugin's action.
    fn action_invoke(
        &self,
        plugin: &PluginId,
        target_plugin: &str,
        name: &str,
        args_json: &str,
    ) -> Result<String, CallError>;
}
