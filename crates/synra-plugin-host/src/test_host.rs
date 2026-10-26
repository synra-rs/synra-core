//! Shared recording host for gate and real-Wasm boundary tests.

use crate::host_calls::{CallError, Host, PlatformAction};
use std::sync::Mutex;
use synra_protocol::ids::PluginId;

/// A host that records what it was asked and answers with a value taken from the function's name.
#[derive(Default)]
pub(crate) struct Stub {
    /// Every `(function, argument)` that got as far as the host.
    pub(crate) seen: Mutex<Vec<(String, String)>>,
    /// The device list it reports.
    pub(crate) devices: Vec<(String, String, String)>,
    /// Whether a secret is held, so `secret-get` has something to find.
    pub(crate) secret: Option<String>,
    /// Override the sample clipboard result, including absence and an empty text value.
    pub(crate) clipboard: Option<Option<String>>,
    /// How many bytes its storage is holding, which the quota check reads.
    ///
    /// Settable rather than derived from what `storage-set` was asked to write, because the number that matters is what
    /// the *store* holds — and this double has no store. A value the test chooses is what lets the arithmetic be checked
    /// without one.
    pub(crate) storage_bytes: u64,
}

impl Stub {
    pub(crate) fn with_devices(devices: &[(&str, &str, &str)]) -> Self {
        Self {
            devices: devices
                .iter()
                .map(|(id, name, kind)| ((*id).to_owned(), (*name).to_owned(), (*kind).to_owned()))
                .collect(),
            ..Self::default()
        }
    }

    /// A stub whose storage already holds this much.
    pub(crate) fn using(bytes: u64) -> Self {
        Self {
            storage_bytes: bytes,
            ..Self::default()
        }
    }

    /// Everything the host was asked, as bare function names.
    pub(crate) fn called(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }
}

impl Host for Stub {
    fn sdk_version(&self) -> String {
        "1.0.0".to_owned()
    }
    fn host_kind(&self) -> String {
        "headless".to_owned()
    }
    fn locale(&self) -> String {
        "en-GB".to_owned()
    }
    fn dark_mode(&self) -> bool {
        true
    }
    fn can(&self, _plugin: &PluginId, capability: &str) -> bool {
        capability == "log:*"
    }
    fn platform_capabilities(&self) -> Vec<String> {
        vec!["platform:notify".to_owned()]
    }

    fn log(
        &self,
        _plugin: &PluginId,
        level: &str,
        message: &str,
        context: Option<&str>,
    ) -> Result<(), CallError> {
        self.record(
            "log",
            &format!("{level}/{message}/{}", context.unwrap_or("-")),
        );
        Ok(())
    }
    fn event_emit(&self, _plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError> {
        self.record("event-emit", &format!("{event}/{payload}"));
        Ok(())
    }

    fn devices(&self) -> Vec<(String, String, String)> {
        self.record("device-list", "");
        self.devices.clone()
    }
    fn device_send(
        &self,
        _plugin: &PluginId,
        target: &str,
        event: &str,
        payload: &str,
    ) -> Result<(), CallError> {
        self.record("device-send", &format!("{target}/{event}/{payload}"));
        if target == "unknown" {
            return Err(CallError::new(CallError::HOST_FAILED, "no such device"));
        }
        Ok(())
    }
    fn device_broadcast(
        &self,
        _plugin: &PluginId,
        event: &str,
        payload: &str,
    ) -> Result<(), CallError> {
        self.record("device-broadcast", &format!("{event}/{payload}"));
        Ok(())
    }

    fn storage_get(&self, _plugin: &PluginId, key: &str) -> Result<Option<String>, CallError> {
        self.record("storage-get", key);
        Ok((key == "known").then(|| "a value".to_owned()))
    }
    fn storage_set(&self, _plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError> {
        self.record("storage-set", &format!("{key}={value}"));
        Ok(())
    }
    fn storage_delete(&self, _plugin: &PluginId, key: &str) -> Result<(), CallError> {
        self.record("storage-delete", key);
        Ok(())
    }
    fn storage_keys(
        &self,
        _plugin: &PluginId,
        prefix: Option<&str>,
    ) -> Result<Vec<String>, CallError> {
        self.record("storage-keys", prefix.unwrap_or(""));
        Ok(vec![
            format!("{}one", prefix.unwrap_or("")),
            format!("{}two", prefix.unwrap_or("")),
        ])
    }
    fn storage_used(&self, _plugin: &PluginId) -> Result<u64, CallError> {
        self.record("storage-used", "");
        Ok(self.storage_bytes)
    }

    fn secret_get(&self, _plugin: &PluginId, key: &str) -> Result<Option<String>, CallError> {
        self.record("secret-get", key);
        Ok(self.secret.clone())
    }
    fn secret_set(&self, _plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError> {
        self.record("secret-set", &format!("{key}={value}"));
        Ok(())
    }
    fn secret_delete(&self, _plugin: &PluginId, key: &str) -> Result<(), CallError> {
        self.record("secret-delete", key);
        Ok(())
    }

    fn fetch(&self, _plugin: &PluginId, request_json: &str) -> Result<String, CallError> {
        self.record("network-fetch", request_json);
        Ok("{\"status\":200}".to_owned())
    }

    fn transfer_send(
        &self,
        _plugin: &PluginId,
        kind: &str,
        target: &str,
        meta_json: &str,
    ) -> Result<String, CallError> {
        self.record("transfer-send", &format!("{kind}/{target}/{meta_json}"));
        Ok("transfer-1".to_owned())
    }
    fn transfer_status(&self, _plugin: &PluginId, transfer_id: &str) -> Result<String, CallError> {
        self.record("transfer-status", transfer_id);
        Ok("{\"state\":\"running\"}".to_owned())
    }

    fn platform(
        &self,
        _plugin: &PluginId,
        action: PlatformAction,
        argument: &str,
    ) -> Result<Option<String>, CallError> {
        self.record("platform", &format!("{}/{argument}", action.as_str()));
        if action == PlatformAction::ReadClipboard {
            return Ok(self
                .clipboard
                .clone()
                .unwrap_or_else(|| Some("clipboard text".to_owned())));
        }
        Ok(None)
    }

    fn action_declare(
        &self,
        _plugin: &PluginId,
        name: &str,
        schema_json: &str,
    ) -> Result<(), CallError> {
        self.record("action-declare", &format!("{name}/{schema_json}"));
        Ok(())
    }
    fn action_list(&self, _plugin: &PluginId) -> Result<String, CallError> {
        self.record("action-list", "");
        Ok("[{\"plugin\":\"@acme/other\",\"name\":\"greet\"}]".to_owned())
    }
    fn action_invoke(
        &self,
        _plugin: &PluginId,
        target_plugin: &str,
        name: &str,
        args_json: &str,
    ) -> Result<String, CallError> {
        self.record(
            "action-invoke",
            &format!("{target_plugin}/{name}/{args_json}"),
        );
        Ok("\"hello\"".to_owned())
    }
}

impl Stub {
    /// Records a call, and does nothing if the lock is poisoned — a stub that panicked inside another test's stub
    /// should not turn into a second failure here.
    pub(crate) fn record(&self, name: &str, argument: &str) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((name.to_owned(), argument.to_owned()));
        }
    }
}
