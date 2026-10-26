//! A [Host] for tests that never reach one.
//!
//! # Why this lives here rather than in each test module
//!
//! Because `Host` has no defaults: a host function with no implementation is one a plugin can call and get
//! `unimplemented`, which is a worse answer than a refusal with a code. So every one of its methods is named, and each
//! refusal carries a code a guest could branch on — which is ~170 lines that every crate wanting a `PluginSet` in a test
//! would otherwise copy. It was copied once, in `synra-core`'s dispatch tests; the shell needed the same thing, and two
//! copies of "refuse everything" is one more than a test fixture can afford to let drift.
//!
//! It is public because exporting it is the point: a fixture that only works inside one crate is a fixture the next crate
//! rewrites.

use synra_protocol::ids::PluginId;

use crate::host_calls::{CallError, Host};

/// A host that refuses every call, for tests that never reach a host function.
pub struct RefusingHost;

impl Host for RefusingHost {
    fn sdk_version(&self) -> String {
        "0.0.0".to_owned()
    }
    fn host_kind(&self) -> String {
        "headless".to_owned()
    }
    fn locale(&self) -> String {
        "en-GB".to_owned()
    }
    fn dark_mode(&self) -> bool {
        false
    }
    fn can(&self, _plugin: &PluginId, _capability: &str) -> bool {
        false
    }
    fn platform_capabilities(&self) -> Vec<String> {
        Vec::new()
    }
    fn log(
        &self,
        _plugin: &PluginId,
        _level: &str,
        _message: &str,
        _context: Option<&str>,
    ) -> Result<(), CallError> {
        Ok(())
    }
    fn event_emit(
        &self,
        _plugin: &PluginId,
        _event: &str,
        _payload: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn devices(&self) -> Vec<(String, String, String)> {
        Vec::new()
    }
    fn device_send(
        &self,
        _p: &PluginId,
        _t: &str,
        _e: &str,
        _pl: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn device_broadcast(
        &self,
        _p: &PluginId,
        _e: &str,
        _pl: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn storage_get(
        &self,
        _p: &PluginId,
        _k: &str,
    ) -> Result<Option<String>, CallError> {
        refuse()
    }
    fn storage_set(
        &self,
        _p: &PluginId,
        _k: &str,
        _v: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn storage_delete(
        &self,
        _p: &PluginId,
        _k: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn storage_keys(
        &self,
        _p: &PluginId,
        _prefix: Option<&str>,
    ) -> Result<Vec<String>, CallError> {
        refuse()
    }
    fn storage_used(
        &self,
        _p: &PluginId,
    ) -> Result<u64, CallError> {
        refuse()
    }
    fn secret_get(
        &self,
        _p: &PluginId,
        _k: &str,
    ) -> Result<Option<String>, CallError> {
        refuse()
    }
    fn secret_set(
        &self,
        _p: &PluginId,
        _k: &str,
        _v: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn secret_delete(
        &self,
        _p: &PluginId,
        _k: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn fetch(
        &self,
        _p: &PluginId,
        _request_json: &str,
    ) -> Result<String, CallError> {
        refuse()
    }
    fn transfer_send(
        &self,
        _p: &PluginId,
        _k: &str,
        _t: &str,
        _m: &str,
    ) -> Result<String, CallError> {
        refuse()
    }
    fn transfer_status(
        &self,
        _p: &PluginId,
        _id: &str,
    ) -> Result<String, CallError> {
        refuse()
    }
    fn platform(
        &self,
        _p: &PluginId,
        _a: crate::PlatformAction,
        _arg: &str,
    ) -> Result<Option<String>, CallError> {
        refuse()
    }
    fn action_declare(
        &self,
        _p: &PluginId,
        _n: &str,
        _s: &str,
    ) -> Result<(), CallError> {
        refuse()
    }
    fn action_list(
        &self,
        _p: &PluginId,
    ) -> Result<String, CallError> {
        refuse()
    }
    fn action_invoke(
        &self,
        _p: &PluginId,
        _t: &str,
        _n: &str,
        _a: &str,
    ) -> Result<String, CallError> {
        refuse()
    }
}

/// A refusal every method here returns: a call that reached a host which provides nothing.
///
/// `NOT_IMPLEMENTED` rather than a made-up code, because a guest that branches on it is branching on something true — the
/// test host really does not implement it.
fn refuse<T>() -> Result<T, CallError> {
    Err(CallError::new(
        "NOT_IMPLEMENTED",
        "this test host provides nothing",
    ))
}
