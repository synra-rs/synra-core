//! The session: what it holds, and what it says about itself.
//!
//! # Why these run without the `wasm-runtime` feature
//!
//! Because that is the point of the module existing. `LinkerSession` used to live in `linker.rs`, which is compiled only
//! with an engine — so a type that is a plain struct of an identifier, a capability set, a budget and a host could not
//! be named, constructed or tested in a build with no engine. It can now, and these tests are the evidence: they exercise
//! the type in the configuration where it used to not exist.

use std::sync::Arc;

use synra_capability::CapabilitySet;
use synra_protocol::ids::PluginId;

use crate::engine::session::LinkerSession;
use crate::host_calls::{CallError, Host};
use crate::quota::{Budget, Quota};

/// The smallest host that satisfies the trait, for a test that never calls it.
///
/// Every method either answers a constant or refuses. It is written out rather than derived because the trait has no
/// defaults: a host function with no implementation is one a plugin can call and get `unimplemented`, which is a worse
/// answer than a refusal with a code.
struct Silent;

impl Host for Silent {
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
    fn log(&self, _plugin: &PluginId, _level: &str, _message: &str, _ctx: Option<&str>) -> Result<(), CallError> {
        Ok(())
    }
    fn event_emit(&self, _plugin: &PluginId, _event: &str, _payload: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn devices(&self) -> Vec<(String, String, String)> {
        Vec::new()
    }
    fn device_send(&self, _p: &PluginId, _t: &str, _e: &str, _pl: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn device_broadcast(&self, _p: &PluginId, _e: &str, _pl: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn storage_get(&self, _p: &PluginId, _k: &str) -> Result<Option<String>, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn storage_set(&self, _p: &PluginId, _k: &str, _v: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn storage_delete(&self, _p: &PluginId, _k: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn storage_keys(&self, _p: &PluginId, _prefix: Option<&str>) -> Result<Vec<String>, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn storage_quota(&self, _p: &PluginId) -> Result<(u64, u64), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn secret_get(&self, _p: &PluginId, _k: &str) -> Result<Option<String>, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn secret_set(&self, _p: &PluginId, _k: &str, _v: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn secret_delete(&self, _p: &PluginId, _k: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn fetch(&self, _p: &PluginId, _request_json: &str) -> Result<String, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn transfer_send(&self, _p: &PluginId, _k: &str, _t: &str, _m: &str) -> Result<String, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn transfer_status(&self, _p: &PluginId, _id: &str) -> Result<String, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn platform(&self, _p: &PluginId, _a: &str, _arg: &str) -> Result<Option<String>, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn action_declare(&self, _p: &PluginId, _n: &str, _s: &str) -> Result<(), CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn action_list(&self, _p: &PluginId) -> Result<String, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
    fn action_invoke(&self, _p: &PluginId, _t: &str, _n: &str, _a: &str) -> Result<String, CallError> {
        Err(CallError::new("NOT_IMPLEMENTED", "no host"))
    }
}

fn plugin() -> PluginId {
    PluginId::try_from("@acme/notes".to_owned()).expect("a plugin id")
}

#[test]
fn a_session_holds_what_it_was_built_with() {
    let mut grants = CapabilitySet::new();
    grants.insert_str("log:*").expect("a capability");

    let session = LinkerSession::new(
        plugin(),
        grants,
        Arc::new(Budget::new(Quota::default())),
        Arc::new(Silent),
    );

    assert_eq!(session.plugin.as_str(), "@acme/notes");
    assert_eq!(session.grants.len(), 1);
    assert!(session.grants.contains(&synra_capability::Capability::parse("log:info").expect("a capability")));
}

#[test]
fn a_fresh_session_has_audited_nothing() {
    // The buffer starts empty, which is what makes "the plugin did nothing" distinguishable from "the session was never
    // given to an instance". A session that began with an entry would make the two look alike.
    let session = LinkerSession::new(
        plugin(),
        CapabilitySet::new(),
        Arc::new(Budget::new(Quota::default())),
        Arc::new(Silent),
    );

    assert!(session.recorded().is_empty());
}

#[test]
fn the_debug_rendering_names_the_plugin_and_counts_the_grants() {
    // A `Debug` that printed the capability set or the host would put a session's whole contents in a log line. What a
    // reader needs is which plugin, how much it holds, and whether anything has been recorded against it.
    let mut grants = CapabilitySet::new();
    grants.insert_str("log:*").expect("a capability");
    grants.insert_str("device:list").expect("a capability");

    let session = LinkerSession::new(
        plugin(),
        grants,
        Arc::new(Budget::new(Quota::default())),
        Arc::new(Silent),
    );

    let rendered = format!("{session:?}");
    assert!(rendered.contains("@acme/notes"), "{rendered}");
    assert!(rendered.contains("grants: 2"), "{rendered}");
    assert!(rendered.contains("audited: 0"), "{rendered}");
}

#[test]
fn the_session_type_exists_without_an_engine() {
    // ★ The assertion this file exists for. `LinkerSession` used to be declared in `linker.rs`, which is behind the
    // `wasm-runtime` feature — so in a build with no engine, the type that says what a plugin may do did not exist.
    //
    // This test compiles and runs in the **default** feature set. `cargo test -p synra-plugin-host` is what proves it;
    // the assertion itself is deliberately trivial, because the fact being pinned is that there is a test *here* at all.
    let session = LinkerSession::new(
        plugin(),
        CapabilitySet::new(),
        Arc::new(Budget::new(Quota::default())),
        Arc::new(Silent),
    );
    assert_eq!(session.plugin.as_str(), "@acme/notes");
}
