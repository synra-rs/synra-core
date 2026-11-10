use std::sync::Arc;

use parking_lot::Mutex;
use synra_core::dispatch::{PluginSet, PluginSpec};
use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
use synra_protocol::ids::DeviceId;
use synra_protocol::inbound::ShareItem;

mod local;
mod remote;
mod withdrawal;

fn set_that_accepts(plugin: &str) -> Arc<Mutex<PluginSet>> {
    scripted_plugin(plugin, Some(local_device()))
}

fn set_that_accepts_without_a_place(plugin: &str) -> Arc<Mutex<PluginSet>> {
    scripted_plugin(plugin, None)
}

/// Scripts the proposal and the execution using the same arguments the proposal supplies.
fn scripted_plugin(plugin: &str, target: Option<DeviceId>) -> Arc<Mutex<PluginSet>> {
    let backend = ScriptedBackend::new();
    let args = serde_json::json!({ "url": "https://example.com" });
    let mut proposal = serde_json::json!({
        "handled": true,
        "action": "open",
        "title": "Open the link",
        "required": [],
        "args": args,
    });
    if let Some(target) = target {
        proposal["target"] = serde_json::json!(target.to_string());
    }
    backend.script(
        &Work::CanHandle { item_json: item_json() },
        Scripted::Ok(proposal.to_string()),
    );
    backend.script(
        &Work::Execute { action: "open".to_owned(), args_json: args.to_string() },
        Scripted::Ok("opened".to_owned()),
    );
    let mut set = PluginSet::new(
        Backend::new(Arc::new(backend)),
        // A host that provides nothing: the plugin never reaches a host function.
        Arc::new(crate::runtime::plugin_host::KernelHost::new(
            Arc::new(Mutex::new({
                let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
                db.migrate().expect("migrates");
                db
            })),
            "0.1.0-test",
        )),
    );
    let mut grants = synra_capability::CapabilitySet::new();
    grants.insert_str("log:*").expect("a capability");
    set.load(PluginSpec {
        id: synra_protocol::ids::PluginId::try_from(plugin.to_owned()).expect("a plugin id"),
        version: "1.0.0".to_owned(),
        wasm: b"\0asm\x01\0\0\0".to_vec(),
        grants,
        policy: synra_plugin_host::InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .expect("loads");
    Arc::new(Mutex::new(set))
}

/// The device these tests treat as "this one".
///
/// ★ A fixed identifier rather than `DeviceId::new()`. The first version generated a fresh one per call, so the
/// target the fixture's proposal named was never the target `decide` compared against — and the failure read as
/// "running an action on another device is not implemented", which is a true statement about a test that had invented
/// two devices.
fn local_device() -> DeviceId {
    "0e5a1c34-0000-4000-8000-000000000001"
        .parse()
        .expect("a device id")
}

fn item() -> ShareItem {
    ShareItem {
        from: local_device(),
        mime: "text/uri-list".to_owned(),
        text: Some("https://example.com".to_owned()),
        transfers: Vec::new(),
        context_id: None,
    }
}

fn item_json() -> String {
    serde_json::to_string(&item()).expect("serialises")
}

/// An invocation, as the sending half of this build builds one.
///
/// Built with the library's own constructor rather than by hand, because a fixture that spelled the payload itself
/// would be a second definition of the shape — and the two would drift the first time either changed.
fn invocation(request: synra_protocol::ids::RequestId) -> synra_protocol::envelope::Envelope {
    let mut envelope = synra_core::intent::remote::invoke(
        local_device(),
        "0e5a1c34-0000-4000-8000-0000000000ff".parse().expect("a device id"),
        &synra_core::intent::remote::Invoke {
            plugin_id: synra_protocol::ids::PluginId::try_from("@acme/opener".to_owned())
                .expect("a plugin id"),
            plugin_version: "1.0.0".to_owned(),
            action: "open".to_owned(),
            args: serde_json::json!({ "url": "https://example.com" }),
        },
        synra_protocol::ids::TraceId::new(),
        1_000,
    )
    .expect("an envelope");
    // The identifier is the sender's, and it is what a resend is recognised by.
    envelope.request_id = request;
    envelope
}
