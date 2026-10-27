//! Actual event components and persisted metadata shared by native-host integration tests.

use serde_json::json;
use synra_protocol::PluginId;

/// The event all fixtures use, with a complete package owner.
pub const EVENT: &str = "_plugin.@acme/emitter.ready";
/// A fixed local identity for event contexts.
pub const DEVICE: &str = "00000000-0000-4000-8000-000000000001";

/// An event plugin's real bytes, manifest and declared authority.
pub struct EventPlugin {
    /// Complete package identity.
    pub id: PluginId,
    /// Exact manifest bytes persisted for consent and event routing.
    pub manifest: String,
    /// Component encoded against the production WIT.
    pub wasm: Vec<u8>,
    /// Declared and granted capabilities.
    pub grants: Vec<String>,
}

impl EventPlugin {
    /// Persist fixture identity, installation, exact manifest and consent through real store methods.
    ///
    /// # Errors
    /// Metadata could not be written to the test database.
    pub fn persist(&self, db: &synra_store::SynraDb) -> Result<(), String> {
        db.create_identity_if_absent(&synra_store::records::IdentityRow {
            device_id: DEVICE.to_owned(),
            display_name: "Event host".to_owned(),
            platform: "test".to_owned(),
            created_at_ms: 1,
        })
        .map_err(|error| error.to_string())?;
        db.insert_plugin(self.id.as_str(), true, true, "healthy", 1, 1)
            .map_err(|error| error.to_string())?;
        let digest = manifest_digest(&self.manifest);
        let decisions: Vec<_> = self.grants.iter().map(|cap| (cap.clone(), true)).collect();
        db.record_grants(self.id.as_str(), &decisions, 1, &digest)
            .map_err(|error| error.to_string())?;
        db.record_plugin_version(&synra_store::sqlite::PluginVersionRecord {
            plugin_id: self.id.as_str(),
            version: "1.0.0",
            artifact: "plugin.wasm",
            digest: "fixture-component",
            manifest: &self.manifest,
            publisher_id: None,
            fingerprint: None,
            installed_ms: 1,
        })
        .map_err(|error| error.to_string())
    }
    /// A guest action emits an event. In loop mode its event handler emits again.
    ///
    /// # Errors
    /// A fixture or production WIT could not be assembled.
    pub fn emitter(loop_events: bool) -> Result<Self, String> {
        let mut grants = vec![format!("event:emit:{EVENT}")];
        let handles = if loop_events {
            grants.push(format!("event:subscribe:{EVENT}"));
            json!([{"event":EVENT}])
        } else {
            json!([])
        };
        let manifest = json!({"id":"@acme/emitter","version":"1.0.0","title":"Emitter",
            "publisher":{"id":"test"},"sdk":{"min":"1.0.0"},"wit":"synra:plugin@1.0.0",
            "runtime":{"headless":{"artifact":"plugin.wasm","stateful":true}},
            "capabilities":grants.iter().map(|cap|json!({"cap":cap})).collect::<Vec<_>>(),
            "actions":[{"name":"emit"}],"handles":handles,
            "events":[{"name":EVENT,"payload":{"type":"object","properties":{"text":{"type":"string","maxLength":32},"kind":{"type":"string","maxLength":16}},"required":["text"],"additionalProperties":false}}]}).to_string();
        Ok(Self {
            id: PluginId::parse("@acme/emitter").map_err(|error| error.to_string())?,
            manifest,
            wasm: component(false, loop_events)?,
            grants,
        })
    }

    /// A guest handler stores the exact host event context and increments its stateful call count.
    ///
    /// # Errors
    /// A fixture or production WIT could not be assembled.
    pub fn receiver(condition: Option<serde_json::Value>) -> Result<Self, String> {
        let grants = vec![
            format!("event:subscribe:{EVENT}"),
            "storage:local:write".to_owned(),
        ];
        let handle = match condition {
            Some(condition) => json!({"event":EVENT,"match":condition}),
            None => json!({"event":EVENT}),
        };
        let manifest = json!({"id":"@acme/receiver","version":"1.0.0","title":"Receiver",
            "publisher":{"id":"test"},"sdk":{"min":"1.0.0"},"wit":"synra:plugin@1.0.0",
            "runtime":{"headless":{"artifact":"plugin.wasm","stateful":true}},
            "capabilities":grants.iter().map(|cap|json!({"cap":cap})).collect::<Vec<_>>(),
            "handles":[handle]})
        .to_string();
        Ok(Self {
            id: PluginId::parse("@acme/receiver").map_err(|error| error.to_string())?,
            manifest,
            wasm: component(true, false)?,
            grants,
        })
    }
}

/// Hash fixture manifest bytes with the same SHA-256 encoding as production consent.
#[must_use]
pub fn manifest_digest(text: &str) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(text.as_bytes()))
}

fn component(receiver: bool, looping: bool) -> Result<Vec<u8>, String> {
    let import = if receiver {
        "storage-set"
    } else {
        "event-emit"
    };
    let encoded: String = EVENT.bytes().map(|byte| format!("\\{byte:02x}")).collect();
    let length = EVENT.len();
    let handler = if receiver {
        r#"(call $host (i32.const 3072) (i32.const 8) (local.get 0) (local.get 1) (i32.const 512))
        (if (i32.load8_u (i32.const 512)) (then (return (i32.const 512))))
        (global.set $count (i32.add (global.get $count) (i32.const 1)))
        (i32.store8 (i32.const 2048) (i32.add (i32.const 48) (global.get $count)))
        (call $host (i32.const 3100) (i32.const 5) (i32.const 2048) (i32.const 1) (i32.const 512))
        (i32.const 512)"#
            .to_owned()
    } else if looping {
        format!(
            "(call $host (i32.const 1024) (i32.const {length}) (i32.const 4096) (i32.const 15) (i32.const 512)) (i32.const 512)"
        )
    } else {
        "(i32.const 0)".to_owned()
    };
    let action = if receiver {
        "(i32.const 0)".to_owned()
    } else {
        format!(
            "(call $host (i32.const 1024) (i32.const {length}) (local.get 2) (local.get 3) (i32.const 512)) (i32.const 512)"
        )
    };
    let wat = format!(
        r#"(module
      (import "synra:plugin/host@1.0.0" "{import}" (func $host (param i32 i32 i32 i32 i32)))
      (memory (export "memory") 4)
      (global $next (mut i32) (i32.const 8192)) (global $count (mut i32) (i32.const 0))
      (data (i32.const 1024) "{encoded}")
      (data (i32.const 3072) "received") (data (i32.const 3100) "calls")
      (data (i32.const 4096) "{{\22text\22:\22loop\22}}")
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $ptr i32) (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (i32.mul (local.get 3) (i32.const 4)))) (local.get $ptr))
      (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
      (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/lifecycle@1.0.0#on-event") (param i32 i32) (result i32) {handler})
      (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) {action}))"#
    );
    let module = wat::parse_str(wat).map_err(|error| error.to_string())?;
    crate::component::encode(module)
}
