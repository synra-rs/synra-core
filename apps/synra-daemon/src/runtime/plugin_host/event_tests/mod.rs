//! Production daemon host, actual WIT guest code, asynchronous worker and real file SQLite.
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use synra_core::dispatch::{PluginSet, PluginSpec};
use synra_plugin_host::{
    Backend, BackendKind, CallBudget, CallOutcome, InstancePolicy, Work, quota::Quota,
};
use synra_protocol::TraceId;
use synra_testkit::plugin_events::EventPlugin;

use super::KernelHost;

mod delivery;
mod queue;

struct Rig {
    db: Arc<Mutex<synra_store::SynraDb>>,
    set: Arc<Mutex<PluginSet>>,
    service: Arc<synra_core::plugin_events::EventService>,
    emitter: EventPlugin,
    receiver: EventPlugin,
    // Dropped after the set, service and SQLite handles.
    _root: EventDirectory,
}

struct EventDirectory {
    directory: Option<tempfile::TempDir>,
    service: std::sync::Weak<synra_core::plugin_events::EventService>,
}

impl Drop for EventDirectory {
    fn drop(&mut self) {
        // A finished handler may still be returning from the worker's stack. Wait for its
        // actual Arc to drop before closing a Windows SQLite file's directory.
        wait(|| self.service.strong_count() == 0);
        self.directory.take().unwrap().close().unwrap();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.service.stop();
        wait(|| !self.service.report().worker_running);
    }
}

impl Rig {
    fn new(looping: bool, condition: Option<serde_json::Value>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut db = synra_store::SynraDb::open(&root.path().join("events.sqlite3")).unwrap();
        db.migrate().unwrap();
        let mut emitter = EventPlugin::emitter(looping).unwrap();
        let receiver = EventPlugin::receiver(condition).unwrap();
        // Deliberately allow payload fields named like context fields; they must stay nested.
        let mut manifest: serde_json::Value = serde_json::from_str(&emitter.manifest).unwrap();
        manifest["events"][0]["payload"]["additionalProperties"] = serde_json::Value::Bool(true);
        emitter.manifest = manifest.to_string();
        emitter.persist(&db).unwrap();
        receiver.persist(&db).unwrap();
        let db = Arc::new(Mutex::new(db));
        let host = Arc::new(KernelHost::new(Arc::clone(&db), "test"));
        let service = host.events();
        let engine =
            synra_plugin_host::engine::WasmtimeBackend::new(BackendKind::WasmtimeCranelift)
                .unwrap();
        let set = PluginSet::new(Backend::new(Arc::new(engine)), host)
            .with_event_delivery(Arc::clone(&service))
            .into_shared()
            .unwrap();
        {
            let mut set = set.lock();
            load(&mut set, &emitter);
            if !looping {
                load(&mut set, &receiver);
            }
        }
        Self {
            _root: EventDirectory {
                directory: Some(root),
                service: Arc::downgrade(&service),
            },
            db,
            set,
            service,
            emitter,
            receiver,
        }
    }

    fn emit(&self, payload: serde_json::Value, trace: TraceId) -> CallOutcome {
        self.set
            .lock()
            .call_traced(
                &self.emitter.id,
                &Work::InvokeAction {
                    name: "emit".to_owned(),
                    args_json: payload.to_string(),
                },
                CallBudget::from_quota(&Quota::default()),
                1,
                Some(trace),
            )
            .unwrap()
    }

    fn stored(&self, key: &str) -> Option<String> {
        self.db
            .lock()
            .storage_get(self.receiver.id.as_str(), key)
            .unwrap()
    }
}

fn load(set: &mut PluginSet, plugin: &EventPlugin) {
    set.load_with_lifecycle(
        PluginSpec {
            id: plugin.id.clone(),
            version: "1.0.0".to_owned(),
            wasm: plugin.wasm.clone(),
            grants: synra_capability::CapabilitySet::parse_all(
                plugin.grants.iter().map(String::as_str),
            )
            .unwrap(),
            policy: InstancePolicy::Stateful,
            limit: 1,
            quota: Quota {
                events_per_sec: 1_000,
                ..Quota::default()
            },
        },
        synra_plugin_api::manifest_digest(&plugin.manifest),
        false,
    )
    .unwrap();
    assert!(matches!(
        set.call(
            &plugin.id,
            &Work::Activate {
                config_json: "{}".to_owned()
            },
            CallBudget::from_quota(&Quota::default()),
            1
        )
        .unwrap(),
        CallOutcome::Ok(_)
    ));
    set.mark_active(&plugin.id).unwrap();
}

fn wait(mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if ready() {
            return;
        }
        assert!(
            Instant::now() < until,
            "event worker did not reach the expected state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
