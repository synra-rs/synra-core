//! Real guest execution, both intent boards and close/reopen SQLite result replay.

use super::*;
use crate::intent::{Choice, IntentCandidate, IntentState, PlannedAction};
use synra_plugin_host::{Backend, BackendKind, InstancePolicy, testing::RefusingHost};

fn plugin() -> PluginId {
    PluginId::parse("@acme/results").expect("plugin id")
}

fn device(tail: u8) -> DeviceId {
    format!("00000000-0000-4000-8000-0000000000{tail:02}")
        .parse()
        .expect("device id")
}

fn guest(failed: bool, payload: &str) -> Vec<u8> {
    let flag = u8::from(failed);
    let length = payload.len();
    let bytes: String = payload
        .bytes()
        .map(|byte| format!("\\{byte:02x}"))
        .collect();
    let module = wat::parse_str(format!(r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1000) "notImplemented")
  (data (i32.const 2048) "refused by guest")
  (data (i32.const 3072) "{bytes}")
  (global $next (mut i32) (i32.const 8192))
  (global $answered (mut i32) (i32.const 0))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (local.get $ptr) (local.get 3)))
    (local.get $ptr))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32)
    (if (global.get $answered) (then (unreachable)))
    (global.set $answered (i32.const 1))
    (i32.store8 (i32.const 256) (i32.const {flag}))
    (if (i32.const {flag})
      (then
        (i32.store (i32.const 260) (i32.const 1000))
        (i32.store (i32.const 264) (i32.const 14))
        (i32.store (i32.const 268) (i32.const 2048))
        (i32.store (i32.const 272) (i32.const 16))
        (i32.store8 (i32.const 276) (i32.const 1))
        (i32.store (i32.const 280) (i32.const 3072))
        (i32.store (i32.const 284) (i32.const {length})))
      (else
        (i32.store (i32.const 260) (i32.const 3072))
        (i32.store (i32.const 264) (i32.const {length}))))
    (i32.const 256))
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-event") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#)).expect("guest module");
    let mut resolve = wit_parser::Resolve::default();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../wit/synra-plugin.wit");
    let (package, _) = resolve.push_path(path).expect("production WIT");
    let world = resolve
        .select_world(&[package], Some("plugin"))
        .expect("plugin world");
    let mut module = module;
    wit_component::embed_component_metadata(
        &mut module,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
    )
    .expect("component metadata");
    wit_component::ComponentEncoder::default()
        .module(&module)
        .expect("module")
        .validate(true)
        .encode()
        .expect("component")
}

fn plugins(failed: bool, payload: &str) -> Arc<Mutex<PluginSet>> {
    let engine = synra_plugin_host::engine::WasmtimeBackend::new(BackendKind::WasmtimeCranelift)
        .expect("engine");
    let mut set = PluginSet::new(Backend::new(Arc::new(engine)), Arc::new(RefusingHost));
    set.load(crate::dispatch::PluginSpec {
        id: plugin(),
        version: "1.0.0".to_owned(),
        wasm: guest(failed, payload),
        grants: synra_capability::CapabilitySet::new(),
        policy: InstancePolicy::Stateful,
        limit: 1,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .expect("loaded");
    Arc::new(Mutex::new(set))
}

fn offered(board: &mut Board, target: DeviceId, now: i64) -> synra_protocol::IntentId {
    let (id, _, _) = board.raise(
        IntentSource::Clipboard {
            target: Some(target),
        },
        Choice::Automatic,
        None,
        None,
        now,
    );
    assert!(board.offer(
        id,
        IntentCandidate {
            plugin_id: plugin(),
            plugin_version: "1.0.0".to_owned(),
            planned: PlannedAction {
                plugin_id: plugin(),
                action: "run".to_owned(),
                args: serde_json::Value::Null
            },
            required_caps: Vec::new(),
            suggested_target: Some(target),
            title: "Run".to_owned(),
            detail: None,
        }
    ));
    assert!(matches!(
        board.settle(id, now + 1000),
        Some(IntentState::Confirming { .. })
    ));
    id
}

fn reopen(board: &Arc<Mutex<Board>>, path: &std::path::Path) -> Arc<Mutex<Board>> {
    let records: Vec<_> = board
        .lock()
        .all()
        .into_iter()
        .map(|intent| crate::intent::persist::row_of(intent, 10_000))
        .collect();
    {
        let mut db = synra_store::SynraDb::open(path).expect("database");
        db.migrate().expect("schema");
        for record in records {
            db.save_intent(&record).expect("saved");
        }
    }
    let db = synra_store::SynraDb::open(path).expect("reopened database");
    let mut restored = Board::new();
    assert_eq!(
        crate::intent::persist::restore(&mut restored, &db)
            .expect("restored")
            .restored,
        1
    );
    Arc::new(Mutex::new(restored))
}

#[test]
fn real_guest_outcomes_match_locally_remotely_and_after_result_replay_from_sqlite() {
    for (failed, payload, expected) in [
        (
            false,
            r#"{"value":"中文🖱️"}"#,
            serde_json::json!({"value":"中文🖱️"}),
        ),
        (false, "[1,true]", serde_json::json!([1, true])),
        (false, "null", serde_json::Value::Null),
        (false, "42", serde_json::json!(42)),
        (false, r#""text""#, serde_json::json!("text")),
        (false, "", serde_json::json!("")),
        (false, "plain text", serde_json::json!("plain text")),
        (
            true,
            r#"{"kind":"unsupported","label":"中文🖱️"}"#,
            serde_json::Value::Null,
        ),
    ] {
        for target in [device(1), device(2)] {
            let plugins = plugins(failed, payload);
            let board = Arc::new(Mutex::new(Board::new()));
            let now = synra_store::sqlite::now_ms();
            let id = offered(&mut board.lock(), target, now);
            let decided = decide(
                &plugins,
                &board,
                device(1),
                &id.to_string(),
                None,
                None,
                now + 1000,
            )
            .expect("decision");
            if let Some(outbound) = decided.outbound {
                let receiver = Arc::new(Mutex::new(Board::new()));
                let first = accept_remote(
                    &plugins,
                    &receiver,
                    device(2),
                    &outbound.envelope,
                    now + 1000,
                )
                .expect("receiver")
                .expect("reply");
                assert_eq!(first.trace_id, outbound.envelope.trace_id);
                let mut duplicate = outbound.envelope.clone();
                duplicate.trace_id = synra_protocol::TraceId::new();
                let again = accept_remote(&plugins, &receiver, device(2), &duplicate, now + 2000)
                    .expect("duplicate")
                    .expect("cached reply");
                assert_eq!(again.trace_id, first.trace_id);
                let first_result = crate::intent::remote::result_from(&first).expect("result");
                assert_eq!(
                    first_result,
                    crate::intent::remote::result_from(&again).expect("cached result")
                );
                let root = tempfile::tempdir().expect("owned directory");
                let restored = reopen(&receiver, &root.path().join("state.sqlite3"));
                let after_restart =
                    accept_remote(&plugins, &restored, device(2), &duplicate, now + 3000)
                        .expect("restored duplicate")
                        .expect("restored reply");
                assert_eq!(after_restart.trace_id, first.trace_id);
                assert_eq!(
                    first_result,
                    crate::intent::remote::result_from(&after_restart).expect("restored result")
                );
                assert_eq!(apply_result(&board, &first).expect("applied"), Some(id));
                assert_eq!(
                    apply_result(&board, &again).expect("duplicate reply ignored"),
                    None
                );
            } else {
                assert_eq!(decided.ok, !failed);
                assert_eq!(decided.result, expected);
            }
            let intent = board.lock().get(id).cloned().expect("intent");
            match intent.state {
                IntentState::Succeeded { result, .. } if !failed => assert_eq!(result, expected),
                IntentState::Failed { error, .. } if failed => {
                    assert_eq!(error.code, synra_protocol::ErrorCode::Unsupported);
                    assert_eq!(error.message, "refused by guest");
                    assert_eq!(error.trace_id, Some(intent.trace.to_string()));
                    assert_eq!(
                        error.details.as_deref(),
                        Some(
                            &serde_json::json!({"pluginCode":"notImplemented","pluginDetails":{"kind":"unsupported","label":"中文🖱️"}})
                        )
                    );
                }
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
    }
}
