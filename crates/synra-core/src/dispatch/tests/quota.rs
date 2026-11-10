use synra_capability::CapabilitySet;
use synra_plugin_host::{Backend, InstancePolicy, Scripted, ScriptedBackend, Work};
use super::super::{PluginSet, PluginSpec};
use super::{host, candidate_for, id, component_bytes};

#[test]
fn an_execution_runs_under_the_plugins_own_quota() {
    // ★ The quota, actually enforced.
    //
    // `CallBudget::from_quota` is documented as the mapping — *"Every field is taken from the quota rather than chosen
    // here, so the number a user sees in a settings screen is the number the sandbox enforces"* — and **production never
    // called it**. Only the scripted backend's `enforcement` and a test did, so `share.execute` ran under a fixed
    // five-second timeout with no instruction limit at all, whatever the plugin's quota said.
    //
    // The scripted backend's `Timeout` answer reports the budget it was given, which is what makes this assertable
    // without an engine: a call that was handed no timeout returns `Ok`, not a timeout, so an outcome here is proof a
    // budget arrived and the number in it is the number that was sent.
    let candidates = [
        ("a quota of its own", 1_234, synra_plugin_host::quota::Quota { call_timeout_ms: 1_234, ..synra_plugin_host::quota::Quota::default() }),
        ("the default quota", 2_000, synra_plugin_host::quota::Quota::default()),
    ];

    for (what, expected_ms, quota) in candidates {
        let backend = ScriptedBackend::new();
        backend.script(
            &Work::Execute { action: "open".to_owned(), args_json: "null".to_owned() },
            Scripted::Timeout,
        );
        let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());
        set.load(PluginSpec {
            id: id("@synra/aaa-quota"),
            version: "1.0.0".to_owned(),
            wasm: component_bytes(),
            grants: CapabilitySet::new(),
            policy: InstancePolicy::Stateless,
            limit: 4,
            quota,
        })
        .expect("loads");

        let outcome = crate::dispatch::execute(
            &mut set,
            &id("@synra/aaa-quota"),
            &candidate_for("@synra/aaa-quota"),
            0,
            synra_protocol::ids::TraceId::new(),
        )
        .expect("the call is made");

        match outcome {
            synra_plugin_host::CallOutcome::Timeout { after } => assert_eq!(
                after,
                std::time::Duration::from_millis(expected_ms),
                "{what}: the call was given the wrong timeout"
            ),
            // Catches the specific regression this test exists for: before the fix the budget was `execute_budget`'s
            // fixed five seconds with `fuel: None`, and a scripted `Timeout` with a budget is a timeout.
            other => panic!("{what}: expected the quota's timeout, got {other:?}"),
        }
    }
}
