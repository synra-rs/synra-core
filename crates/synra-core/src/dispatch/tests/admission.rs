use synra_capability::CapabilitySet;
use synra_plugin_host::{Backend, InstancePolicy, Scripted, ScriptedBackend};
use super::super::{PluginSet, PluginSetError, PluginSpec};
use super::{host, id, component_bytes, load};

#[test]
fn an_artifact_importing_a_function_its_capabilities_do_not_cover_is_refused_at_load() {
    // ★ The load-time half of the three-layer gate, which had no caller until this test existed.
    //
    // `host_surface::undeclared_imports` was written, tested, and called by nothing in production — the pipeline that
    // uses it, `verify::verify`, has no caller either. So a plugin whose Wasm imported a host function its manifest
    // never declared was loaded and run, and the only sign would have been a call refused at the gate long afterwards,
    // on a code path nobody was reading.
    //
    // What is checked is what the **component** imports rather than what the manifest claims, so the double has to be
    // able to report an import for the check to be exercised at all. That is why `ScriptedBackend::importing` exists.
    let backend = ScriptedBackend::new().importing(&["synra:plugin/host#network-fetch"]);
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());

    let refused = set.load(PluginSpec {
        id: id("@synra/aaa-wants-network"),
        version: "1.0.0".to_owned(),
        wasm: component_bytes(),
        // Granted nothing. The artifact imports a function that needs `network:fetch:*`.
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    });

    match refused {
        Err(PluginSetError::UndeclaredImport { import, .. }) => {
            // ★ The message names the **import**, not the capability. An author needs to know which import to drop or
            // declare; naming a capability at a user would suggest a setting they could change, which is the opposite
            // of true.
            assert!(import.contains("network-fetch"), "{import}");
        }
        other => panic!("an undeclared import should refuse the load, got {other:?}"),
    }

    // And nothing was loaded, so a refused plugin cannot be called by accident.
    assert!(set.is_empty(), "a refused plugin must not be in the set: {:?}", set.ids());
}

#[test]
fn an_artifact_importing_a_function_its_capabilities_do_cover_loads() {
    // The other direction, and the one that keeps the check from being a rule nobody can satisfy: the same import with
    // the capability behind it loads.
    let backend = ScriptedBackend::new().importing(&["synra:plugin/host#network-fetch"]);
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());

    let mut grants = CapabilitySet::new();
    grants
        .insert_str("network:fetch:api.github.com")
        .expect("a scoped capability");

    set.load(PluginSpec {
        id: id("@synra/bbb-declared-network"),
        version: "1.0.0".to_owned(),
        wasm: component_bytes(),
        grants,
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .expect("the import is covered, so the load succeeds");

    assert_eq!(set.len(), 1);
}

#[test]
fn a_loaded_plugin_is_granted_until_activation_is_recorded() {
    // ★ Compiling is not running. The lifecycle exists to make that distance visible, and this is the transition that
    // closes it: `load` leaves the plugin `Granted`, and only `mark_active` says it answered `activate`.
    let backend = std::sync::Arc::new(ScriptedBackend::default());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::clone(&backend)), host());
    let plugin = id("@synra/aaa-lifecycle");
    load(&mut set, &backend, "@synra/aaa-lifecycle", Scripted::Ok(r#"{"handled":true}"#.to_owned()));

    let lifecycle = set.lifecycle(&plugin).expect("a loaded plugin has a lifecycle");
    assert!(!lifecycle.is_running(), "a compiled plugin has not been activated");
    assert!(
        matches!(
            lifecycle.state(),
            synra_plugin_host::State::Granted { manifest_digest, .. } if manifest_digest.is_empty()
        ),
        "the default load records an empty digest, not a guessed one: {:?}",
        lifecycle.state()
    );

    set.mark_active(&plugin).expect("activation is a legal move");
    assert!(set.lifecycle(&plugin).expect("still loaded").is_running());

    assert!(set.unload(&plugin));
    assert!(set.lifecycle(&plugin).is_none(), "unloading drops the state with the code");
}
