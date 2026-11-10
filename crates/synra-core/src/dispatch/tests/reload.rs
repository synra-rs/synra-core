use synra_capability::CapabilitySet;
use synra_plugin_host::{Backend, InstancePolicy, Scripted, ScriptedBackend, Work};
use super::super::{Matcher, PluginSet, PluginSpec};
use super::{host, id, component_bytes, load, share_json, raised_board, versions};

#[test]
fn unloading_a_plugin_takes_it_out_of_the_next_pass() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/before",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    load(
        &mut set,
        &backend,
        "@synra/after",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    assert_eq!(set.len(), 2);

    assert!(
        set.unload(&id("@synra/before")),
        "unloading reports whether anything was there"
    );
    assert!(
        !set.unload(&id("@synra/before")),
        "and a second unload reports that nothing was"
    );
    assert_eq!(set.len(), 1);

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);
    assert_eq!(
        report.asked, 1,
        "only the plugin that is still loaded is asked"
    );
}

#[test]
fn loading_twice_replaces_the_plugin() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/updating",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    load(
        &mut set,
        &backend,
        "@synra/updating",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );

    assert_eq!(set.len(), 1, "an update is not a second plugin");
    assert_eq!(set.version(&id("@synra/updating")), Some("1.0.0"));
}

#[test]
fn the_version_a_dispatch_records_is_the_one_loaded_now() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    backend.script_for(
        "@synra/moving",
        &Work::CanHandle {
            item_json: share_json().to_owned(),
        },
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    set.load(PluginSpec {
        id: id("@synra/moving"),
        version: "2.0.0".to_owned(),
        wasm: component_bytes(),
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 1,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .unwrap_or_else(|error| panic!("did not load: {error}"));

    let (mut board, intent_id) = raised_board();
    Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(
        versions(&board, intent_id),
        vec!["2.0.0".to_owned()],
        "a plugin updated under the prompt is noticed"
    );
}
