use super::*;

#[test]
fn the_bindings_name_the_import_the_contract_declares() {
    // The import name is what the component model resolves, so a plugin calling anything else traps. Generated
    // rather than written, and asserted here so the file states which name it is.
    assert_eq!(
        generated::imports::ENV_SDK_VERSION_IMPORT,
        "synra:plugin/host#env-sdk-version"
    );
    assert_eq!(
        generated::imports::DEVICE_LIST_IMPORT,
        "synra:plugin/host#device-list"
    );
    // Every name carries the interface, so a plugin cannot resolve one outside it.
    for name in [
        generated::imports::LOG_IMPORT,
        generated::imports::NETWORK_FETCH_IMPORT,
        generated::imports::PLUGIN_ID_IMPORT,
    ] {
        assert!(name.starts_with("synra:plugin/host#"), "{name}");
    }
}

#[test]
fn the_import_names_are_distinct() {
    // Two functions sharing an import name would be one function with two signatures, and the component model would
    // pick one — silently, and not necessarily the one the caller meant.
    let names = [
        generated::imports::ENV_SDK_VERSION_IMPORT,
        generated::imports::ENV_HOST_KIND_IMPORT,
        generated::imports::ENV_LOCALE_IMPORT,
        generated::imports::ENV_DARK_MODE_IMPORT,
        generated::imports::ENV_CAN_IMPORT,
        generated::imports::LOG_IMPORT,
        generated::imports::EVENT_EMIT_IMPORT,
        generated::imports::DEVICE_LIST_IMPORT,
        generated::imports::DEVICE_SEND_IMPORT,
        generated::imports::STORAGE_GET_IMPORT,
        generated::imports::NETWORK_FETCH_IMPORT,
        generated::imports::PLUGIN_ID_IMPORT,
    ];
    let mut sorted: Vec<&str> = names.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "an import name repeats");
}

#[test]
fn the_contract_version_is_the_one_the_contract_declares() {
    // The manifest's `sdk.min` is compared against the host's version, so a constant that disagreed with the
    // contract would be a plugin claiming to need a version nobody has.
    let contract =
        synra_wit_codegen::Contract::parse(include_str!("../../../wit/synra-plugin.wit")).unwrap();
    assert_eq!(CONTRACT_VERSION, contract.version);
    assert_eq!(HOST_INTERFACE, format!("{}/host", contract.package));
    assert_eq!(
        PLUGIN_WORLD,
        format!("{}/{}", contract.package, contract.world)
    );
}

#[test]
fn public_boundary_types_are_the_generated_host_function_types() {
    // Public values are the generated host function types, rather than the host-side manifest model.
    let outcome = Outcome::Ok("payload".to_owned());
    assert!(matches!(outcome, Outcome::Ok(value) if value == "payload"));
    let _: fn(&str) -> Outcome = host::storage_get;

    let level: LogLevel = LogLevel::Info;
    assert!(matches!(level, LogLevel::Info));

    let target = DeviceTarget {
        id: "dev_a".to_owned(),
        name: "Device".to_owned(),
        kind: DeviceKind::Desktop,
    };
    assert_eq!(target.id, "dev_a");
}

#[test]
fn the_interface_and_the_world_are_named_as_the_contract_names_them() {
    assert_eq!(HOST_INTERFACE, "synra:plugin/host");
    assert_eq!(PLUGIN_WORLD, "synra:plugin/plugin");
}

#[test]
fn every_host_function_the_contract_declares_has_a_binding_and_an_import_name() {
    // ★ The test that keeps the SDK and the contract the same size. Both files are generated from
    // `wit/synra-plugin.wit` by the same tool, so a function added to the contract without regenerating the SDK is
    // a function a plugin cannot call — and the symptom would be a plugin author concluding the host does not
    // provide something it plainly does.
    //
    // The contract is read **as the contract**, not through the kernel's generated table.
    //
    // ★ Why this changed. The table is a checked-in artifact that the **host's** build script regenerates, so a run
    // which builds only this crate compares against whatever the last host build left on disk. Round 126 added a
    // function to the contract, built nothing, and watched this test pass — a guard reading a stale copy of the very
    // thing it guards. `synra-wit-codegen` is the parser the host's build script uses, and it takes the WIT text, so there
    // is no intermediate that can be out of date.
    //
    // It is a dev-dependency rather than a dependency: a plugin links this crate, and a parser must not be in what a
    // user downloads. And it is not `synra-plugin-host`, so it is not the cycle the note above warns about.
    let contract = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../wit/synra-plugin.wit"
    ))
    .expect("the contract");
    let parsed = synra_wit_codegen::Contract::parse(&contract).expect("the contract parses");
    let host = parsed
        .host()
        .expect("the contract declares the host interface");
    // The contract's names are the import names the component model resolves, so they are compared as they are — a
    // bare-name comparison would pass for a binding keyed by the wrong interface.
    let declared: Vec<String> = host
        .functions
        .iter()
        .map(|function| format!("synra:plugin/host#{}", function.name))
        .collect();
    assert_eq!(
        declared.len(),
        35,
        "the contract's own count: {}",
        declared.len()
    );

    let generated = [
        generated::imports::ENV_SDK_VERSION_IMPORT,
        generated::imports::ENV_HOST_KIND_IMPORT,
        generated::imports::ENV_LOCALE_IMPORT,
        generated::imports::ENV_DARK_MODE_IMPORT,
        generated::imports::ENV_CAN_IMPORT,
        generated::imports::LOG_IMPORT,
        generated::imports::EVENT_EMIT_IMPORT,
        generated::imports::DEVICE_LIST_IMPORT,
        generated::imports::DEVICE_SEND_IMPORT,
        generated::imports::INPUT_SESSION_IMPORT,
        generated::imports::DEVICE_BROADCAST_IMPORT,
        generated::imports::STORAGE_GET_IMPORT,
        generated::imports::STORAGE_SET_IMPORT,
        generated::imports::STORAGE_DELETE_IMPORT,
        generated::imports::STORAGE_KEYS_IMPORT,
        generated::imports::STORAGE_QUOTA_IMPORT,
        generated::imports::SECRET_GET_IMPORT,
        generated::imports::SECRET_SET_IMPORT,
        generated::imports::SECRET_DELETE_IMPORT,
        generated::imports::NETWORK_FETCH_IMPORT,
        generated::imports::NETWORK_WEBSOCKET_IMPORT,
        generated::imports::TRANSFER_SEND_IMPORT,
        generated::imports::TRANSFER_STATUS_IMPORT,
        generated::imports::PLATFORM_OPEN_URL_IMPORT,
        generated::imports::PLATFORM_OPEN_PATH_IMPORT,
        generated::imports::PLATFORM_REVEAL_PATH_IMPORT,
        generated::imports::PLATFORM_SIMULATE_KEYS_IMPORT,
        generated::imports::PLATFORM_NOTIFY_IMPORT,
        generated::imports::PLATFORM_READ_CLIPBOARD_IMPORT,
        generated::imports::PLATFORM_WRITE_CLIPBOARD_IMPORT,
        generated::imports::PLATFORM_CAPABILITIES_IMPORT,
        generated::imports::ACTION_DECLARE_IMPORT,
        generated::imports::ACTION_INVOKE_IMPORT,
        generated::imports::ACTION_LIST_IMPORT,
        generated::imports::PLUGIN_ID_IMPORT,
    ];

    let mut missing: Vec<&String> = declared
        .iter()
        .filter(|name| !generated.contains(&name.as_str()))
        .collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "the SDK has no binding for: {missing:?}"
    );

    let mut extra: Vec<&str> = generated
        .iter()
        .copied()
        .filter(|name| !declared.iter().any(|held| held == name))
        .collect();
    extra.sort_unstable();
    assert!(
        extra.is_empty(),
        "the SDK binds functions the contract does not declare: {extra:?}"
    );

    // And every name is keyed by the interface, so a plugin cannot resolve one outside it.
    for name in generated {
        assert!(name.starts_with("synra:plugin/host#"), "{name}");
    }
}
