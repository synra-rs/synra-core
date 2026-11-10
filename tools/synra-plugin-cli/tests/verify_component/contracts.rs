use super::*;

#[test]
fn malformed_bytes_and_core_modules_fail_through_the_command() {
    let root = tempfile::tempdir().unwrap();
    manifest(root.path(), "plugin.wasm", &[]);
    for bytes in [
        b"not wasm".as_slice(),
        b"\0asm\x01\0\0\0",
        b"\0asm\x0d\0\x01\0",
    ] {
        std::fs::write(root.path().join("plugin.wasm"), bytes).unwrap();
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
}

#[test]
fn a_real_component_is_read_from_the_manifest_path_and_its_actual_imports_are_checked() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("dist")).unwrap();
    std::fs::write(
        root.path().join("dist/custom.wasm"),
        fixture::from_contract(fixture::CONTRACT),
    )
    .unwrap();
    // A stale conventional output cannot replace the manifest's declared component.
    std::fs::write(root.path().join("plugin.wasm"), b"stale").unwrap();
    let capabilities = synra_plugin_host::host_surface::CAPABILITIES;
    manifest(root.path(), "dist/custom.wasm", capabilities);
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    assert!(!report.to_string().contains("warn"), "{report}");
    let scoped: Vec<&str> = capabilities
        .iter()
        .map(|cap| match *cap {
            "network:fetch:*" => "network:fetch:api.github.com:GET",
            "log:*" => "log:info",
            "event:emit:*" => "event:emit:_plugin.@acme/verify.ready",
            "device:send:*" => "device:send:00000000-0000-4000-8000-000000000001",
            "action:invoke:*:*" => "action:invoke:@acme/formatter:format-date",
            "action:declare:*" => "action:declare:format-date",
            cap => cap,
        })
        .collect();
    manifest(root.path(), "dist/custom.wasm", &scoped);
    let path = root.path().join("manifest.json");
    let mut declaration: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    declaration.as_object_mut().unwrap().insert(
        "network".to_owned(),
        serde_json::json!({ "outbound": [{ "host": "api.github.com", "methods": ["GET"] }] }),
    );
    declaration.as_object_mut().unwrap().insert(
        "events".to_owned(),
        serde_json::json!([{ "name": "_plugin.@acme/verify.ready", "payload": {
            "type": "object", "properties": {}, "additionalProperties": false
        }}]),
    );
    std::fs::write(path, declaration.to_string()).unwrap();
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    let incomplete_action: Vec<&str> = capabilities
        .iter()
        .map(|cap| {
            if *cap == "action:invoke:*:*" {
                "action:invoke:*"
            } else {
                *cap
            }
        })
        .collect();
    manifest(root.path(), "dist/custom.wasm", &incomplete_action);
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(
        report
            .to_string()
            .contains("synra:plugin/host#action-invoke"),
        "{report}"
    );
    let without_open: Vec<&str> = capabilities
        .iter()
        .copied()
        .filter(|cap| *cap != "platform:open-url")
        .collect();
    manifest(root.path(), "dist/custom.wasm", &without_open);
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(
        report
            .to_string()
            .contains("synra:plugin/host#platform-open-url"),
        "{report}"
    );
    assert!(
        report
            .to_string()
            .contains("not covered by manifest capabilities"),
        "{report}"
    );
}

#[test]
fn a_verified_zero_import_component_passes_without_an_unread_warning() {
    let root = tempfile::tempdir().unwrap();
    let source = fixture::CONTRACT.replace("    import host;", "");
    assert_ne!(source, fixture::CONTRACT);
    std::fs::write(
        root.path().join("plugin.wasm"),
        fixture::from_contract(&source),
    )
    .unwrap();
    manifest(root.path(), "plugin.wasm", &[]);
    let (status, report) = verify(root.path());
    assert!(status.success(), "{report}");
    assert!(report.to_string().contains("0 actual import"), "{report}");
}

#[test]
fn actual_import_versions_resources_and_wrong_host_or_guest_signatures_fail() {
    let root = tempfile::tempdir().unwrap();
    manifest(
        root.path(),
        "plugin.wasm",
        synra_plugin_host::host_surface::CAPABILITIES,
    );
    for source in [
        fixture::CONTRACT.replace("@1.0.0", "@9.0.0"),
        fixture::CONTRACT.replace(
            "platform-open-url: func(url: string) -> outcome;",
            "platform-open-url: func(url: u32) -> outcome;",
        ),
        fixture::CONTRACT.replace(
            "activate: func(config-json: string) -> outcome;",
            "activate: func(config-json: u32) -> outcome;",
        ),
        fixture::CONTRACT.replace(
            "interface host {",
            "interface host {\n    resource forbidden;",
        ),
        fixture::CONTRACT.replace("    export actions;", ""),
    ] {
        assert_ne!(source, fixture::CONTRACT);
        std::fs::write(
            root.path().join("plugin.wasm"),
            fixture::from_contract(&source),
        )
        .unwrap();
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
}

#[test]
fn invalid_nested_function_bodies_do_not_pass_on_interface_metadata_alone() {
    let root = tempfile::tempdir().unwrap();
    manifest(
        root.path(),
        "plugin.wasm",
        synra_plugin_host::host_surface::CAPABILITIES,
    );
    let mut bytes = fixture::component();
    let range = wasmparser::Parser::new(0)
        .parse_all(&bytes)
        .find_map(|payload| match payload.unwrap() {
            wasmparser::Payload::CodeSectionEntry(body) => Some(body.range()),
            _ => None,
        })
        .unwrap();
    let instruction = bytes.get_mut(range.end.checked_sub(2).unwrap()).unwrap();
    assert_eq!(
        *instruction, 0,
        "the dummy body's final instruction must be unreachable"
    );
    *instruction = 0xff;
    std::fs::write(root.path().join("plugin.wasm"), bytes).unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("opcode"), "{report}");
}
