use super::*;

#[test]
fn a_headless_scaffold_builds_a_component_and_a_failed_rebuild_preserves_it() {
    let dir = tempfile::tempdir().unwrap();
    let scaffold = synra_plugin_cli::template::Scaffold::new(
        "@acme/template",
        "0.1.0",
        "Template",
        synra_plugin_cli::template::TemplateKind::Headless,
    )
    .unwrap();
    for file in scaffold.files {
        let path = dir.path().join(file.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.contents).unwrap();
    }
    let sdk = isolated_sdk::copy(dir.path());
    let cargo = dir.path().join("Cargo.toml");
    let source = std::fs::read_to_string(&cargo)
        .unwrap()
        .replace("[lib]", "[lib]\nname = \"differently_named_guest\"");
    // The package is unpublished; patch only dependency resolution, leaving the generated Rust source intact.
    patch_sdk(&cargo, &source, &sdk);
    let build = || build_guest(dir.path());
    let (status, log) = build();
    assert!(status.success(), "{log}");
    let bytes = std::fs::read(dir.path().join("dist/plugin.wasm")).unwrap();
    let (status, log) = run(Command::new(env!("CARGO_BIN_EXE_synra-plugin"))
        .args(["verify", "--dir"])
        .arg(dir.path().join("dist")));
    assert!(status.success(), "{log}");
    assert_eq!(bytes.get(..8), Some(b"\0asm\x0d\0\x01\0".as_slice()));
    let mut plugins = set();
    let spec = spec(bytes.clone(), false);
    let id = spec.id.clone();
    plugins.load(spec).unwrap();
    assert_eq!(
        plugins
            .call(
                &id,
                &Work::Activate {
                    config_json: "{}".to_owned()
                },
                CallBudget::unlimited(),
                0
            )
            .unwrap(),
        CallOutcome::Ok(String::new())
    );
    assert_eq!(
        plugins
            .call(
                &id,
                &Work::CanHandle {
                    item_json: "{}".to_owned()
                },
                CallBudget::unlimited(),
                0
            )
            .unwrap(),
        CallOutcome::Ok(r#"{"handled":false}"#.to_owned())
    );
    std::fs::write(dir.path().join("src/lib.rs"), "pub fn not_a_plugin() {}").unwrap();
    let (status, log) = build();
    assert!(!status.success(), "{log}");
    assert_eq!(
        std::fs::read(dir.path().join("dist/plugin.wasm")).unwrap(),
        bytes
    );
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "compile_error!(\"intentional rebuild failure\");",
    )
    .unwrap();
    let (status, log) = build();
    assert!(!status.success(), "{log}");
    assert_eq!(
        std::fs::read(dir.path().join("dist/plugin.wasm")).unwrap(),
        bytes
    );
}
