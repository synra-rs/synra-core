use super::*;

#[test]
fn a_real_hybrid_package_installs_and_failed_ui_rebuild_preserves_the_previous_generation() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let scaffold = synra_plugin_cli::template::Scaffold::new(
        "@acme/hybrid",
        "0.1.0",
        "Hybrid",
        synra_plugin_cli::template::TemplateKind::Hybrid,
    )
    .unwrap();
    for file in scaffold.files {
        let path = root.join(file.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.contents).unwrap();
    }
    let sdk = isolated_sdk::copy(root);
    let cargo = root.join("Cargo.toml");
    let source = std::fs::read_to_string(&cargo).unwrap();
    patch_sdk(&cargo, &source, &sdk);
    let build = || build_guest(root);
    let (status, log) = build();
    assert!(status.success(), "{log}");
    let output = root.join("dist");
    let manifest = std::fs::read(output.join("manifest.json")).unwrap();
    let component = std::fs::read(output.join("plugin.wasm")).unwrap();
    let ui = std::fs::read(output.join("ui.zip")).unwrap();
    let (status, log) = run(Command::new(env!("CARGO_BIN_EXE_synra-plugin"))
        .args(["verify", "--dir"])
        .arg(&output));
    assert!(status.success(), "{log}");
    let archive = root.join("hybrid.tgz");
    let (status, log) = run(Command::new(env!("CARGO_BIN_EXE_synra-plugin"))
        .args(["pack", "--dir"])
        .arg(&output)
        .arg("--out")
        .arg(&archive));
    assert!(status.success(), "{log}");
    assert!(archive.is_file());
    let data = tempfile::tempdir().unwrap();
    let mut db = synra_store::SynraDb::open(&data.path().join("db.sqlite")).unwrap();
    db.migrate().unwrap();
    let backend = Backend::new(Arc::new(
        WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap(),
    ));
    let tarball = std::fs::read(&archive).unwrap();
    let digest = synra_core::transfer::ObjectDigest::of(&tarball)
        .as_sri()
        .to_string();
    let unpacked = synra_core::install::unpack_published_tarball(
        &tarball,
        Some(&digest),
        "hybrid.tgz",
        &data.path().join("downloads"),
        1,
    )
    .unwrap();
    let installed = synra_core::install::from_directory(
        &mut db,
        &backend,
        &data.path().join("plugins"),
        unpacked.path(),
        1,
        synra_plugin_host::verify::HostFacts::desktop(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(installed.path.join("ui/index.html")).unwrap(),
        std::fs::read(root.join("ui/index.html")).unwrap()
    );
    assert_eq!(db.plugins().unwrap().len(), 1);
    let extracted = unpacked.path().to_path_buf();
    unpacked.cleanup();
    assert!(!extracted.exists());
    // Keep the entire old package, including its signature, when UI packaging fails.
    std::fs::write(
        output.join("signature.json"),
        b"previous generation signature",
    )
    .unwrap();
    std::fs::rename(root.join("ui/index.html"), root.join("ui/missing.html")).unwrap();
    let (status, log) = build();
    assert!(!status.success(), "{log}");
    assert_eq!(
        std::fs::read(output.join("manifest.json")).unwrap(),
        manifest
    );
    assert_eq!(
        std::fs::read(output.join("plugin.wasm")).unwrap(),
        component
    );
    assert_eq!(std::fs::read(output.join("ui.zip")).unwrap(), ui);
    assert_eq!(
        std::fs::read(output.join("signature.json")).unwrap(),
        b"previous generation signature"
    );
    std::fs::rename(root.join("ui/missing.html"), root.join("ui/index.html")).unwrap();
    let (status, log) = build();
    assert!(status.success(), "{log}");
    assert_eq!(
        std::fs::read(output.join("ui.zip")).unwrap(),
        ui,
        "unchanged assets must package deterministically"
    );
    assert!(
        !output.join("signature.json").exists(),
        "a new generation must not retain a stale signature"
    );
}
