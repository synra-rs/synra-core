use super::*;

// ── Compiling ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_artifact_larger_than_the_ceiling_is_refused_before_the_engine_sees_it() {
    // ★ The limit the host did not have.
    //
    // The CLI refuses a `.wasm` over 16 MiB and the registry refuses a packument over 8 MiB, and `compile` checked only
    // whether the bytes were empty — so anything arriving by another road went straight into the engine, whose parser is not
    // a resource limiter.
    //
    // ★ And what makes this test about *our* refusal rather than wasmtime's.
    //
    // A megabyte of zeroes is not a component, so the engine would refuse it too, with a parse error. The assertion is on the
    // message: it names both numbers, which only this layer can produce.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let oversized = vec![0u8; crate::engine::MAX_COMPONENT_BYTES + 1];

    match backend.compile(&oversized, "@acme/huge") {
        Err(BackendError::Compile { detail }) => {
            assert!(
                detail.contains("16777217"),
                "it names the size it was given: {detail}"
            );
            assert!(
                detail.contains("16777216"),
                "and the largest it accepts: {detail}"
            );
        }
        // A compiled artifact has no `Debug`, so the arm reports that it succeeded rather than showing one.
        Ok(_) => panic!("a 16 MiB artifact was compiled"),
        Err(other) => panic!("expected a size refusal, got {other}"),
    }
}

#[test]
fn an_empty_artifact_is_refused_before_the_engine_sees_it() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    assert!(matches!(
        backend.compile(b"", "p"),
        Err(BackendError::Compile { .. })
    ));
}

#[test]
fn bytes_that_are_not_a_component_are_refused_with_the_engines_own_reason() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    // A text file and a truncated header, which are what a failed download and a renamed file look like.
    for bytes in [&b"not a component at all"[..], &b"\0asm\x01\0\0\0"[..]] {
        // Matched rather than formatted: a compiled artefact is a trait object and not `Debug`, and what the test
        // wants is the engine's own reason rather than a rendering of the value.
        match backend.compile(bytes, "p") {
            Err(BackendError::Compile { detail }) => assert!(!detail.is_empty()),
            Err(other) => panic!("expected a compile refusal, got {other}"),
            Ok(_) => panic!("{bytes:?} was accepted as a component"),
        }
    }
}

#[test]
fn a_component_compiles_and_reports_a_digest_of_the_right_shape() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let artifact = compile(&backend, EMPTY, "@acme/empty");

    assert_eq!(artifact.kind(), BackendKind::WasmtimeCranelift);
    assert_eq!(
        artifact.digest().len(),
        64,
        "a digest is what a cache key is built from"
    );
    assert!(
        artifact
            .digest()
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
}

#[test]
fn what_a_component_imports_is_read_from_the_component() {
    // ★ The fact a manifest cannot be trusted for. This component's import comes from its own type, and the host
    // reports it before the artifact is handed back rather than discovering it at the first call.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let artifact = compile(&backend, IMPORTS, "@acme/imports");

    let concrete = (artifact.as_ref() as &dyn std::any::Any)
        .downcast_ref::<EngineArtifact>()
        .expect("the artefact this backend made");
    assert_eq!(concrete.imports(), ["synra:plugin/host#env-sdk-version"]);
}

#[test]
fn unexpected_resources_in_the_host_interface_are_not_dropped_from_import_checks() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap();
    let artifact = compile(
        &backend,
        r#"(component
      (import "synra:plugin/host@1.0.0" (instance
        (export "unexpected" (type (sub resource)))))
      (instance $lifecycle)
      (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle)))"#,
        "@acme/resource-import",
    );
    assert_eq!(artifact.imports(), ["synra:plugin/host@1.0.0#unexpected"]);
    let grants = synra_capability::CapabilitySet::new();
    assert_eq!(
        crate::host_surface::undeclared_imports(artifact.imports(), &grants),
        artifact.imports()
    );
}

#[test]
fn a_component_that_imports_a_function_the_host_lacks_fails_to_instantiate_with_it_named() {
    // ★ The other half, and the one that must keep holding: a component built against a host that has a function this
    // one does not must fail at *load* time, naming the function — not silently succeed and then do nothing when the
    // plugin calls it. The linker defines exactly the contract's table, so anything outside it is refused by the
    // linker rather than by a rule somebody has to remember.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, IMPORTS_UNKNOWN, "@acme/unknown-import");

    match handle(&backend).instantiate(artifact.as_ref()) {
        Err(BackendError::Instantiate { detail }) => {
            assert!(
                detail.contains("teleport") || detail.contains("synra:plugin/host"),
                "the refusal must name the import: {detail}"
            );
        }
        Err(other) => panic!("expected a link refusal, got {other}"),
        Ok(_) => panic!("a component importing a function this host lacks must not run"),
    }
}

#[test]
fn an_artefact_from_another_backend_is_refused_by_name() {
    // A handle from a different engine is not an artefact this one can instantiate, and the failure has to say so
    // rather than trap inside the engine.
    let (backend, _executor) = backend_and_executor();
    let scripted = Arc::new(crate::engine::scripted::ScriptedBackend::new());
    let theirs = scripted
        .compile(b"\0asm\x01\0\0\0", "@acme/scripted")
        .expect("the scripted backend compiles anything with a header");

    match handle(&backend).instantiate(theirs.as_ref()) {
        Err(BackendError::Engine { detail }) => assert!(detail.contains("wasmtime"), "{detail}"),
        Err(other) => panic!("expected an engine refusal, got {other}"),
        Ok(_) => panic!("a scripted artefact must not be run by the real engine"),
    }
}

// ── Running ───────────────────────────────────────────────────────────────────────────────────────
