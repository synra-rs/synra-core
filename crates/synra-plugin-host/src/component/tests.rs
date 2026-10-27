use super::*;

fn component_for(contract: &str) -> Vec<u8> {
    let mut resolve = Resolve::default();
    let package = resolve.push_str("fixture.wit", contract).unwrap();
    let world = resolve.select_world(&[package], Some("plugin")).unwrap();
    let mut module =
        wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
    wit_component::embed_component_metadata(
        &mut module,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
    )
    .unwrap();
    wit_component::ComponentEncoder::default()
        .module(&module)
        .unwrap()
        .validate(true)
        .encode()
        .unwrap()
}

#[test]
fn a_complete_executable_component_returns_actual_metadata() {
    let wasm = synra_testkit::component::inert_component().unwrap();
    let info = inspect(&wasm).unwrap();
    assert_eq!(info.bytes, wasm.len() as u64);
    assert!(info.imports.is_empty());
}

#[test]
fn a_component_missing_the_required_event_entry_is_rejected() {
    let source = CONTRACT.replace("    on-event: func(event-json: string) -> outcome;", "");
    assert_ne!(source, CONTRACT);
    let wasm = component_for(&source);
    let error = inspect(&wasm).unwrap_err();
    assert!(
        matches!(error, ComponentError::WrongWorld { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("on-event"), "{error}");
}

#[test]
fn an_entry_name_with_the_wrong_parameter_type_is_rejected() {
    let source = CONTRACT.replace(
        "on-event: func(event-json: string)",
        "on-event: func(event-json: list<u8>)",
    );
    assert_ne!(source, CONTRACT);
    let error = inspect(&component_for(&source)).unwrap_err();
    assert!(
        matches!(error, ComponentError::WrongWorld { .. }),
        "{error:?}"
    );
}

#[test]
fn a_nested_core_function_body_is_validated() {
    let mut wasm = synra_testkit::component::inert_component().unwrap();
    assert!(inspect(&wasm).is_ok());
    // Change a real core function's i32.const 0 return into i64.const 0, preserving
    // valid component metadata and all required export names and signatures.
    let body = wasm
        .windows(4)
        .position(|bytes| bytes == [0x00, 0x41, 0x00, 0x0b])
        .unwrap();
    wasm[body + 1] = 0x42;
    let error = inspect(&wasm).unwrap_err();
    assert!(error.to_string().contains("type mismatch"), "{error}");
}

#[test]
fn raw_modules_empty_input_and_components_without_exports_are_rejected() {
    assert_eq!(inspect(&[]).unwrap_err(), ComponentError::Empty);
    let core = wat::parse_str("(module)").unwrap();
    assert_eq!(inspect(&core).unwrap_err(), ComponentError::NotComponent);
    let empty = wat::parse_str("(component)").unwrap();
    assert!(inspect(&empty).is_err());
}

#[test]
fn oversize_input_is_refused_before_parsing() {
    let bytes = vec![0; crate::engine::MAX_COMPONENT_BYTES + 1];
    assert!(matches!(
        inspect(&bytes),
        Err(ComponentError::TooLarge { .. })
    ));
}

#[test]
fn parser_diagnostics_are_bounded_at_utf8_boundaries() {
    assert_eq!(diagnostic(&"测".repeat(1024)), "测".repeat(512));
}

#[test]
fn repeated_export_type_identities_cannot_unwind_out_of_validation() {
    let wasm = wat::parse_str(
        r#"(component
        (type $record (record (field "text" string)))
        (type $result (variant (case "ok" string) (case "err" $record)))
        (instance $left (export "error" (type $record)) (export "result" (type $result)))
        (instance $right (export "error" (type $record)) (export "result" (type $result)))
        (export "acme:alias/left@1.0.0" (instance $left))
        (export "acme:alias/right@1.0.0" (instance $right)))"#,
    )
    .unwrap();
    assert_eq!(
        inspect(&wasm).unwrap_err(),
        ComponentError::Invalid {
            detail: "component metadata parser panicked".to_owned(),
        }
    );
}

#[test]
fn a_wit_metadata_package_is_not_an_executable_plugin() {
    let mut resolve = Resolve::default();
    let package = resolve.push_str("metadata.wit", CONTRACT).unwrap();
    let bytes = wit_component::encode(&resolve, package).unwrap();
    assert_eq!(inspect(&bytes).unwrap_err(), ComponentError::NotComponent);
}
