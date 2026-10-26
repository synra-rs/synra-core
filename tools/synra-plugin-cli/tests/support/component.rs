//! Reviewable test components derived from the actual contract rather than fake Wasm headers.

pub(crate) const CONTRACT: &str = include_str!("../../wit/synra-plugin.wit");

pub(crate) fn component() -> Vec<u8> {
    from_contract(&CONTRACT.replace("    import host;", ""))
}

pub(crate) fn from_contract(source: &str) -> Vec<u8> {
    let mut resolve = wit_parser::Resolve::default();
    let package = resolve.push_str("test.wit", source).unwrap();
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
