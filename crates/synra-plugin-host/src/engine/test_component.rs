//! Components assembled with metadata from the production WIT world.

fn world() -> (wit_parser::Resolve, wit_parser::WorldId) {
    let mut resolve = wit_parser::Resolve::default();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../wit/synra-plugin.wit");
    let (package, _) = resolve.push_path(path).unwrap();
    let world = resolve.select_world(&[package], Some("plugin")).unwrap();
    (resolve, world)
}

fn encode(
    mut module: Vec<u8>,
    resolve: &wit_parser::Resolve,
    world: wit_parser::WorldId,
) -> Vec<u8> {
    wit_component::embed_component_metadata(
        &mut module,
        resolve,
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

/// Encodes test core logic against the complete production interface, without hand-copied WIT types.
pub(super) fn component(module: Vec<u8>) -> Vec<u8> {
    let (resolve, world) = world();
    encode(module, &resolve, world)
}

/// Provides every import and export shape directly from WIT for linker compatibility checks.
pub(super) fn dummy_world() -> Vec<u8> {
    let (resolve, world) = world();
    let module =
        wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
    encode(module, &resolve, world)
}
