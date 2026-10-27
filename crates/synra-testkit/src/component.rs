//! Small executable fixtures encoded against the complete production plugin world.

/// A guest that provides every required entry point, with no imported host functions.
/// Its callbacks succeed with empty outcomes; `can-handle` returns an empty string.
///
/// # Errors
/// Returns the assembler or WIT encoder diagnostic if the fixture cannot be built.
pub fn inert_component() -> Result<Vec<u8>, String> {
    deactivation_component(false)
}

/// A complete production-world guest whose deactivation either returns or loops forever.
///
/// # Errors
/// Returns the assembler or WIT encoder diagnostic.
pub fn deactivation_component(looping: bool) -> Result<Vec<u8>, String> {
    let deactivate = if looping {
        "(loop $spin (br $spin))"
    } else {
        ""
    };
    let module = wat::parse_str(format!(r#"(module
      (memory (export "memory") 4)
      (global $next (mut i32) (i32.const 8192))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $ptr i32) (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (i32.mul (local.get 3) (i32.const 4)))) (local.get $ptr))
      (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/lifecycle@1.0.0#deactivate") {deactivate})
      (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/lifecycle@1.0.0#on-event") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
      (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))"#))
      .map_err(|error| error.to_string())?;
    encode(module)
}

/// Encode custom core guest logic against the production WIT world.
///
/// # Errors
/// Returns the WIT metadata or component encoder diagnostic.
pub fn encode(mut module: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut resolve = wit_parser::Resolve::default();
    let package = resolve
        .push_str(
            "synra-plugin.wit",
            include_str!("../../../wit/synra-plugin.wit"),
        )
        .map_err(|error| error.to_string())?;
    let world = resolve
        .select_world(&[package], Some("plugin"))
        .map_err(|error| error.to_string())?;
    wit_component::embed_component_metadata(
        &mut module,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
    )
    .map_err(|error| error.to_string())?;
    wit_component::ComponentEncoder::default()
        .module(&module)
        .map_err(|error| error.to_string())?
        .validate(true)
        .encode()
        .map_err(|error| error.to_string())
}
