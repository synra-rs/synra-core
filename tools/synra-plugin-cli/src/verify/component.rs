//! Static component validation without executing constructors or compiling native guest code.

use synra_plugin_host::host_surface;
use wit_parser::{Resolve, TypeDefKind, WorldId, WorldItem};

/// Validated component metadata used by the report.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    /// Actual file length after the bounded read.
    pub bytes: u64,
    /// Actual imported functions in the host's canonical naming scheme.
    pub imports: Vec<String>,
}

const CONTRACT: &str = include_str!("../../wit/synra-plugin.wit");

pub(crate) fn inspect(bytes: &[u8]) -> Result<ComponentInfo, String> {
    if bytes.is_empty() {
        return Err("the component is empty".to_owned());
    }
    let length = u64::try_from(bytes.len()).map_err(|error| error.to_string())?;
    if length > super::MAX_WASM_BYTES {
        return Err(format!(
            "the component is {length} bytes, over the {}-byte limit",
            super::MAX_WASM_BYTES
        ));
    }
    if bytes.get(..8) != Some(b"\0asm\x0d\0\x01\0".as_slice()) {
        return Err(
            "the artifact must be a binary Wasm component; rebuild with synra-plugin build"
                .to_owned(),
        );
    }
    let wit_component::DecodedWasm::Component(resolve, world) = wit_component::decode(bytes)
        .map_err(|error| format!("the component cannot be decoded: {error:#}"))?
    else {
        return Err("the artifact is a WIT package rather than an executable component".to_owned());
    };
    let imports = calls(&resolve, world)?;
    for import in &imports {
        if !host_surface::provides(import) {
            return Err(format!("{import} is not provided by this host contract"));
        }
    }
    let mut contract = Resolve::default();
    let package = contract
        .push_str("synra-plugin.wit", CONTRACT)
        .map_err(|error| error.to_string())?;
    let world = contract
        .select_world(&[package], Some("plugin"))
        .map_err(|error| error.to_string())?;
    // targets validates all nested function bodies and checks import/export subtyping against the real world.
    wit_component::targets(&contract, world, bytes).map_err(|error| {
        format!("the component does not implement the plugin WIT world: {error:#}")
    })?;
    Ok(ComponentInfo {
        bytes: length,
        imports,
    })
}

fn calls(resolve: &Resolve, world: WorldId) -> Result<Vec<String>, String> {
    let world = resolve
        .worlds
        .get(world)
        .ok_or("the component has no world")?;
    let host = format!(
        "{}/{}@{}",
        host_surface::PACKAGE,
        host_surface::HOST_INTERFACE,
        host_surface::PACKAGE_VERSION
    );
    let types = format!(
        "{}/types@{}",
        host_surface::PACKAGE,
        host_surface::PACKAGE_VERSION
    );
    let mut calls = Vec::new();
    for (key, item) in &world.imports {
        let name = resolve.name_world_key(key);
        let WorldItem::Interface { id, .. } = item else {
            calls.push(name);
            continue;
        };
        let interface = resolve
            .interfaces
            .get(*id)
            .ok_or("missing imported interface")?;
        if name == host {
            calls.extend(interface.functions.keys().map(|function| {
                format!(
                    "{}/{}#{function}",
                    host_surface::PACKAGE,
                    host_surface::HOST_INTERFACE
                )
            }));
            for (resource, id) in &interface.types {
                if resolve.types.get(*id).is_some_and(|ty| {
                    matches!(ty.kind, TypeDefKind::Resource | TypeDefKind::Handle(_))
                }) {
                    calls.push(format!("{name}#{resource}"));
                }
            }
        } else if name != types
            || !interface.functions.is_empty()
            || interface.types.values().any(|id| {
                resolve.types.get(*id).is_some_and(|ty| {
                    matches!(ty.kind, TypeDefKind::Resource | TypeDefKind::Handle(_))
                })
            })
        {
            calls.push(name);
        }
    }
    calls.sort();
    calls.dedup();
    Ok(calls)
}
