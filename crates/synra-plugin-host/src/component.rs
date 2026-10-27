//! Static validation of actual plugin component bytes, shared by native admission and author tools.

use crate::host_surface;
use wit_parser::{Resolve, TypeDefKind, WorldId, WorldItem};

/// Classified failure to implement the host's plugin contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComponentError {
    /// An empty artifact cannot implement the contract.
    #[error("the component is empty")]
    Empty,
    /// Refused before the parser receives the bytes.
    #[error("the component is {bytes} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// Actual input size.
        bytes: usize,
        /// Host input limit.
        limit: usize,
    },
    /// A core module or text input is not the installable binary component.
    #[error("the artifact must be a binary Wasm component; rebuild with synra-plugin build")]
    NotComponent,
    /// The binary or its decoded WIT metadata is invalid.
    #[error("the component cannot be decoded: {detail}")]
    Invalid {
        /// Bounded parser diagnostic.
        detail: String,
    },
    /// The artifact requires something the host never provides.
    #[error("{import} is not provided by this host contract")]
    UnsupportedImport {
        /// Bounded name of the rejected actual import.
        import: String,
    },
    /// Export names, signatures, types or component bodies do not conform.
    #[error("the component does not implement the plugin WIT world: {detail}")]
    WrongWorld {
        /// Bounded contract diagnostic.
        detail: String,
    },
    /// The embedded host contract itself cannot be read.
    #[error("the embedded plugin WIT contract is invalid: {detail}")]
    HostContract {
        /// Bounded host configuration diagnostic.
        detail: String,
    },
}

/// Actual component metadata, returned only after the complete WIT contract is validated.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    /// Actual encoded byte length.
    pub bytes: u64,
    /// Imported functions in the host's canonical naming scheme.
    pub imports: Vec<String>,
}

const CONTRACT: &str = include_str!("../../../wit/synra-plugin.wit");

/// Validate binary encoding, allowed imports, all required exports and types against the real WIT world.
/// This does not instantiate the component, execute constructors or compile native guest code.
///
/// # Errors
/// Returns a classified, bounded diagnostic on malformed, oversized or incompatible input.
pub fn inspect(bytes: &[u8]) -> Result<ComponentInfo, ComponentError> {
    if bytes.is_empty() {
        return Err(ComponentError::Empty);
    }
    if bytes.len() > crate::engine::MAX_COMPONENT_BYTES {
        return Err(ComponentError::TooLarge {
            bytes: bytes.len(),
            limit: crate::engine::MAX_COMPONENT_BYTES,
        });
    }
    if bytes.get(..8) != Some(b"\0asm\x0d\0\x01\0".as_slice()) {
        return Err(ComponentError::NotComponent);
    }
    // The decoder can panic on legal component type aliases that are not representable
    // as its inferred WIT world. Untrusted metadata must become a refusal, never unwind
    // through an installer or native runtime. Native hosts use the unwind panic strategy.
    std::panic::catch_unwind(|| inspect_contract(bytes)).unwrap_or_else(|_| {
        Err(ComponentError::Invalid {
            detail: "component metadata parser panicked".to_owned(),
        })
    })
}

fn inspect_contract(bytes: &[u8]) -> Result<ComponentInfo, ComponentError> {
    let wit_component::DecodedWasm::Component(resolve, world) = wit_component::decode(bytes)
        .map_err(|error| ComponentError::Invalid {
            detail: diagnostic(&format!("{error:#}")),
        })?
    else {
        return Err(ComponentError::NotComponent);
    };
    let imports = calls(&resolve, world).map_err(|error| ComponentError::Invalid {
        detail: diagnostic(&error),
    })?;
    if let Some(import) = imports.iter().find(|name| !host_surface::provides(name)) {
        return Err(ComponentError::UnsupportedImport {
            import: diagnostic(import),
        });
    }
    let mut contract = Resolve::default();
    let package = contract
        .push_str("synra-plugin.wit", CONTRACT)
        .map_err(|error| ComponentError::HostContract {
            detail: diagnostic(&error.to_string()),
        })?;
    let world = contract
        .select_world(&[package], Some("plugin"))
        .map_err(|error| ComponentError::HostContract {
            detail: diagnostic(&error.to_string()),
        })?;
    // targets validates nested function bodies and complete import/export subtyping.
    wit_component::targets(&contract, world, bytes).map_err(|error| {
        ComponentError::WrongWorld {
            detail: diagnostic(&format!("{error:#}")),
        }
    })?;
    Ok(ComponentInfo {
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        imports,
    })
}

fn diagnostic(text: &str) -> String {
    text.chars().take(512).collect()
}

#[cfg(test)]
mod tests;

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
