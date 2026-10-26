//! Imported calls are authorization facts; interface containers are not calls.

use wasmtime::Engine;
use wasmtime::component::types::{Component, ComponentItem};

use super::interface_name;
use crate::host_surface;

pub(super) fn calls(component: &Component, engine: &Engine) -> Vec<String> {
    let host = interface_name(host_surface::HOST_INTERFACE);
    let types = interface_name("types");
    let mut calls = Vec::new();
    for (name, item) in component.imports(engine) {
        match item {
            ComponentItem::ComponentInstance(instance) if name == host => {
                for (function, item) in instance.exports(engine) {
                    match item {
                        ComponentItem::ComponentFunc(_) => calls.push(format!(
                            "{}/{}#{function}",
                            host_surface::PACKAGE,
                            host_surface::HOST_INTERFACE
                        )),
                        ComponentItem::Type(_) => {}
                        _ => calls.push(format!("{name}#{function}")),
                    }
                }
            }
            ComponentItem::ComponentInstance(instance) if name == types => {
                // Shared WIT value types do not authorize operations. Unexpected functions still fail closed.
                if instance
                    .exports(engine)
                    .any(|(_, item)| !matches!(item, ComponentItem::Type(_)))
                {
                    calls.push(name.to_owned());
                }
            }
            _ => calls.push(name.to_owned()),
        }
    }
    calls.sort();
    calls.dedup();
    calls
}
