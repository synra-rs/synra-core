//! Component types generated from the production WIT contract.

wasmtime::component::bindgen!({
    path: "../../wit/synra-plugin.wit",
    world: "plugin",
    imports: { default: trappable },
});
