//! Author-tool adapter to the same static contract check used by native admission.

pub use synra_plugin_host::component::ComponentInfo;

pub(crate) fn inspect(bytes: &[u8]) -> Result<ComponentInfo, String> {
    synra_plugin_host::component::inspect(bytes).map_err(|error| error.to_string())
}
