//! Wasmtime compilation, bounded instance startup and execution budgeting.
//!
//! Configuration, compiled artifacts, instance state and typed guest invocation have separate
//! owners. WIT-generated host bindings are installed by the shared linker.

mod artifact;
mod backend;
pub(super) mod bindings;
mod compile;
mod config;
mod imports;
mod instance;
mod invoke;
mod store;

pub use artifact::EngineArtifact;
pub use backend::{WasmtimeBackend, shared};
pub(crate) use config::engine_config;
pub(crate) use store::StoreData;

/// The crate's own version, which is the engine-version input to a compile cache key.
///
/// The engine's version is the crate's: `wasmtime` is pinned in `Cargo.toml`, so a change to it is a change to the
/// build rather than to a runtime value. A cache entry a rebuild cannot use is a miss, which is a recompilation and
/// not a crash.
pub(crate) const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name an interface is exported under.
///
/// # Why this is spelled out rather than assumed
///
/// A component's exports are keyed by their *interface-qualified* name — `synra:plugin/lifecycle@1.0.0`, with the
/// version on the interface rather than on the package — and the functions inside it are reached through that instance.
/// A lookup on the bare function name finds nothing, and the symptom is a call that reports "the component does not
/// export activate" for a component that plainly does: a plugin author's problem to have, and not one the host should
/// invent.
///
/// Both halves come from [`crate::host_surface`], which `build.rs` regenerates from the contract, so a version bump in
/// `wit/synra-plugin.wit` cannot leave this behind. The separator is `@` between the interface and its version and `/`
/// between the package and the interface, which is the component model's own grammar rather than a choice made here.
#[must_use]
pub(crate) fn interface_name(interface: &str) -> String {
    format!(
        "{}/{interface}@{}",
        crate::host_surface::PACKAGE,
        crate::host_surface::PACKAGE_VERSION,
    )
}

/// The fully flattened name of a function, for a component that exports its interface that way.
#[must_use]
pub(crate) fn export_name(interface: &str, function: &str) -> String {
    format!("{}#{function}", interface_name(interface))
}

#[cfg(test)]
mod tests;
