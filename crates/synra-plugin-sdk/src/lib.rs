//! What a Synra plugin is written against.
//!
//! # What is here
//!
//! The **generated host bindings**: one module per host call, each with the import name the component model resolves and
//! the signature the contract declares. Both are generated from `wit/synra-plugin.wit`, so a plugin that calls a
//! function the contract does not declare gets a compile error in its own crate rather than a trap when the kernel
//! instantiates it.
//!
//! The three types the boundary exchanges — [`DeviceTarget`], [`LogLevel`] and [`Outcome`] — are re-exported from
//! `synra-plugin-api` rather than declared here. That crate is the contract both sides read, and a second definition of
//! `Outcome` would drift from the host's at the first field added, with the failure landing at the component boundary
//! where the message names neither.
//!
//! # Why this crate is thin
//!
//! It is what a plugin *links*, so everything in it is in the user's download. The generated bindings are the whole
//! surface and they are signatures; the logic is the kernel's, on the other side of the boundary.
//!
//! # The bindings are not yet wired to a runtime
//!
//! `generated::host`'s functions are `todo!()`. The bodies call into the component model's imports, which requires
//! `wit-bindgen` to have generated the guest side — and that is a build-time step this crate does not have yet. What the
//! generation *does* provide today is the part that cannot be got wrong: the names and the signatures. A plugin written
//! against them is one whose calls resolve to functions the contract declares, and the wiring is an implementation
//! detail that changes none of them.
//!
//! Said plainly rather than left implied: a plugin that called these today would panic. The type-checked surface is
//! real; the plumbing behind it is not written.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ★ The generated bindings' signatures are the contract: a parameter is named what the contract names it, and renaming
// one to `_capability` to silence an unused-variable warning would rename the contract. The bodies are `todo!()` until
// `wit-bindgen` generates the guest side, so every parameter is unused today by construction — which is why the
// exemption is here, on the crate, rather than the names being changed.
//
// An `#![allow]` inside the generated file itself would not work: an inner attribute is only an inner attribute at the
// top of a file, and `include!` splices the file into the middle of this one.
#![allow(unused_variables)]

// The `todo!()` in a generated binding marks the boundary this crate cannot wire yet: the bodies call the component
// model's imports, which requires `wit-bindgen` to have generated the guest side. The crate-level lint table and this
// attribute are the two places a crate-local exception to `synra-core`'s workspace lints can live, and the exception is
// recorded in `Cargo.toml` beside this crate's other decisions.
#![allow(clippy::todo)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. A generated binding's body is
// `todo!()`, and an assertion about a signature is the shape these tests have.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod generated {
    //! The generated bindings. Included rather than written, and not to be edited.

    /// One function per host call, with the import name the component model resolves.
    ///
    /// Named `bindings` rather than `host` because the file it includes declares a module of its own — the generator
    /// emits a module so a caller can write `host::log` — and a module and the item it contains sharing a name is a
    /// warning about a reader having to work out which `host` is meant.
    pub mod bindings {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/host.rs"));
    }

    pub mod imports {
        //! The import names, on their own, for a build script that wants them without compiling the module.
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated/imports.rs"));
    }
}

/// The host calls, re-exported at the top level.
///
/// So a plugin writes `synra_plugin_sdk::host::log(..)` rather than `synra_plugin_sdk::generated::bindings::host::log`,
/// and the path in a plugin's source names the thing it is calling rather than where the file was put.
pub use generated::bindings::host;

// ★ Re-exported rather than declared: these are the contract's types, and a plugin's `Outcome` has to be the host's
// `Outcome` or the component model refuses the instantiation.
pub use synra_plugin_api::{DeviceTarget, LogLevel, Outcome};

/// The version of the plugin contract these bindings were generated from.
///
/// A plugin states the SDK version it was built against in its manifest, and the host refuses a plugin whose `sdk.min`
/// is above what it supports. This constant is what a plugin's build script reports rather than a string somebody typed.
pub const CONTRACT_VERSION: &str = "1.0.0";

/// The interface a plugin imports.
pub const HOST_INTERFACE: &str = "synra:plugin/host";

/// The world a plugin implements.
pub const PLUGIN_WORLD: &str = "synra:plugin/plugin";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bindings_name_the_import_the_contract_declares() {
        // The import name is what the component model resolves, so a plugin calling anything else traps. Generated
        // rather than written, and asserted here so the file states which name it is.
        assert_eq!(
            generated::imports::ENV_SDK_VERSION_IMPORT,
            "synra:plugin/host#env-sdk-version"
        );
        assert_eq!(
            generated::imports::DEVICE_LIST_IMPORT,
            "synra:plugin/host#device-list"
        );
        // Every name carries the interface, so a plugin cannot resolve one outside it.
        for name in [
            generated::imports::LOG_IMPORT,
            generated::imports::NETWORK_FETCH_IMPORT,
            generated::imports::PLUGIN_ID_IMPORT,
        ] {
            assert!(name.starts_with("synra:plugin/host#"), "{name}");
        }
    }

    #[test]
    fn the_import_names_are_distinct() {
        // Two functions sharing an import name would be one function with two signatures, and the component model would
        // pick one — silently, and not necessarily the one the caller meant.
        let names = [
            generated::imports::ENV_SDK_VERSION_IMPORT,
            generated::imports::ENV_HOST_KIND_IMPORT,
            generated::imports::ENV_LOCALE_IMPORT,
            generated::imports::ENV_DARK_MODE_IMPORT,
            generated::imports::ENV_CAN_IMPORT,
            generated::imports::LOG_IMPORT,
            generated::imports::EVENT_EMIT_IMPORT,
            generated::imports::DEVICE_LIST_IMPORT,
            generated::imports::DEVICE_SEND_IMPORT,
            generated::imports::STORAGE_GET_IMPORT,
            generated::imports::NETWORK_FETCH_IMPORT,
            generated::imports::PLUGIN_ID_IMPORT,
        ];
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "an import name repeats");
    }

    #[test]
    fn the_contract_version_is_the_one_the_contract_declares() {
        // The manifest's `sdk.min` is compared against the host's version, so a constant that disagreed with the
        // contract would be a plugin claiming to need a version nobody has.
        assert_eq!(CONTRACT_VERSION, "1.0.0");
    }

    #[test]
    fn the_boundary_types_are_the_contracts_and_not_copies() {
        // A compile-time property with a runtime witness: these are re-exports, so a plugin's `Outcome` **is** the
        // host's. A copy would compile here and be refused by the component model at instantiation.
        let outcome: Outcome = Outcome::done();
        assert!(outcome.is_ok());

        let level: LogLevel = LogLevel::Info;
        assert_eq!(level.as_str(), "info");

        let target: DeviceTarget = DeviceTarget::new("dev_a");
        assert_eq!(target.device_id, "dev_a");
    }

    #[test]
    fn the_interface_and_the_world_are_named_as_the_contract_names_them() {
        assert_eq!(HOST_INTERFACE, "synra:plugin/host");
        assert_eq!(PLUGIN_WORLD, "synra:plugin/plugin");
    }
}
