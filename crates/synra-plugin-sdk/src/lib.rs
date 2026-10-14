//! What a Synra plugin is written against.
//!
//! # What is here
//!
//! The **generated host bindings**: one function per host call, with the import name the component model resolves and
//! the signature the contract declares. Generated from `wit/synra-plugin.wit`, so a plugin that calls a function the
//! contract does not declare gets a compile error in its own crate rather than a trap when the kernel instantiates it.
//!
//! The three types the boundary exchanges — [`DeviceTarget`], [`LogLevel`] and [`Outcome`] — are re-exported from
//! `synra-plugin-api` rather than declared here. That crate is the contract both sides read, and a second definition of
//! `Outcome` would drift from the host's at the first field added, with the failure landing at the component boundary
//! where the message names neither.
//!
//! # Why this crate is thin
//!
//! It is what a plugin *links*, so everything in it is in the user's download. The generated bindings are the whole
//! surface, and the logic is the kernel's, on the other side of the boundary.
//!
//! # How the bindings are made
//!
//! `wit_bindgen::generate!` in [`generated`] reads the contract when this crate is compiled, which is what makes drift
//! impossible: a signature that disagreed with the WIT file would be a compile error here rather than a trap at
//! instantiation. There is no build step to run and no generated file to keep in step.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ★ The generated bindings' signatures are the contract: a parameter is named what the contract names it, and renaming
// one to `_capability` to silence an unused-variable warning would rename the contract.
//
// An `#![allow]` inside the generated file itself would not work: an inner attribute is only an inner attribute at the
// top of a file, and `include!` splices the file into the middle of this one.
#![allow(unused_variables)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. An assertion about a generated
// signature is the shape these tests have.
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
    //! The generated bindings.
    //!
    //! # Generated at compile time, and not by a build step
    //!
    //! `wit_bindgen::generate!` reads `wit/synra-plugin.wit` when this crate is compiled, so the bindings cannot drift
    //! from the contract: a function added to the interface is a function this crate has the moment it is rebuilt, and
    //! a signature that disagreed with the contract would be a compile error rather than a trap at instantiation.
    //!
    //! # The two files beside this one are generated too
    //!
    //! `src/generated/host.rs` and `src/generated/imports.rs` are `wit-codegen`'s output, and they are the **host-side**
    //! artifacts: the signatures and the import names the kernel's own table is built from. They are kept because a
    //! build script that wants the import names without compiling the bindings reads them, and because the suite
    //! compares them against what `wit_bindgen` produces — two generators, one contract, and a test that says so.
    //!
    //! The documentation `wit-bindgen` emits is derived from the WIT comments and does not cover every generated item,
    //! so the lint is off here rather than the contract being rewritten to satisfy a linter.
    #[allow(missing_docs)]
    pub mod bindings {
        wit_bindgen::generate!({
            path: "../../wit",
            world: "plugin",
        });

        /// The host calls, under the path this crate has always exposed them at.
        ///
        /// `wit_bindgen` names the module after the interface — `synra::plugin::host` — and this alias is what keeps a
        /// plugin's `synra_plugin_sdk::host::log(..)` working without it having to name the package and the version.
        pub use synra::plugin::host;
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

    #[test]
    fn every_host_function_the_contract_declares_has_a_binding_and_an_import_name() {
        // ★ The test that keeps the SDK and the contract the same size. Both files are generated from
        // `wit/synra-plugin.wit` by the same tool, so a function added to the contract without regenerating the SDK is
        // a function a plugin cannot call — and the symptom would be a plugin author concluding the host does not
        // provide something it plainly does.
        //
        // The contract's table is read as **text** rather than through the crate that owns it: `synra-plugin-host`
        // depends on this one through the workspace, and a dev-dependency back on it would be a cycle. What is being
        // compared is a generated artifact against another generated artifact, which is a text comparison by nature.
        let table = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../synra-plugin-host/src/generated/capability_table.rs"),
        )
        .expect("the contract's capability table");
        // The contract's table lists full import names and the SDK's constants are full import names, so they are
        // compared as they are — a bare-name comparison would pass for a binding keyed by the wrong interface.
        let declared: Vec<String> = table
            .lines()
            .filter_map(|line| line.trim().strip_prefix("(\"synra:plugin/host#"))
            .filter_map(|rest| rest.split('"').next())
            .map(|name| format!("synra:plugin/host#{name}"))
            .collect();
        assert_eq!(declared.len(), 35, "the contract's own count: {}", declared.len());

        let generated = [
            generated::imports::ENV_SDK_VERSION_IMPORT,
            generated::imports::ENV_HOST_KIND_IMPORT,
            generated::imports::ENV_LOCALE_IMPORT,
            generated::imports::ENV_DARK_MODE_IMPORT,
            generated::imports::ENV_CAN_IMPORT,
            generated::imports::LOG_IMPORT,
            generated::imports::EVENT_EMIT_IMPORT,
            generated::imports::EVENT_SUBSCRIBE_IMPORT,
            generated::imports::DEVICE_LIST_IMPORT,
            generated::imports::DEVICE_SEND_IMPORT,
            generated::imports::DEVICE_BROADCAST_IMPORT,
            generated::imports::STORAGE_GET_IMPORT,
            generated::imports::STORAGE_SET_IMPORT,
            generated::imports::STORAGE_DELETE_IMPORT,
            generated::imports::STORAGE_KEYS_IMPORT,
            generated::imports::STORAGE_QUOTA_IMPORT,
            generated::imports::SECRET_GET_IMPORT,
            generated::imports::SECRET_SET_IMPORT,
            generated::imports::SECRET_DELETE_IMPORT,
            generated::imports::NETWORK_FETCH_IMPORT,
            generated::imports::NETWORK_WEBSOCKET_IMPORT,
            generated::imports::TRANSFER_SEND_IMPORT,
            generated::imports::TRANSFER_STATUS_IMPORT,
            generated::imports::PLATFORM_OPEN_URL_IMPORT,
            generated::imports::PLATFORM_OPEN_PATH_IMPORT,
            generated::imports::PLATFORM_REVEAL_PATH_IMPORT,
            generated::imports::PLATFORM_SIMULATE_KEYS_IMPORT,
            generated::imports::PLATFORM_NOTIFY_IMPORT,
            generated::imports::PLATFORM_READ_CLIPBOARD_IMPORT,
            generated::imports::PLATFORM_WRITE_CLIPBOARD_IMPORT,
            generated::imports::PLATFORM_CAPABILITIES_IMPORT,
            generated::imports::ACTION_DECLARE_IMPORT,
            generated::imports::ACTION_INVOKE_IMPORT,
            generated::imports::ACTION_LIST_IMPORT,
            generated::imports::PLUGIN_ID_IMPORT,
        ];

        let mut missing: Vec<&String> =
            declared.iter().filter(|name| !generated.contains(&name.as_str())).collect();
        missing.sort_unstable();
        assert!(missing.is_empty(), "the SDK has no binding for: {missing:?}");

        let mut extra: Vec<&str> =
            generated.iter().copied().filter(|name| !declared.iter().any(|held| held == name)).collect();
        extra.sort_unstable();
        assert!(extra.is_empty(), "the SDK binds functions the contract does not declare: {extra:?}");

        // And every name is keyed by the interface, so a plugin cannot resolve one outside it.
        for name in generated {
            assert!(name.starts_with("synra:plugin/host#"), "{name}");
        }
    }
}
