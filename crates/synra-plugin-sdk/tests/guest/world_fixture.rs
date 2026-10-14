//! A plugin component built from the contract, for the engine's own end-to-end tests.
//!
//! # What this is for
//!
//! The engine's two end-to-end tests use `WAT` fixtures, and a hand-written lifted function whose parameter is a
//! `string` and whose result is a `string` has to get the canonical ABI's lowering right — `(ptr, len)` in, a return
//! pointer out, and a `realloc` the host calls. That is exactly the kind of thing a generator exists to get right and a
//! hand-written fixture gets subtly wrong, which is why those tests are ignored with that reason.
//!
//! So this is the *real* thing: the contract's own bindings, a `Guest` implementation for each exported interface, and
//! `wit_bindgen`'s `export!` for the ABI.
//!
//! # Why this is not compiled today
//!
//! Three reasons, in the order they are reached, and none of them is a missing line of code:
//!
//! 1. **`unsafe`.** `export!` emits `#[unsafe(no_mangle)]` functions — the component's own entry points — and this
//!    workspace sets `unsafe_code = "forbid"`. A `forbid` cannot be lifted by a crate or by an item, so the only way to
//!    compile this is to relax a workspace-wide policy that is there for a reason. That is a decision for whoever owns
//!    the policy, not one to make in a test file.
//! 2. **The target.** A guest is `wasm32-wasip2`, which is not installed here. `wasm32-unknown-unknown` is, and building
//!    for it fails first inside `getrandom` — reached through `synra-plugin-api`'s signing dependencies — which refuses
//!    that target without its `js` feature.
//! 3. **The artifact.** Even a built guest is a *core* module; componentising it needs `wasm-tools`, which is not
//!    installed either.
//!
//! The file is kept because it is the shape a plugin takes against these bindings, and because the three reasons above
//! are what somebody picking this up needs to know. It is not built, and there is no `#[ignore]` because a test that
//! cannot compile is not a test that is skipped.

#![allow(dead_code)]

wit_bindgen::generate!({
    path: "../../wit",
    world: "plugin",
});

use synra::plugin::types::Outcome;

/// The plugin the engine's tests drive.
struct Fixture;

impl exports::synra::plugin::lifecycle::Guest for Fixture {
    fn activate(_config_json: String) -> Outcome {
        Outcome::ok("hello from the generated plugin")
    }

    fn deactivate() {}

    fn migrate(_from_version: String, _to_version: String) -> Outcome {
        Outcome::ok("migrated")
    }

    fn on_tick(_tick_json: String) -> Outcome {
        Outcome::ok("ticked")
    }
}

impl exports::synra::plugin::share::Guest for Fixture {
    fn can_handle(_item_json: String) -> String {
        r#"{"handled":false}"#.to_owned()
    }

    fn execute(_action: String, _args_json: String) -> Outcome {
        Outcome::err(synra::plugin::types::Error {
            code: "notMine".to_owned(),
            message: "this plugin handles nothing".to_owned(),
            details: None,
        })
    }
}

impl exports::synra::plugin::actions::Guest for Fixture {
    fn invoke(_name: String, _args_json: String) -> Outcome {
        Outcome::ok("invoked")
    }
}

export!(Fixture);
