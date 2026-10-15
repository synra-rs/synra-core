//! Spike 3 — can `wasmtime` cross-compile to `aarch64-linux-android`?
//!
//! The assumption under test: the mobile plugin backend is `wasmtime` with cranelift, as
//! `crates/synra-plugin-host` already builds it on the desktop. Risk R-01 is 🔴 high precisely because nobody has
//! compiled it for a phone. If this fails, the fallback named in the roadmap is `wasmi`, which is a different
//! dependency with different performance and a different story on iOS.
//!
//! The check is `cargo check`, not `cargo build`: the question is whether the **dependency graph** survives the
//! target, and linking is a separate question answered by spike 1's toolchain. That distinction is the whole
//! result of this spike and must not be blurred — a check that passes here proves nothing about whether an `.so`
//! links, and RESULTS.md says so.

/// Names the API surface the plugin host actually reaches for.
///
/// Declaring the dependency is enough to have cargo build it, but referencing the types means the spike also proves
/// the target reaches the *public API*, not merely that a crate with a `Cargo.toml` exists.
pub fn engine() -> wasmtime::Result<wasmtime::Engine> {
    wasmtime::Engine::new(&wasmtime::Config::new())
}
