//! File and traversal bounds for author inputs.
/// The most bytes a Wasm artifact may be.
///
/// Sixteen mebibytes. A plugin that compiles to more than this is one whose time-to-first-call the user will feel, and
/// the bound is a build-time fact rather than a runtime one — so an author finds out from `verify` rather than from a
/// user's complaint.
///
/// ★ **And it is the host's number rather than a second copy of it.**
///
/// `synra_plugin_host::engine::MAX_COMPONENT_BYTES` is what `compile` checks before wasmtime sees anything; this is what
/// `verify` checks on the author's machine. They were two independent literals that happened to agree — which is a
/// coincidence with a lifetime, and the lifetime ends the first time somebody adjusts one of them.
///
/// What it would cost: a `verify` that passes an artifact the host then refuses at load. The checker would have told an
/// author their plugin was fine, and the kernel would disagree — the worst possible division of labour between a check
/// and the thing it checks for.
pub const MAX_WASM_BYTES: u64 = synra_plugin_host::engine::MAX_COMPONENT_BYTES as u64;

/// The most bytes a UI bundle may be.
///
/// Uses the serving layer\'s uncompressed content budget. Encoded ZIP bytes have a separate shared limit.
pub const MAX_UI_BYTES: u64 = synra_plugin_ui::MAX_ARTIFACT_BYTES;

/// The most files a UI bundle may hold.
pub const MAX_UI_FILES: usize = synra_plugin_ui::MAX_ARTIFACT_FILES;

/// The most bytes read from manifest.json before parsing it.
pub(super) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
