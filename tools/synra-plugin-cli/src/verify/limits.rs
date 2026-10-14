//! The size ceilings, and the imports a plugin may and may not use.
/// The most bytes a Wasm artifact may be.
///
/// Sixteen mebibytes. A plugin that compiles to more than this is one whose time-to-first-call the user will feel, and
/// the bound is a build-time fact rather than a runtime one — so an author finds out from `verify` rather than from a
/// user's complaint.
pub const MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;

/// The most bytes a UI bundle may be.
///
/// Thirty-two mebibytes, which is the bound the UI artifact layer uses. Larger means the bundle is shipping something
/// it should be fetching, or a source map that belongs in a debug build.
pub const MAX_UI_BYTES: u64 = 32 * 1024 * 1024;

/// The most files a UI bundle may hold.
pub const MAX_UI_FILES: usize = 2_000;

/// Host functions the kernel never provides, whatever version.
///
/// # Why this is a closed list rather than a warning
///
/// Each of these would let a plugin reach something the kernel's capability system exists to gate. There is no
/// capability that makes `wasi:filesystem` safe for a plugin whose manifest says it needs none, and there is no
/// version in which importing `sockets` is correct. So a plugin importing one is refused, and the message names the
/// import rather than the rule.
pub const REFUSED_IMPORTS: &[&str] = &[
    "wasi:filesystem",
    "wasi:sockets",
    "wasi:cli",
    "wasi:http",
    "wasi:random",
    "wasi:threads",
    "synra:host/raw-socket",
    "synra:host/exec",
    "synra:host/env",
];

/// Host functions this SDK version provides.
///
/// # Why a list and not a version comparison
///
/// A plugin's imports are strings in a binary; the SDK version it was built against is a string in its manifest, and
/// the two are not connected by anything the kernel can check. So the check is against the *host's* surface: every
/// import the artifact names has to be one this build provides, which catches both a plugin built against an older SDK
/// that called something since removed and one built against a newer SDK that called something not yet added.
pub const PROVIDED_IMPORTS: &[&str] = &[
    "synra:host/log",
    "synra:host/storage",
    "synra:host/secrets",
    "synra:host/net",
    "synra:host/notify",
    "synra:host/clipboard",
    "synra:host/open",
    "synra:host/device",
    "synra:host/plugin",
    "synra:host/execute",
];
