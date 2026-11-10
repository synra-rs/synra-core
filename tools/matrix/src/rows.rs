//! The supported and planned workspace configurations.

use super::Row;

/// The Android target every cross-compilation row is written against.
const ANDROID: &str = "aarch64-linux-android";

/// The rows, in the order a reader should meet them: the kernel that must be portable, then the two features, then the
/// combinations that do not exist yet.
pub(super) fn rows() -> Vec<Row> {
    vec![
        Row {
            claim: "the protocol layer compiles for Android",
            source: "06 §2.1 · 06 §6",
            args: &[
                "-p",
                "synra-protocol",
                "-p",
                "synra-capability",
                "--target",
                ANDROID,
            ],
            blocked_by: None,
        },
        Row {
            claim: "the transport layer compiles for Android",
            source: "06 §6 · mobile-check",
            args: &["-p", "synra-net", "--target", ANDROID],
            blocked_by: None,
        },
        Row {
            claim: "persistence compiles for Android",
            source: "06 §5.4 · 06 §6",
            args: &["-p", "synra-store", "--target", ANDROID],
            blocked_by: None,
        },
        Row {
            claim: "the kernel compiles for Android",
            source: "06 §6",
            args: &["-p", "synra-core", "--target", ANDROID],
            blocked_by: None,
        },
        Row {
            claim: "the plugin host compiles for Android with a real engine",
            source: "06 §5.2 · 06 §6",
            args: &[
                "-p",
                "synra-plugin-host",
                "--features",
                "wasm-runtime",
                "--target",
                ANDROID,
            ],
            blocked_by: None,
        },
        Row {
            claim: "the plugin host compiles with no engine at all",
            source: "06 §5.2",
            args: &["-p", "synra-plugin-host", "--no-default-features"],
            blocked_by: None,
        },
        Row {
            claim: "the CLI compiles on its own",
            source: "06 §6",
            args: &["-p", "synra-cli"],
            blocked_by: None,
        },
        Row {
            claim: "the kernel can be built without its plugin subsystem",
            source: "06 §5.3 · 06 §6",
            args: &[
                "-p",
                "synra-core",
                "--no-default-features",
                "--features",
                "plugins",
            ],
            blocked_by: Some(
                "`synra-core` declares no `plugins` feature. The subsystem **does** exist now — `dispatch/plugins.rs` \
                 loads an artefact, builds the instance pool and runs `can-handle`/`execute` through the host, and the \
                 daemon passes it a `Board` — so what is missing is not the wiring but a flag that switches it off. \
                 Adding one means making `synra-plugin-host` and `synra-plugin-api` optional dependencies and gating \
                 the dispatch seam; until that is done this row is a SKIP rather than an `ok`, because an `ok` would \
                 claim the kernel can be built without plugins and it cannot. (The older reason here — \"its source \
                 never names `synra_plugin_host`\" — was true when written and stopped being true when the seam was \
                 wired; see NOTES/2026-02-the-plugin-host-was-never-wired.md.)",
            ),
        },
        Row {
            claim: "the kernel can run plugins on the wasmi interpreter",
            source: "06 §5.2 · 06 §6",
            args: &[
                "-p",
                "synra-core",
                "--no-default-features",
                "--features",
                "plugins,synra-plugin-host/wasmi",
            ],
            blocked_by: Some(
                "no `wasmi` dependency exists, so the flag would select an empty backend. Whether wasmi replaces \
                 wasmtime at compile time or at run time is still a design question, not a build flag.",
            ),
        },
        Row {
            claim: "the mobile build can use a precompiled engine",
            source: "06 §5.2 · 06 §6",
            args: &[
                "-p",
                "synra-plugin-host",
                "--features",
                "wasmtime-aot",
                "--target",
                ANDROID,
            ],
            blocked_by: Some(
                "no `wasmtime-aot` feature exists. Note that on the evidence in spike/RESULTS.md this is an iOS \
                 requirement: wasmtime sets `has_host_compiler_backend` for Android, so cranelift is available there.",
            ),
        },
        Row {
            claim: "the kernel can be built without its TCP transport",
            source: "06 §5.1 · 06 §6",
            args: &[
                "-p",
                "synra-core",
                "--no-default-features",
                "--features",
                "transport-tcp",
            ],
            blocked_by: Some(
                "`synra-net` declares no features, and its TCP transport is the only transport implemented. A flag that \
                 removed it would have nothing to remove.",
            ),
        },
    ]
}
