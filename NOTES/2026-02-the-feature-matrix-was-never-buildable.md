# The feature matrix was never buildable

An audit of what the M0 acceptance criteria assume against what the workspace actually contains.

## What the roadmap asks for

The workspace layout document carries a **feature combination matrix** that CI is supposed to run in full:

| Combination | Command it names |
| --- | --- |
| minimal kernel | `cargo check -p synra-core --no-default-features` |
| default (with plugins) | `cargo check --workspace` |
| mobile, AOT with no JIT | `cargo check -p synra-plugin-host --target aarch64-linux-android --features wasmtime-aot` |
| mobile, SQLite | `cargo check -p synra-store --target aarch64-linux-android` |
| light (`wasmi`) | `cargo check -p synra-core --no-default-features --features plugins --features synra-plugin-host/wasmi` |
| CLI only | `cargo check -p synra-cli` |
| no plugins | `cargo check -p synra-core --no-default-features --features transport-tcp` |

Its own warning is the reason it exists: *"core's CI must run this whole matrix, or 'the kernel can be headless / can be
mobile' will quietly rot."*

## What is actually there

**No crate in the workspace declares a `[features]` section.** Not one.

So of the seven rows, two run the same configuration as the default build (`--no-default-features` on a crate with no
features is the default build) and the other five name flags that do not exist — `plugins`, `wasmtime-aot`,
`transport-tcp`, `synra-plugin-host/wasmi`. `cargo check --features plugins` fails with "none of the selected packages
contains this feature".

The matrix is therefore not "unrun". It is **unrunnable**, and running the two rows that do work would report success for
a check that verified nothing — which is worse than reporting nothing, because it would look like coverage.

The same document also specifies a `.cargo/config.toml` for mobile target parameters. It is absent, which follows: there
are no mobile targets to parameterise yet.

## Why this is recorded rather than fixed

Building the feature system is not a mechanical change, and doing it to satisfy a matrix would be the wrong order:

1. **The flags are an architecture decision, not a build detail.** `plugins`, `wasmtime-aot`, `wasmi` and
   `transport-tcp` decide which dependencies exist in which configuration. Which of them are real — and whether
   `wasmi` is a compile-time alternative to `wasmtime` or a runtime one — is a design question with the wasm host, not
   with CI.
2. **Three of the affected crates are Stable.** `synra-protocol`, `synra-capability` and `synra-plugin-api` carry a
   stability promise, so adding a feature to one is a versioned change with an ADR rather than an edit.
3. **The mobile targets are not installed**, so the rows that matter most — the two cross-compilation ones — could not
   be verified even with the flags present. Adding a flag whose check cannot run buys nothing.

## What was built instead

`tools/guards` — the five structural invariants from the same document, as a program, plus the MSRV check. Unlike the
matrix these are checkable **now**, and each was verified by deliberate violation:

| Guard | How it was proved |
| --- | --- |
| no GUI in the kernel | the whole workspace has no `tauri`/`wry`/`tao` anywhere, so it passes by construction |
| no IO in the protocol layer | added `tokio` to `synra-protocol/Cargo.toml` → FAIL, then reverted |
| `main.rs` is a shell | padded `apps/synra-daemon/src/main.rs` past 60 lines → FAIL, then reverted. It really was 300 lines before this work |
| `directories` only in `Paths::discover` | added a `directories::` reference to `synra-store/src/sqlite/settings.rs` → FAIL, then reverted |
| every host function is gated | no `ungated_host_fn!` exists anywhere yet, so it passes by construction |

A guard that has never failed is not known to work. Three of the five were made to fail on purpose for that reason.

The MSRV row is checked by building the workspace with the toolchain `rust-version` names — and it reports **SKIP**
rather than FAIL when the toolchain's components are only partly installed, because "could not check" and "checked and
failed" are different answers. The first version of that check reported a network timeout as an MSRV failure, which is a
false accusation; a guard that cries wolf is one people learn to ignore.

## The general point

An acceptance criterion that cannot fail is not an acceptance criterion. Both halves of this note are the same mistake in
different clothes: a `rust-version` nobody built with, and a feature matrix nobody could run. The fix in each case is the
same — make the check executable, or say plainly that it is not.
