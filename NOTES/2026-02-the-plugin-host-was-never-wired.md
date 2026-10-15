# The feature matrix had nothing to run, and the plugin host was never wired

Two findings from building `tools/matrix`, recorded together because the second one changes what the first one is
allowed to conclude.

## The matrix had no rows

`tools/matrix` runs the combinations `06-workspace-layout.md` §6 promises. When it was written, seven of them were named
and **none of them could have run**:

- Five named flags that do not exist: `plugins`, `wasmtime-aot`, `transport-tcp`, `synra-plugin-host/wasmi`.
- Two that do — `cargo check -p synra-core --no-default-features` and `cargo check -p synra-cli` — pass for the wrong
  reason. `--no-default-features` on a crate that declares no features *is* the default build, so the row verified
  nothing while reporting success.

Seven rows that either fail or mean nothing is the same failure as the one in
[2026-02-the-feature-matrix-was-never-buildable.md](2026-02-the-feature-matrix-was-never-buildable.md), reached from the
other direction: that note said the matrix is unrunnable, and this is what unrunnable looks like when you try to run it.

## Why most of them still cannot run

Adding the missing flags is not a build detail, and it is not what was missing:

| Row | What it needs | Why it is not there |
| --- | --- | --- |
| "no plugin subsystem" | `synra-core`'s `plugins` feature | `synra-core`'s source **never names** `synra_plugin_host` or `synra_plugin_api` |
| "wasmi interpreter" | a `wasmi` dependency | no backend selection exists at all |
| "precompiled engine" | a `wasmtime-aot` feature | iOS-shaped question, and iOS is not buildable here |
| "without TCP" | `synra-net`'s `transport-tcp` | TCP is the only transport implemented |

`synra-core` declares both `synra-plugin-host` and `synra-plugin-api` in `[dependencies]`. Neither appears in a single
line of its production source. `synra-plugin-host` appears only in `tests/hot_paths.rs`, and that file is already covered
by the `dev-dependencies` entry, so the `[dependencies]` one is redundant on top of unused.

**A feature flag that switches off nothing is the feature matrix problem again, one level down.** Declaring `plugins` on
`crates/synra-core` would have made that one row green while the kernel still had no plugin subsystem — a green row over
an absent feature is precisely what the previous note warns about.

So the flags are not written, and `tools/matrix` prints those four rows as `SKIP` with the reason instead. The matrix is
now a thing that runs and reports honestly, which it was not before, and the gap is on screen rather than in a note.

## The real finding: no plugin host is wired to anything

Searching for what constructs `intent::Board` — 530 lines, 604 lines of tests, the type that owns every decision about
when to stop asking plugins and what a user picked — returned **nothing outside its own module**. And the daemon says so
itself, in the one place it would be inconvenient to say it
([`apps/synra-daemon/src/runtime/reports.rs`](../../apps/synra-daemon/src/runtime/reports.rs)):

```rust
// ★ `false`, so a client does not present an installed plugin as one that is running. The kernel has loaded
// nothing: there is no Wasm host wired to this daemon yet.
"loaded": false,
```

The CLI agrees ([`apps/synra-cli/src/session.rs`](../../apps/synra-cli/src/session.rs)): `plugin list` is served and
install/enable/disable "are not asked for at all".

### What this means for reading the roadmap

M2 and M3 look complete when you count commits, and their *libraries* are — `synra-plugin-host` compiles components with
wasmtime, gates 35 host functions through the capability check, runs the 13-state lifecycle, verifies packages in 11
ordered steps, and signs them. The store's `plugins` table is real and `plugin_sync.rs` really moves a bundle between
devices.

What does not exist is the **path**: nothing raises an intent, feeds it to the board, calls a plugin through the host,
and settles the result. Every one of those halves exists; the seam between them is unwritten.

So "M2 complete" is wrong in the way that matters, and it is wrong *invisibly* — the code is substantial, the tests
pass, and the guard that would notice is exactly the `plugins` feature row the matrix could not run.

### The seam, precisely

For someone picking this up, the work is not "build the plugin host" — that is built. It is:

1. `synra-core` depends on `synra-plugin-host` and `synra-plugin-api` **for a reason**: the kernel owns intent, and the
   board's candidates have to come from real plugins.
2. `apps/synra-daemon` constructs a `Board` and a plugin host, and passes one to the other.
3. `runtime/reports.rs` stops hardcoding `"loaded": false`.
4. `synra-core`'s unused dependencies stop being unused, which is what makes the `plugins` feature meaningful.

Until step 1 exists, the honest row in `tools/matrix` is a `SKIP`, not an `ok`.
