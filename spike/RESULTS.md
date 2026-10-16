# Spike results

Each row is an assumption from `synra-rs/design-docs` → `19-roadmap.md` §0.1, the conclusion, and the command that
reproduces it.

**A spike is written to be falsified, not to make something work.** A row that says "blocked by this machine" is a
completed spike — it names the exact missing prerequisite and the exact command that settles it once installed. What is
*not* allowed is a row that reports a pass it did not earn, which is the mistake
[2026-02-the-feature-matrix-was-never-buildable.md](../NOTES/2026-02-the-feature-matrix-was-never-buildable.md)
already documents.

| # | Spike | Verdict | One line |
| --- | --- | --- | --- |
| 3 | wasmtime → aarch64-linux-android | ✅ **pass** | wasmtime 38 + component-model + cranelift checks clean for the target |
| 4 | rusqlite bundled → aarch64-linux-android | ✅ **pass** | `libsqlite3-sys` compiles the SQLite amalgamation with the NDK's clang |
| 7 | protocol conformance | ✅ **done** | superseded by `cargo nextest run -p synra-protocol --test wire_fixtures` |
| 1 | Tauri 2 mobile + tokio | ⛔ not run | needs JDK + Android SDK + a device |
| 2 | Tauri 2 mobile + a wasm instance | ⛔ not run | depends on 1 |
| 5 | multi-WebView independent origins | ⛔ not run | desktop spike, runnable today |
| 6 | CSP blocks a plugin's fetch | ⛔ not run | desktop spike, runnable today |
| 8 | host-call latency under concurrency | ⛔ not run | needs `cargo bench` on the plugin host |

> ⚠️ **What a green 3 and 4 do not mean.** `cargo check` never links and never runs. They prove the dependency graphs
> survive the target. They do **not** prove that an `.so` links, that a component instantiates on a phone, or — most
> importantly — that Cranelift's JIT can obtain executable memory at runtime on a release Android build. See
> [The JIT question](#the-jit-question) below. Spikes 1 and 2 are what settle that, and they still need a device.

---

## Environment

The host decides what can be run and must be recorded with the results — a spike result without its environment is not
reproducible.

| Fact | Value |
| --- | --- |
| `rustc` | 1.98.1 (MSRV declared 1.88; the 1.88 toolchain is installed for the MSRV job) |
| Android SDK | `C:\Users\imba97\AppData\Local\Android\Sdk` — `platforms/android-36`, `build-tools`, `platform-tools` |
| **`cmdline-tools`** | **absent** — `sdkmanager` cannot install anything, including the NDK |
| JDK | **absent** (`java` not on PATH) — blocks spikes 1 and 2 |
| `rustup target add aarch64-linux-android` | done; target std present |
| **NDK** | **r28b, `Pkg.Revision = 28.1.13356709`**, installed to `C:\Android\ndk\28.1.13356709` |

### The NDK had to be installed by hand, and it could not go on `D:`

`D:` had **2.4 GB free**. The NDK is 713 MB compressed and about 3 GB extracted, so it went to `C:` (34.4 GB free).
`C:\Android\ndk\` is outside the project tree on purpose — the SDK is machine state, not a repository artefact.

> ⚠️ **`D:` running out of space silently failed a build rather than reporting it cleanly.** Compiling
> `synra-plugin-host` with `wasm-runtime` for Android ran out mid-way through Cranelift's ISLE code generation and
> surfaced as `StorageFull (os error 112)` attributed to a *source* file. Any Android row needs its target directory
> somewhere with room:
>
> ```
> set CARGO_TARGET_DIR=C:\cargo-target\synra-android
> ```

### The toolchain variables

```
set CC_aarch64_linux_android=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd
set AR_aarch64_linux_android=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-ar.exe
set CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd
```

API 24 because that is Tauri 2's minimum. The NDK ships 21 through 35.

---

## Spike 4 — rusqlite bundled → aarch64-linux-android

**Assumption:** the kernel stores to SQLite compiled from source on every platform, so that `foreign_keys` and the
schema behave identically everywhere. The cost is a C toolchain on every build host. The roadmap's fallback is `redb`,
pure Rust — a large change to `synra-store`'s schema layer.

**Command**

```
cd spike/04-rusqlite-android && cargo check --target aarch64-linux-android
```

**Conclusion: pass.**

```
Compiling libsqlite3-sys v0.38.2
Checking rusqlite v0.40.2
Finished `dev` profile [unoptimized + debuginfo] target(s) in 12.53s
```

The roadmap's fallback to `redb` is **not** needed on the strength of this spike.

> ⚠️ `rusqlite` *without* `bundled` would also have passed, and proved nothing: it links the platform's SQLite instead
> of compiling the one that ships. The spike is written against `bundled` on purpose for that reason.

---

## Spike 3 — wasmtime → aarch64-linux-android

**Assumption:** the plugin backend can stay `wasmtime` + cranelift on Android, as `crates/synra-plugin-host` already
builds it on the desktop. Risk R-01 is 🔴 high because this had never been compiled for a phone.

**Command**

```
cd spike/03-wasmtime-android && cargo check --target aarch64-linux-android
```

**Conclusion: pass.** Same wasmtime version and same feature set as the crate itself —
`38`, with `component-model`, `cranelift`, `runtime`, `std`.

> **First run, before the NDK existed**, this failed with `cc-rs: failed to find tool "clang.exe"`. That was an
> infrastructure failure and was recorded as one rather than as a verdict. wasmtime is **not** pure Rust on this
> target — its build script compiles `runtime/vm/helpers.c` — so the spike could not have concluded anything until a C
> cross-compiler was present.

---

## The real matrix rows

The spikes use the same versions as the workspace, but the questions that matter are about the workspace's own crates.
With the NDK in place:

| Command | Result |
| --- | --- |
| `cargo check -p synra-protocol -p synra-capability --target aarch64-linux-android` | ✅ pass (also passed *before* the NDK) |
| `cargo check -p synra-net --target aarch64-linux-android` | ✅ pass (also passed *before* the NDK) |
| `cargo check -p synra-store --target aarch64-linux-android` | ✅ pass |
| `cargo check -p synra-core --target aarch64-linux-android` | ✅ **pass** |
| `cargo check -p synra-plugin-host --features wasm-runtime --target aarch64-linux-android` | ✅ **pass** (1m50s) |

**The entire kernel cross-compiles to Android aarch64 today**, including SQLite and including real wasmtime. Before the
NDK, the last two failed on `cc-rs`.

---

## The JIT question

wasmtime's build sets these cfgs for `aarch64-linux-android`:

```
cargo:rustc-cfg=has_virtual_memory
cargo:rustc-cfg=has_host_compiler_backend
```

`has_host_compiler_backend` means wasmtime considers a **JIT** compiler backend available on this target. So
`wasmtime-aot` is, on this evidence, an **iOS** requirement rather than an Android one: iOS forbids executable memory
outright, Android does not.

**But that is not the same as saying JIT works on a release Android build, and the matrix must not imply it.**

- Android enforces W^X. An app cannot create an anonymous `PROT_EXEC` mapping unless it is JIT-signed, and an app
  distributed through Play is not.
- Cranelift allocates executable memory **at runtime**. That is exactly the operation Android restricts.
- `cargo check` compiles the code that *would* do it. It never performs it.

So the honest state is two-tier:

| Question | Answer |
| --- | --- |
| Does wasmtime + cranelift **compile** for Android? | ✅ yes, proven here |
| Does Cranelift **JIT** on a release Android build? | ❓ **unproven** — needs a device; spikes 1 and 2 |
| Does it work on iOS? | ❓ unproven, and needs macOS — `wasmtime-aot` exists for this |

**Consequence for the design.** `19-roadmap.md` §0.1 and `06-workspace-layout.md` §6 both list `wasmtime-aot` as the
*Android* row. If Android turns out to need AOT for release, that is a much bigger constraint than the documents
assume, and it should be resolved before M4 ships a desktop app whose plugin host cannot be reused on mobile.

The cheap way to settle it: build a **release** APK (where the restriction bites, not debug) and have the plugin host
instantiate one component at startup, asserting the engine was configured for AOT or Pulley rather than JIT. Until
that runs, treat Android's Wasm story as open.

---

## Findings that contradict the design documents

Found while building these spikes; each is a doc/reality mismatch rather than a code defect, and each is cheap to fix.

| # | Finding | Where |
| --- | --- | --- |
| 1 | `synra-plugin-host` **already has** `[features]`: `wasm-runtime` (default off) and `wasm-text`. The note claiming "no crate declares a `[features]` section" was true when written and is stale for 1 of 21 crates. | `06-workspace-layout.md` §6 |
| 2 | The matrix names `plugins`, `wasmtime-aot`, `transport-tcp`, `synra-plugin-host/wasmi`. The crate ships `wasm-runtime` and `wasm-text`. The names do not match, so the matrix cannot run even where the capability exists. | `06-workspace-layout.md` §6 |
| 3 | The workspace pins `wasmtime = "38"`; `README` §8 anchors Wasmtime at `48.x`. Ten minor versions apart. | `design-docs/README.md` §8 |
| 4 | The workspace pins `rusqlite = "0.40"`; `README` §8 anchors it at `0.3x`. | `design-docs/README.md` §8 |
| 5 | §7.2's `justfile` refers to `./xtask/guards.sh`, `./xtask/check-matrix.sh`, `./xtask/check-msrv.sh`. There is no `justfile` and no `xtask/`; the guards that exist are the Rust binary `tools/guards`. | `06-workspace-layout.md` §7.2 |
| 6 | Three crates in the workspace appear nowhere in the design docs: `synra-control`, `synra-ipc`, `synra-testkit-alloc`. | `06-workspace-layout.md` §1 |
| 7 | `06 §7.2` puts the Android cross-compile checks in the core repository but never says where the NDK comes from, or that `cmdline-tools` is not assumed. This workspace has no `sdkmanager`. | `06-workspace-layout.md` §7.2 |

---

## Reproducing everything above

```powershell
$ndkbin = "C:\Android\ndk\28.1.13356709\toolchains\llvm\prebuilt\windows-x86_64\bin"
$env:CC_aarch64_linux_android = "$ndkbin\aarch64-linux-android24-clang.cmd"
$env:AR_aarch64_linux_android = "$ndkbin\llvm-ar.exe"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$ndkbin\aarch64-linux-android24-clang.cmd"
$env:CARGO_TARGET_DIR = "C:\cargo-target\synra-android"   # D: does not have the room

cd synra-rust-core/spike/04-rusqlite-android && cargo check --target aarch64-linux-android   # pass
cd synra-rust-core/spike/03-wasmtime-android && cargo check --target aarch64-linux-android   # pass
cd synra-rust-core
cargo check -p synra-core --target aarch64-linux-android                                      # pass
cargo check -p synra-plugin-host --features wasm-runtime --target aarch64-linux-android       # pass
```
