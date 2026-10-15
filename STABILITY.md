# Stability

What this repository promises, crate by crate, and what it checks to keep the promise.

The design document's rule is that a promise nobody checks is a wish, so each tier below names the check that enforces
it. Everything here is in the workspace's `crates/`, plus the two hosts and the author's tool in `apps/` and `tools/`.

## The tiers

| Tier | Crates | Promise | Published | What enforces it |
| --- | --- | --- | --- | --- |
| **Stable** | `synra-protocol`, `synra-capability`, `synra-plugin-api` | SemVer. A breaking change needs a major version, an ADR, and a migration note. | yes | the rules below, and `api-guard` |
| **Semi-stable** | `synra-net`, `synra-store`, `synra-core`, `synra-plugin-host` | SemVer. A **trait** may gain a method in a minor version if that method has a default. | yes | the rules below, and `api-guard` |
| **Internal** | `synra-observe`, `synra-platform`, `synra-plugin-ui`, `synra-ipc`, `synra-control`, `synra-plugin-sdk`, `synra-testkit`*, `synra-testkit-alloc`*, `wit-codegen`, `synra-plugin-cli`, `synra-cli`, `synra-daemon` | No promise. Anything may change in any version. | partly | nothing — and that is the point |

\* `synra-testkit` and `synra-testkit-alloc` set `publish = false`: a fixture's API changes whenever a test needs it,
and a published crate's API is a promise.

★ `synra-control` and `synra-plugin-sdk` were added here and to `api-guard`'s table together, because they had been in
neither. The check that was meant to catch this asserted `CRATES.len() >= 13` — a transcription of the table rather than
a comparison against the workspace — so two crates existed with no tier and nothing reported it. The check now reads
`Cargo.toml` and fails on any crate under `crates/` that is unclassified.

Both are `Internal` on purpose. `Internal` promises nothing, so moving either **up** a tier later breaks no one, while
declaring one `Stable` before its shape has settled makes the first breaking change a broken promise. `synra-plugin-sdk`
is the one to revisit: it is what a plugin author compiles against, so it will want `Stable` once there are authors whose
builds it could break.

### Why "semi-stable" is a tier and not a fudge

`synra-core` is the orchestration layer, and its business rules will grow. It has to distinguish two things:

* **The interface** — `Kernel`'s public methods — is stable.
* **The internal structure** — how the aggregates are composed — may move.

Without that distinction the choice is between freezing everything and moving everything, and both are wrong: the first
makes evolution impossible, and the second interrupts every downstream consumer repeatedly.

### Why the hosts and the tools are internal

`synra-cli` and `synra-daemon` are *hosts*: they exist so a person can use the kernel without a window, and their
command surfaces change when a person's workflow does. `synra-plugin-cli` is an author's tool whose output is an
artifact rather than a library. None of them is a dependency of anything.

They are still checked — the commands parse, the reports are asserted — but nothing downstream may rely on their
shapes.

## The rules a stable crate follows

### No concrete container types in a public signature

A public `HashMap` is a promise about the implementation: replacing it with a `BTreeMap` would be a breaking change,
and the replacement is exactly the change a performance problem calls for. Public signatures take and return the
crate's own types, or an iterator when a sequence is meant.

`Vec` is the exception where the order *is* the contract — a list of files is a list — and even there a `&[T]` is
preferred to a `Vec<T>` on the way in.

### Public struct fields are private, with a constructor and accessors

A public field is a second way to construct the type, and it stays valid only as long as the invariants hold. Every
stable crate's public structs have private fields; construction goes through a function that checks, and reading goes
through a method that borrows.

The exceptions are types whose whole purpose is to be a bag of fields — a DTO — and those are `#[non_exhaustive]` so a
field can be added without a major version.

### Enums for third parties are `#[non_exhaustive]`; internal ones are not

An enum a consumer must match on is one where a new variant is a breaking change for them. `#[non_exhaustive]` makes
that a compile error *they* see, with a message that says to add an arm, rather than a match that silently falls through
to a default.

An enum that stays inside the workspace must **not** be `#[non_exhaustive]`: it would force a wildcard arm that
suppresses the compiler's own exhaustiveness check, which is the one thing that catches a variant nobody handled.

### Errors expose stable codes, not third-party types

A public error variant holding `std::io::Error` or `serde_json::Error` is a promise about *that* crate's version: a
minor release of `serde_json` would change this crate's error type. Errors carry the kernel's own `ErrorCode` and a
sentence; the third-party error is kept in a `details` string, where it is useful and not a promise.

## What is checked, and how

### The hot paths allocate nothing

`crates/synra-core/tests/hot_paths.rs` installs an allocation counter and asserts that decoding a frame, matching a
capability, running the gate and routing an event allocate **zero**.

An allocation on a per-frame path is a lock, a branch and a possible failure inside the allocator, multiplied by the
frame rate. A benchmark would catch it eventually and flakily; a count is exact.

The assertion is deliberately about the *refusals* too — a capability that does not match and an event with no
subscriber. Those are the paths a hostile peer drives, and they are the ones a naive implementation allocates on.

### The public API is checked by reading the source

`tools/api-guard` reads every file of every stable and semi-stable crate and reports the rules above where they are
broken:

* a concrete container type in a public signature;
* a public struct whose fields are public;
* an enum a consumer must match on that is missing `#[non_exhaustive]`, and an internal enum that has it and so
  suppresses the compiler's own exhaustiveness check;
* a public error variant holding a third-party type.

It is a text pass rather than a compiled one, deliberately: `cargo public-api` is not installed everywhere, and a check
that cannot run is a check nobody runs. What a text pass cannot catch — a re-exported type, a signature that got longer
without gaining a forbidden word — is what a reviewer reads a diff for.

The snapshot files under `api/*.txt` are **not** committed. A `cargo public-api` snapshot is a better artefact than a
text pass and it is what this file used to promise; it is not here, and a promise about a directory that does not exist
is worse than a smaller promise that holds.

### The WIT contract is enforced at build time

`crates/synra-plugin-host/build.rs` regenerates the capability table from `wit/synra-plugin.wit` before the crate
compiles, and the generator **refuses** a host function with no `@ungated` or `@capability` annotation.

That is the strongest check in the repository, and it is a build failure rather than a test because the thing it
prevents is a host function **any plugin can call** — a hole with no symptom. Adding one by accident is impossible:
the crate does not compile.

### Every crate denies what would make a promise unkeepable

The workspace's lints deny `panic`, `unwrap_used`, `expect_used`, `indexing_slicing`, `unsafe_code` and
`missing_docs` at the crate root. A public function that can panic has a failure mode not in its signature, and
"documented" is a precondition for "stable".

`synra-testkit-alloc` is the one crate that allows `unsafe`, in its `Cargo.toml`'s lint table rather than in a source
file — so the exception is a property of a crate a reader can find, and the crate is 300 lines of allocator
forwarding. Test code is exempt from the panic family: a fixture that fails loudly is a fixture that works.

## Changing something

1. **A stable crate's public API.** Add the change and say in the pull request why the promise is being changed; run
   `cargo run -p api-guard -- .` and fix what it reports. A breaking change needs a major version and an ADR.
2. **A semi-stable crate's trait.** Adding a method with a default is a minor change. Adding one without a default is
   not.
3. **The WIT contract.** Edit `wit/synra-plugin.wit`, annotate every host function, and build. The table regenerates
   and the host, the gate and the plugin CLI's import check all follow from it.
4. **An internal crate.** Anything, any time. That is what the tier is for.

## What is deliberately not checked

* **Benchmarks.** They need a machine whose noise is controlled, which CI is not. The allocation counts catch the
  regressions that matter and do it deterministically.
* **A compiled API snapshot.** `cargo public-api` writes a better artefact than a text pass and it is not installed in
  every environment; the text pass in `tools/api-guard` is what runs, and it says what it cannot see.
* **The number of public items.** "It grew" is not a problem; "it grew by accident" is, and that is what a diff shows.