# Stability

What this repository promises, crate by crate, and what it checks to keep the promise.

The design document's rule is that a promise nobody checks is a wish, so each tier below names the check that enforces
it. Everything here is in the workspace's `crates/`, plus the two hosts and the author's tool in `apps/` and `tools/`.

## The tiers

| Tier | Crates | Promise | Published | What enforces it |
| --- | --- | --- | --- | --- |
| **Stable** | `synra-protocol`, `synra-capability`, `synra-plugin-api` | SemVer. A breaking change needs a major version, an ADR, and a migration note. | yes | the rules below, and `api/*.txt` snapshots |
| **Semi-stable** | `synra-net`, `synra-store`, `synra-core`, `synra-plugin-host` | SemVer. A **trait** may gain a method in a minor version if that method has a default. | yes | the rules below |
| **Internal** | `synra-observe`, `synra-platform`, `synra-plugin-ui`, `synra-ipc`, `synra-testkit`*, `wit-codegen`, `synra-plugin-cli`, `synra-cli`, `synra-daemon` | No promise. Anything may change in any version. | partly | nothing — and that is the point |

\* `synra-testkit` and `synra-testkit-alloc` set `publish = false`: a fixture's API changes whenever a test needs it,
and a published crate's API is a promise.

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

### The public API is snapshotted

`api/*.txt` holds `cargo public-api --simplified` output for every stable and semi-stable crate. A change to one is a
change to the promise, and CI fails until it is regenerated.

The tool is not installed in every environment, so the snapshot is regenerated by whoever changes a public signature
and reviewed in the pull request that changes it. What the snapshot catches is what a reviewer would otherwise have to
notice by reading a diff of generic-heavy Rust:

* a concrete type that reached a public signature;
* a `pub` that should have been `pub(crate)`;
* a public surface that grew by accident.

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

1. **A stable crate's public API.** Add the change, regenerate `api/<crate>.txt`, and say in the pull request why the
   promise is being changed. A breaking change needs a major version and an ADR.
2. **A semi-stable crate's trait.** Adding a method with a default is a minor change. Adding one without a default is
   not.
3. **The WIT contract.** Edit `wit/synra-plugin.wit`, annotate every host function, and build. The table regenerates
   and the host, the gate and the plugin CLI's import check all follow from it.
4. **An internal crate.** Anything, any time. That is what the tier is for.

## What is deliberately not checked

* **Benchmarks.** They need a machine whose noise is controlled, which CI is not. The allocation counts catch the
  regressions that matter and do it deterministically.
* **`cargo-public-api` in CI.** It needs a nightly-free setup this repository does not have everywhere; the snapshot is
  a review artifact rather than a gate.
* **The number of public items.** "It grew" is not a problem; "it grew by accident" is, and that is what a diff shows.