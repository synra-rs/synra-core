# Development contracts

Current publication status: **Published at 0.1.0**.

The libraries are on crates.io at 0.1.0. The hosts under apps/ and the tools under tools/ remain
unpublished. The wire formats, WIT and IPC contracts now have external consumers and follow the
0.1.0 line: a breaking change to any published crate needs a minor bump on the 0.x line, and every
affected crate is republished in dependency order.

The 0.1.0 line carries no compatibility promise beyond the crate versions themselves. A public Rust
item does not by itself establish one; only the recorded consumers and the versions below do.

## Library boundaries

These roles describe diagnostic responsibilities, not stability tiers. Every published library is at
0.1.0; `synra-testkit`, `synra-testkit-alloc` and `synra-fetch` stay private to development.

| Boundary | Libraries | Publication | Required checks |
| --- | --- | --- | --- |
| Domain | `synra-protocol`, `synra-capability`, `synra-plugin-api`, `synra-net`, `synra-store`, `synra-core`, `synra-plugin-host` | 0.1.0 | Public domain errors are classified at the Synra boundary; API guard, compiler and actual callers |
| Adapter | `synra-observe`, `synra-platform`, `synra-plugin-ui`, `synra-ipc`, `synra-control`, `synra-plugin-sdk`, `synra-registry` | 0.1.0 | Host integration, typed contracts, compiler and actual callers |
| Build | `synra-wit-codegen` | 0.1.0 | Generated contract mirrors are checked against their owning source |
| Private | `synra-testkit`, `synra-testkit-alloc`, `synra-fetch` | publish = false | Test support and internal fetch stay out of the release |

Hosts under apps/ and tools under tools/ are unpublished, except `synra-wit-codegen`: the host's build
script depends on it, so it ships as a build dependency. Test support remains private to development;
publish = false is packaging configuration, not an API freeze.

## Published versions

Every crate below is on crates.io at 0.1.0. Publishing order is dependency order: a crate never
precedes the crates it depends on.

`synra-protocol`, `synra-wit-codegen`, `synra-store`, `synra-capability`, `synra-observe`, `synra-net`,
`synra-plugin-api`, `synra-registry`, `synra-plugin-ui`, `synra-plugin-host`, `synra-plugin-sdk`,
`synra-platform`, `synra-control`, `synra-ipc`, `synra-core`.

A crate that reads the plugin contract carries its own copy of `wit/synra-plugin.wit`, because
`cargo package` ships only files inside the crate directory. The copies mirror the workspace source;
regenerate and check them together with the derived artifacts.

## Refactoring and encapsulation

- Exhaustive enums, public DTO fields, container choices and required trait methods may change.
- Use private state and checked entry points where domain or security invariants require them.
- Read-only data snapshots may expose fields and containers directly.
- Choose non_exhaustive for a concrete boundary reason; the guard neither requires nor forbids it.
- Do not expose an unclassified dependency error through a shared domain interface. Callers need
  machine-readable failure categories; implementation errors are translated at the owning boundary.

## Checks that remain mandatory

- Dependency direction stays enforced by tools/guards: protocol types have no IO or GUI dependencies,
  and the kernel is independent of the desktop shell.
- Capability checks, authentication, namespace ownership, resource limits, sandbox paths and task
  cancellation retain their runtime checks and refusal tests.
- Workspace lints continue to reject unsafe code, production panic paths and lock mistakes.
  The isolated counting-allocator test crate keeps its explicit unsafe exception.
- WIT host functions require capability or ungated annotations. Contract mirrors and generated
  resources are checked against their owning source.
- Allocation budgets stay in the actual hot_paths and hot_path_alloc tests. Do not raise a budget
  to accommodate an uninvestigated regression.
- API and protocol changes compile real callers, including the sibling app and JS consumers where
  applicable, and cover real Wasm, database or transport boundaries.

## What synra-error-guard checks

Run cargo run --locked -p synra-error-guard -- . from this workspace.

The guard parses shared domain declarations and public signatures for unclassified dependency
errors, reports unreadable or invalid sources, and reads the whole declared library catalogue.
Tests compare that catalogue with actual Cargo workspace metadata and this document. A missing or
duplicate library cannot silently escape classification. IO failures do not become successful scans.

It does not freeze signature snapshots, forbid DTO containers, require compatibility annotations
or infer publication from pub. Name resolution, macro expansion, security semantics and actual
consumer compatibility remain compiler, integration-test and review responsibilities.

## Verification frequency

Run targeted compilation, lint and affected tests during development; run applicable phase gates
when a coherent change is ready. Reuse unchanged passing checks and retain diagnostic evidence.
Regularly remove confirmed unused build variants, temporary directories and failed outputs while
preserving source, runtime data and useful dependency caches. Check available space before large
links as an additional preflight, not as the trigger for routine cleanup.
