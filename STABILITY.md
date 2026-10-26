# Development contracts

Current publication status: **Unpublished**.

The application and Rust workspace have never been released. All workspace libraries, hosts, tools,
wire formats, WIT, SDK and IPC contracts may be refactored directly. Update their actual callers,
mirrors and tests together. No major-version bump, legacy-format adapter, migration note or parallel
old implementation is required for an unpublished contract.

Before an external release, record actual consumers and supported versions individually. A public
Rust item or a Cargo publish setting does not establish a released compatibility promise.

## Library boundaries

These roles describe diagnostic responsibilities, not stability tiers. Every library is unpublished.

| Boundary | Libraries | Publication | Required checks |
| --- | --- | --- | --- |
| Domain | `synra-protocol`, `synra-capability`, `synra-plugin-api`, `synra-net`, `synra-store`, `synra-core`, `synra-plugin-host` | Unpublished | Public domain errors are classified at the Synra boundary; API guard, compiler and actual callers |
| Adapter | `synra-observe`, `synra-platform`, `synra-plugin-ui`, `synra-ipc`, `synra-control`, `synra-plugin-sdk`, `synra-testkit`, `synra-testkit-alloc`, `synra-fetch`, `synra-registry` | Unpublished | Host integration, typed contracts, compiler and actual callers |

Hosts under apps/ and tools under tools/ are also unpublished. Test support remains private to
development; publish = false is packaging configuration, not an API freeze.

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

## What api-guard checks

Run cargo run --locked -p api-guard -- . from this workspace.

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
