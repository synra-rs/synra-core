# Working in this repository

This file is for an AI agent making changes here. It is the *only* place the rules live: where a rule needs explaining, it
links to the file that owns the explanation rather than repeating it.

Read this before the first edit of a session. `README.md` says what the project is; `STABILITY.md` says what each crate
promises. This says how to work.

---

## 1. The repository is Rust, and only Rust

`synra-core` is a Cargo workspace of 21 members: 15 libraries in `crates/`, two binaries in `apps/`, four tools in
`tools/`. Tracked files are `.rs`, `.toml`, `.md`, `.wit`, `.lock`, `.txt` (proptest regressions) and `.gitignore`.

- **Do not add a file in another language.** No `.js`, `.mjs`, `.ts`, `.py`, `.sh`, not even as a helper. A script that
  automates an edit is written as a one-off command in the shell and never committed — a `.mjs` that split a source file
  lived here once and was removed for exactly this reason.
- **Do not add another project's files.** A sibling repository is a separate project with its own repository, its own rules
  and its own release cadence. Nothing from it is copied, vendored, or referenced as a path.
- The only exception is `Cargo.lock`, which is generated and committed on purpose.

---

## 2. Facts to hold while editing

From `Cargo.toml` at the root — read it rather than trusting this list if they disagree:

| | |
| --- | --- |
| Edition | 2024 |
| Minimum Rust | 1.88 |
| Resolver | 3 |
| License | MIT |
| Author | `imba97 <mail@imba97.cn>` |
| Profile | `panic = "unwind"` — a plugin panic must be catchable |

Twenty-one workspace members. `crates/synra-protocol`, `crates/synra-capability` and `crates/synra-plugin-api` are
**Stable**: a breaking change there needs a major version, an ADR and a migration note. `STABILITY.md` names the tier of
every crate and what enforces it.

---

## 3. The lints are the specification

`[workspace.lints]` in the root `Cargo.toml` denies, not warns. A change that trips one is not a change that needs an
`#[allow]`; it is a change that has not been written yet.

Denied in the kernel:

- `unsafe_code` — forbidden outright.
- `panic`, `unwrap_used`, `expect_used` — every failure path produces a structured error. `.expect()` in a test is fine;
  in `crates/`, it is not.
- `indexing_slicing` — use `.get()`. A slice that cannot panic in practice is one a reader must prove.
- `correctness`, `suspicious` — denied at the lint-group level.
- `await_holding_lock`, `future_not_send`, `large_futures` — concurrency mistakes are compile errors here.
- `redundant_clone`, `needless_pass_by_value`, `significant_drop_tightening` — allocation and lock scope are correctness.
- `cognitive_complexity` — a function too tangled to read is refused, so **split it** rather than suppressing.
- `todo`, `unimplemented`, `dbg_macro`, `wildcard_imports`, `use_self`.

`missing_docs` warns: **every public item carries a doc comment**, including enum variants and struct fields.

### `significant_drop_in_scrutinee` has bitten this workspace repeatedly

A `parking_lot::Mutex` guard created in an `if let` or `match` scrutinee lives for the whole block. If the arm calls
something that takes the same lock, that is a **same-thread self-deadlock**, and the symptom is a hang, not an error.

```rust
// Wrong: the guard outlives the arm, and `handle` takes the same lock.
if let Ok(Some(stream)) = host.lock().try_accept() {
    handle(&Arc::clone(&host), stream)?;   // deadlock
}

// Right: one critical section, and the guard is gone before anything else runs.
let taken = host.lock().try_accept();
if let Ok(Some(stream)) = taken {
    handle(&Arc::clone(&host), stream)?;
}
```

The same applies to a `?` inside an expression that still holds a guard. Bind the value, drop the guard, then decide.

---

## 4. How code is laid out

### A module that outgrows a file becomes a directory

When one file passes roughly 500 lines of production code, split it — and split it **by who acts**, not by kind.

```
crates/synra-core/src/session/
├── mod.rs        the public surface, and why the split is what it is
├── types.rs      the vocabulary both sides share
├── wire.rs       which messages exist and how each is built
├── send.rs       the sender's job
├── receive.rs    the receiver's job
└── tests.rs      both sides at once
```

Grouping every error into one file and every struct into another is a split by syntax: a change to one feature still
touches three files. Splitting by the actor keeps a change in one place.

`mod.rs` re-exports everything the old flat module exported, so **a split is a change of layout and not of interface**.

### Splitting a file safely

This went wrong eight times on one file, for one reason: the boundaries were inferred instead of checked.

1. **Print the structure first** — every top-level item with its line number, and whether the `#[cfg(test)]` block
   contains a *nested* `mod`. A `mod proptests` beside `mod tests` rather than inside it changes where the braces go.
2. **Cut on explicit line ranges and assert each boundary** before writing anything:

   ```rust
   // A boundary check that fails loudly beats a file that compiles into something plausible and wrong. This one caught an
   // off-by-one on its first run.
   const BOUNDARIES: [(usize, &str); 3] = [
       (46, "pub const MANIFEST_SCHEMA"),
       (73, "pub struct Manifest"),
       (1359, "#[cfg(test)]"),
   ];
   ```

3. **Never count braces.** `{` inside a raw string, a format argument or a `"{{"` escape is not a brace. One 1213-line test
   block counted 505 openings against 501 closings and was perfectly valid.
4. **Compile, then run that package's tests.** Not the whole workspace — the changed package is the evidence, and the whole
   suite is for the end of a batch.

---

## 5. Editing files

**Rust sources are edited with the editor tool, not with a shell replacement.** A shell replacement reports success even when
it matched nothing: `"abc".Replace("xyz", "…")` returns `"abc"` and exits zero, so a here-string whose leading whitespace or
line endings differ by one character changes nothing while looking like it worked. That has cost hours here more than once —
a probe believed to be running and never compiled, a comment left mangled.

The rule that follows is not "never use the shell", it is **confirm every edit landed**:

```powershell
Select-String -Path <file> -Pattern '<the new text>' | Measure-Object
```

Two consequences worth knowing:

- `Select-String` is **case-insensitive** by default. Use `-CaseSensitive` when the case is the point.
- Line numbers reported by a search are 1-based; a slice index is 0-based. Most off-by-ones come from this.

---

## 6. Tests

- **A test that answers the question the production code asks is not a test of the production code.** The transfer tests all
  passed for weeks while every real transfer took six seconds, because the tests answered the sender and the daemon did not.
  When a layer has two sides, drive **both**.
- **A hanging test is worse than a missing one.** It teaches people to re-run rather than to read. If a test can block, give
  it a deadline and assert the failure.
- Anything that involves a clock takes `now_ms` as an argument. A test that sleeps is a test that flakes.
- Temporary directories remove themselves; ports are bound on port 0 rather than a fixed number; two peers are joined over a
  real loopback socket rather than a mock.
- `proptest` for a property over generated input, `rstest` for a case table. Regression files under
  `proptest-regressions/` are committed on purpose — leave them alone.

---

## 7. Commits

Conventional Commits, one line, no body.

- Subject after the colon: lowercase, imperative, English.
- **No punctuation** in the description — no comma, period, semicolon, question mark, slash.
- **≤ 50 characters**, counted, not estimated:

  ```powershell
  [System.Globalization.StringInfo]::new("fix: let a receiver wait out a quiet link").LengthInTextElements
  ```

- Types in use here: `feat`, `fix`, `refactor`, `perf`, `chore`, `docs`, `test`. `style` folds into `chore`.
- The subject must match the staged diff. `git diff --cached` first.

```powershell
git commit -m "refactor: split the transfer session by side"
```

Whether to push is the human's decision unless they have said otherwise for the session.

---

## 8. Recording what was learned

`NOTES/` holds records of bugs that cost more to *find* than to fix, written so the next investigation starts from them —
including where the search went wrong. They are not user documentation and not a changelog.

`NOTES/2026-02-transfer-six-seconds.md` is the model: the symptom, the root cause, the signals that were on screen and
misread, the instrumentation that failed, and a checklist.

Write one when a bug took more than an hour to locate, or when the searching cost more than the fixing. The value is in the
**process** — a note that only says what the bug was has no value a commit message does not already have.

---

## 9. Response to a failing check

Do not suppress. In order:

1. Read what the lint or test actually says. A `significant_drop_in_scrutinee` is a deadlock, not a style preference.
2. If it is a real defect, fix the defect.
3. If the code is right and the lint is wrong, the narrowest `#[allow]` goes on the **smallest** scope, with a comment
   saying why. A file-level allow needs a reason that survives review.
4. Never `--no-verify`, never delete a test to make a suite green, never loosen a workspace lint to land a change.
