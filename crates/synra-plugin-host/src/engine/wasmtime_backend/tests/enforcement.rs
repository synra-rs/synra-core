use super::*;

#[test]
fn a_host_on_this_engine_may_start_because_it_can_enforce_everything() {
    // ★ The production caller `first_gap` never had.
    //
    // The design writes this layer's safety argument as *"a backend that cannot enforce a limit a caller asks for says so, and
    // the caller refuses rather than running third-party code with a bound it does not have"* — and until now the only caller
    // was a test. This is what the daemon and the shell now call before loading any plugin.
    let backend = Backend::new(Arc::new(
        WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine"),
    ));

    assert_eq!(
        crate::engine::check_enforceable(&backend, &crate::quota::Quota::default()),
        Ok(()),
        "the wasmtime engine and the default quota agree"
    );
}

#[test]
fn a_host_on_an_engine_that_enforces_nothing_is_refused_and_told_which_limit() {
    // ★ The other half, and the half that makes the check a check: an engine that cannot bound what it runs must not be
    // started on, and the refusal names the **first** limit rather than saying "unsupported".
    //
    // The scripted backend is what makes this testable at all: it honestly reports that it has no engine, which is exactly
    // the state a future lightweight backend would be in. It is a test double, so no production path reaches it — which is
    // why the check lives where a kernel chooses its engine rather than on every call.
    let backend = Backend::new(Arc::new(crate::engine::ScriptedBackend::new()));

    match crate::engine::check_enforceable(&backend, &crate::quota::Quota::default()) {
        Err(BackendError::CannotEnforce { missing }) => {
            assert_eq!(
                missing, "an instruction budget",
                "the first limit the defaults ask for"
            );
        }
        other => panic!("an engine that enforces nothing must be refused, got {other:?}"),
    }
}

#[test]
fn the_engine_reports_that_it_enforces_every_limit() {
    // The honest-answer rule: a caller refuses a budget it cannot be given, so what the engine claims has to be true.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let enforcement = backend.enforcement();
    assert!(enforcement.fuel);
    assert!(enforcement.epoch);
    assert!(enforcement.memory);
    assert_eq!(
        enforcement.first_gap(&CallBudget::from_quota(&crate::quota::Quota::default())),
        None
    );
    assert_eq!(backend.engine_version(), ENGINE_VERSION);
    assert!(backend.describe().contains("wasmtime-cranelift"));
}

/// ★ The claim that `enforcement()` makes has to be checked against what the backend can *do*.
///
/// The test above asserted that four booleans on a struct the backend itself returned were `true`. That is a statement
/// about a constant, not about the engine, so it passed while `precompile` claimed a capability no backend implements —
/// `WasmBackend::precompile` has a default returning `BackendUnavailable`, and `grep 'fn precompile'` finds no override
/// anywhere in the workspace.
///
/// This test ties the flag to the behaviour: whatever `enforcement()` reports as available must actually answer.
#[test]
fn what_the_engine_claims_it_enforces_is_what_it_does() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let enforcement = backend.enforcement();

    // The three limits are applied in `apply_budget`, so they are claimed and are real.
    assert!(
        enforcement.fuel && enforcement.epoch && enforcement.memory,
        "{enforcement:?}"
    );

    // Precompilation is the one that is not implemented, so it must not be claimed. This is the assertion that would
    // have caught the false claim: it fails the moment the flag and the method disagree.
    let precompiled = backend.precompile(b"\0asm", "a-plugin");
    assert_eq!(
        enforcement.precompile,
        precompiled.is_ok(),
        "enforcement() says precompile is {}, and the call answers {precompiled:?}",
        enforcement.precompile
    );
}
