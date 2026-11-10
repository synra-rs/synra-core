use std::path::Path;

/// 5. A host function reachable without the gate is a capability the manifest never granted.
///
/// # ★ This guard used to check for a macro that does not exist
///
/// It scanned every `.rs` file for the string `ungated_host_fn!`, allowing
/// `crates/synra-plugin-host/src/host_funcs/env.rs`. Both halves were wrong:
///
/// * `ungated_host_fn!` appears nowhere in the workspace except this function, which was looking for it. The scan could
///   not match, so the check could not fail.
/// * `crates/synra-plugin-host/src/host_funcs/env.rs` does not exist — there is no `host_funcs` directory at all.
///
/// It reported `ok` on every run for months, as one of the five guards. That is worse than having no guard: a missing
/// check is a gap someone may notice, while a green check is evidence that the gap has been closed.
///
/// # What is actually true
///
/// Host functions are not registered by a macro. `crates/synra-plugin-host/build.rs` regenerates
/// `src/generated/capability_table.rs` from `wit/synra-plugin.wit` on every build, so the table cannot drift from the
/// contract and cannot be hand-edited into a weaker state.
///
/// The property that remains worth checking is the one the table encodes: **every function is gated, except reads of
/// the environment**. A `None` in that table is a call any plugin may make, so each one has to be justified. The guard
/// reads the generated table and requires every ungated entry to be one of the three families that only report facts.
///
/// The runtime tests in `host_surface.rs` assert the same property from the compiled table. This runs earlier and
/// without compiling, which is the point of this tool — but it is the same rule, checked the same way, rather than a
/// check for an absent symbol.
pub(crate) fn guard_host_functions_are_gated(root: &Path) -> Vec<String> {
    // The three prefixes a call may have and still be ungated. Each one answers a question about the environment; none
    // of them acts. Anything else ungated is an action any plugin could take, which is the failure this catches.
    const UNGATED_FAMILIES: &[&str] = &["env-", "platform-capabilities", "plugin-id"];

    let table = root.join("crates/synra-plugin-host/src/generated/capability_table.rs");
    let Ok(text) = std::fs::read_to_string(&table) else {
        return vec![format!(
            "{} is missing; the capability table is the only record of which host calls are gated",
            table.display()
        )];
    };

    let mut problems = Vec::new();
    let mut ungated = 0usize;
    let mut gated = 0usize;

    for line in text.lines() {
        // An entry looks like `("synra:plugin/host#log", Some("log:*")),` or `("synra:plugin/host#env-locale", None),`.
        let Some(rest) = line.trim().strip_prefix("(\"") else {
            continue;
        };
        let Some((name, gate)) = rest.split_once("\", ") else {
            continue;
        };
        let short = name.rsplit('#').next().unwrap_or(name);

        if gate.starts_with("None") {
            ungated += 1;
            if !UNGATED_FAMILIES.iter().any(|family| short == *family || short.starts_with(family)) {
                problems.push(format!(
                    "{short} is ungated and is not a read of the environment; an ungated host call is one every plugin may make"
                ));
            }
        } else if gate.starts_with("Some(") {
            gated += 1;
        }
    }

    // A table that parsed to nothing means the format changed and this check silently stopped looking — the exact
    // failure this guard was rewritten to stop having.
    if gated == 0 || ungated == 0 {
        problems.push(format!(
            "the capability table parsed to {gated} gated and {ungated} ungated entries, which cannot be right; \
             the guard has stopped reading it"
        ));
    }

    problems
}
