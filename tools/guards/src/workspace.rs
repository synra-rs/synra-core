use std::path::{Path, PathBuf};
use std::process::Command;

/// The sibling app, built against this crate's public API.
///
/// # ★ Why this is a guard and not a line in a document
///
/// Because it was a line in a document, and the rule was broken anyway. `synra-rust-app` is a **separate workspace** that
/// depends on this one by path, so nothing here compiles it — and twice now a change to a `pub` signature in this
/// workspace left the app unable to build while every check in this workspace stayed green:
///
/// 1. `PluginSet::new` gained a host argument, and the app's `main.rs` kept calling it with one;
/// 2. `orchestrate::cancel` gained a `local_device` argument, and the app's intent commands kept calling it with three.
///
/// The second lasted three rounds. Both were invisible for the same reason: the two workspaces are separate, so the only
/// thing that could have noticed was a person remembering to look — which is exactly the kind of check this tool exists to
/// replace. A rule that depends on memory has now failed twice.
///
/// # Why `--no-default-features`
///
/// Because the default feature pulls in the Tauri shell, which needs a webview toolchain to build and is present on a
/// developer's machine and not on a CI box. What this checks is the **API**, and the library and the binary compile
/// without the shell — which is where both breaks were.
///
/// # The three answers
///
/// `ok`, `SKIP` with a reason, and `FAIL`. A core-only clone has no app to break and says so; "I could not check" is not
/// "I checked and it is fine", and a guard that conflates them is one people learn to ignore.
///
/// # What it costs
///
/// A build of the app, which is the most expensive thing in this tool by a wide margin — seconds against an already-built
/// target, minutes against a cold one. That is the price of the only check that has ever caught this class of mistake, and
/// it is paid on every `cargo run -p guards`. If it ever becomes the reason somebody stops running the guards, the honest
/// change is to make it opt-in and say so here, not to delete it and go back to remembering.
pub(super) fn check_sibling_app(root: &Path) -> bool {
    let Some(app) = root.parent().map(|parent| parent.join("synra-rust-app").join("src-tauri")) else {
        println!("SKIP  the sibling app is not checked out, so nothing is built against this API");
        return true;
    };
    if !app.join("Cargo.toml").is_file() {
        println!("SKIP  no sibling app at {} — a core-only clone has no app to break", app.display());
        return true;
    }

    let output = Command::new("cargo")
        .arg("build")
        .arg("--no-default-features")
        .current_dir(&app)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            println!("ok    the sibling app builds against this crate's public API");
            true
        }
        Ok(output) => {
            println!("FAIL  the sibling app no longer builds against this crate's public API");
            let stderr = String::from_utf8_lossy(&output.stderr);
            // The `error[...]` lines name the call that no longer fits, which is the whole answer: a reader needs the
            // signature and the site, not the whole transcript.
            for line in stderr
                .lines()
                .filter(|line| line.starts_with("error") && !line.contains("could not compile"))
                .take(6)
            {
                println!("        {line}");
            }
            false
        }
        Err(error) => {
            // Cargo missing is not the app failing to build. Reported as a skip for the same reason the MSRV check
            // reports a missing component as one: a guard that cries wolf is one people learn to ignore.
            println!("SKIP  cargo could not be launched to build the sibling app: {error}");
            true
        }
    }
}

/// The declared MSRV, checked by building with that toolchain.
///
/// # Why this is a check and not a number
///
/// `rust-version` is what a downstream user with an older compiler is promised. A promise nobody runs is one that rots
/// the first time a dependency raises its own floor, and the failure then lands on that user rather than here.
pub(super) fn check_msrv(root: &Path) -> bool {
    let Some(msrv) = declared_msrv(root) else {
        println!("FAIL  the MSRV could not be read from Cargo.toml");
        return false;
    };
    let toolchain = format!("+{msrv}");

    let output = Command::new("cargo")
        .arg(&toolchain)
        .arg("check")
        .arg("--workspace")
        .arg("--all-targets")
        .current_dir(root)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            println!("ok    the workspace builds on its declared MSRV ({msrv})");
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // A toolchain whose components are only *partly* installed is not an MSRV failure: `cargo +X` then tries to
            // fetch the missing pieces, and a machine without network reports a download error instead. Reporting that as
            // "does not build on the MSRV" is a false accusation, and a guard that cries wolf is one people learn to
            // ignore. The distinction is the point: "could not check" and "checked and failed" are different answers.
            //
            // Every wording rustup has used is listed, because the first version of this check recognised only one of
            // them and reported a network timeout as a build failure — the exact mistake it exists to avoid.
            if ["component download failed", "error downloading file", "could not download file"]
                .iter()
                .any(|phrase| stderr.contains(phrase))
            {
                println!("SKIP  the MSRV check needs a component that is not installed ({msrv})");
                println!("        install it once with `rustup toolchain install {msrv}` while online");
                return true;
            }
            println!("FAIL  the workspace does not build on its declared MSRV ({msrv})");
            for line in stderr.lines().filter(|line| line.starts_with("error")).take(5) {
                println!("        {line}");
            }
            false
        }
        Err(error) => {
            // A missing toolchain is a failure rather than a skip: "could not check" and "checked and passed" are
            // different answers, and only one of them is a promise kept.
            println!("FAIL  the MSRV check could not run: {error}");
            println!("        install it with `rustup toolchain install {msrv}`");
            false
        }
    }
}

/// The `rust-version` the workspace manifest declares.
fn declared_msrv(root: &Path) -> Option<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    manifest.lines().find_map(|line| {
        line.trim()
            .strip_prefix("rust-version")
            .and_then(|rest| rest.split('"').nth(1))
            .map(str::to_owned)
    })
}

/// The workspace root: the nearest ancestor whose `Cargo.toml` declares `[workspace]`.
pub(super) fn workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file()
            && std::fs::read_to_string(&manifest).is_ok_and(|text| text.contains("[workspace]"))
        {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}
