//! The check itself, and the two questions it asks of a bundle.


use synra_plugin_api::manifest::ValidationLevel;

use super::limits::{MAX_UI_BYTES, MAX_UI_FILES, MAX_WASM_BYTES, PROVIDED_IMPORTS, REFUSED_IMPORTS};
use super::target::Target;
use super::verdict::{Finding, VerifyReport};


use synra_plugin_api::manifest::{Implementation, Manifest, ManifestContext};

/// Whether a rule on one of the lists covers an import.
///
/// # Why not `starts_with`
///
/// ★ A prefix comparison is wrong in the direction that matters. `synra:host/exec` is on the refused list and
/// `synra:host/execute` is on the provided one, and `"synra:host/execute".starts_with("synra:host/exec")` is **true** —
/// so a plugin importing the provided `execute` would have been refused for importing the forbidden `exec`. A test
/// caught it; a user would not have.
///
/// An import is a *namespace* and an *item*, and a rule matches either the whole import or the namespace it belongs to.
/// The separator is what makes the difference, so it is what the comparison uses.
pub(crate) fn covers(rule: &str, import: &str) -> bool {
    if import == rule {
        return true;
    }
    // `wasi:filesystem` covers `wasi:filesystem/types` and `wasi:filesystem/preopens`, and does not cover
    // `wasi:filesystemx`.
    import
        .strip_prefix(rule)
        .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('@') || rest.starts_with(':'))
}

/// Runs every check.
#[must_use]
pub fn verify(target: &Target) -> VerifyReport {
    let mut findings = Vec::new();
    let mut plugin_id = None;
    let mut version = None;

    // ── The manifest ──────────────────────────────────────────────────────────────────────────────
    let manifest = match target.manifest_json.as_deref() {
        None => {
            findings.push(Finding::fail(
                "manifest",
                "there is no manifest.json here",
                "run this from the plugin's directory, or pass --dir",
            ));
            None
        }
        Some(text) => match Manifest::from_json(text) {
            Err(error) => {
                findings.push(Finding::fail(
                    "manifest",
                    format!("the manifest does not parse: {error}"),
                    "check the field the message names against the schema",
                ));
                None
            }
            Ok(mut manifest) => {
                let context = ManifestContext {
                    host_sdk: Some(manifest.sdk.min.clone()),
                    // Derived from the runtime block rather than taken from the manifest, because the manifest has no
                    // separate `implementation` field: what a plugin implements *is* which halves it ships. Passing it
                    // means the schema check also verifies that the declared entry points agree with the declared
                    // artifacts — the check that catches a manifest claiming a UI with no bundle.
                    implementation: Some(Implementation {
                        on_event: manifest.runtime.headless.is_some(),
                        execute: manifest.runtime.headless.is_some(),
                        activate: manifest.runtime.ui.is_some(),
                    }),
                    ..ManifestContext::default()
                };
                match manifest.validate(ValidationLevel::Schema, &context) {
                    Ok(()) => {
                        plugin_id = Some(manifest.id.to_string());
                        // Moved rather than cloned: this is the last use of the version before the manifest itself is
                        // returned, so the string has an owner to go to and the clone was pure cost.
                        version = Some(std::mem::take(&mut manifest.version));
                        findings.push(Finding::pass("manifest", "parses and validates"));
                        Some(manifest)
                    }
                    Err(error) => {
                        plugin_id = Some(manifest.id.to_string());
                        version = Some(manifest.version.clone());
                        findings.push(Finding::fail(
                            "manifest",
                            format!("the manifest does not validate: {error}"),
                            "the kernel makes this same check at install time and refuses the plugin there",
                        ));
                        None
                    }
                }
            }
        },
    };

    // ── The artifact, against the kind the manifest declares ──────────────────────────────────────
    // What the manifest says it ships, which decides which artifact checks apply. A headless plugin has no interface and
    // a UI-only plugin has no Wasm, so running both sets against both would report a finding about a file that cannot
    // exist — and an author would go looking for it.
    let wants_wasm = manifest.as_ref().is_none_or(|manifest| manifest.runtime.headless.is_some());
    let wants_ui = manifest.as_ref().is_none_or(|manifest| manifest.runtime.ui.is_some());

    // A manifest that did not parse leaves both unknown, so both halves are checked and each reports what it found —
    // which is more useful than one finding that says "the kind could not be determined".
    let check_wasm = wants_wasm || manifest.is_none();
    let check_ui = wants_ui || manifest.is_none();

    if check_wasm {
        match target.wasm_bytes {
            None => findings.push(Finding::fail(
                "wasm",
                "the manifest names a Wasm entry point and there is no plugin.wasm",
                "run `synra-plugin build`",
            )),
            Some(0) => findings.push(Finding::fail(
                "wasm",
                "plugin.wasm is empty",
                "the build produced nothing: check that it writes to the path this command reads",
            )),
            Some(bytes) if bytes > MAX_WASM_BYTES => findings.push(Finding::fail(
                "wasm",
                format!("plugin.wasm is {bytes} bytes, over the {MAX_WASM_BYTES}-byte limit"),
                "enable size optimisation in the profile, or move work into the host",
            )),
            Some(bytes) => {
                findings.push(Finding::pass("wasm", format!("{bytes} bytes")));
                // A large artifact is worth saying out loud even when it is inside the bound: a plugin's size is
                // something the user pays for on every install.
                if bytes > MAX_WASM_BYTES / 2 {
                    findings.push(Finding::warn(
                        "wasm-size",
                        format!("{bytes} bytes is over half the limit"),
                        "a plugin this large is one whose first call the user will feel",
                    ));
                }
            }
        }
    }

    if check_ui {
        match target.ui_bundle {
            None => findings.push(Finding::fail(
                "ui",
                "the manifest names a UI entry point and there is no ui/ directory",
                "run `synra-plugin build`",
            )),
            Some((0, _)) => findings.push(Finding::fail(
                "ui",
                "the ui/ directory is empty",
                "a plugin with an interface and no files shows a blank window",
            )),
            Some((files, _bytes)) if files > MAX_UI_FILES => findings.push(Finding::fail(
                "ui",
                format!("the bundle holds {files} files, over the {MAX_UI_FILES}-file limit"),
                "bundle the interface, or remove what the build left behind",
            )),
            Some((_files, bytes)) if bytes > MAX_UI_BYTES => findings.push(Finding::fail(
                "ui",
                format!("the bundle is {bytes} bytes, over the {MAX_UI_BYTES}-byte limit"),
                "a bundle this large is shipping something it should be fetching",
            )),
            Some((files, bytes)) => {
                findings.push(Finding::pass("ui", format!("{files} files, {bytes} bytes")));
            }
        }
    }

    // ── The imports ───────────────────────────────────────────────────────────────────────────────
    if check_wasm {
        if target.wasm_imports.is_empty() {
            // Not a pass: the check did not run, and a pass it did not earn is worse than a warning. The kernel makes
            // the same check on the artifact it receives, so this is a gap in *this* tool rather than in the plugin.
            findings.push(Finding::warn(
                "imports",
                "the artifact's imports were not read, so they were not checked",
                "the kernel checks them at install time; this tool needs the Wasm module parsed to check them here",
            ));
        }
        else {
            let refused: Vec<&String> = target
                .wasm_imports
                .iter()
                .filter(|import| REFUSED_IMPORTS.iter().any(|rule| covers(rule, import)))
                .collect();
            let unknown: Vec<&String> = target
                .wasm_imports
                .iter()
                .filter(|import| {
                    !REFUSED_IMPORTS.iter().any(|rule| covers(rule, import))
                        && !PROVIDED_IMPORTS.iter().any(|rule| covers(rule, import))
                })
                .collect();

            if refused.is_empty() && unknown.is_empty() {
                findings.push(Finding::pass(
                    "imports",
                    format!("{} import(s), all provided", target.wasm_imports.len()),
                ));
            }
            for import in refused {
                findings.push(Finding::fail(
                    "imports",
                    format!("{import} is never provided, whatever the SDK version"),
                    "reach the same thing through a capability the manifest declares",
                ));
            }
            for import in unknown {
                findings.push(Finding::fail(
                    "imports",
                    format!("{import} is not one this SDK version provides"),
                    "rebuild against the SDK version the kernel ships, or raise `sdk.minimum`",
                ));
            }
        }
    }

    VerifyReport { plugin_id, version, findings }
}