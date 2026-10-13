//! `verify`: the four things that stop a plugin reaching a user broken.
//!
//! # Why verify exists at all
//!
//! Every check here is one the *kernel* also makes at install time. That is deliberate — a plugin that fails at
//! install has already been downloaded, and the failure lands on a user who cannot do anything about it. An author
//! running `verify` finds the same problems while they still have the source in front of them.
//!
//! The four, and what each is for:
//!
//! * **The manifest.** Parsed and validated against the schema at the level the kernel would use. A manifest that does
//!   not parse is a plugin that cannot install at all.
//! * **The artifact.** Present, non-empty, and within the size bound. An artifact of zero bytes is the failure a build
//!   script produces when it silently succeeded at nothing.
//! * **WIT compatibility.** The artifact's imports have to be ones this SDK version's host provides. A plugin built
//!   against a newer SDK imports a function the kernel does not have, and the failure is a trap at the first call
//!   rather than anything that names the version.
//! * **Refused imports.** A closed list of host functions that are never provided, whatever version: anything that
//!   would let a plugin reach the network, the filesystem or the process directly rather than through a gated call.
//!   A plugin importing one is refused rather than warned about, because there is no capability that makes it safe.
//!
//! # The report is a value
//!
//! As with the CLI's `doctor`: the findings are a list, so a test asserts them, a script reads them as JSON, and the
//! prose a person sees is one rendering of one report rather than a second implementation of it.
//!
//! # What it does not do
//!
//! No network, no registry, no keyring. `verify` reads what is on disk and says what it thinks; signing is a separate
//! command with a separate key.

use std::path::Path;

use serde::Serialize;

use synra_plugin_api::manifest::{Implementation, Manifest, ManifestContext, ValidationLevel};

/// The most bytes a Wasm artifact may be.
///
/// Sixteen mebibytes. A plugin that compiles to more than this is one whose time-to-first-call the user will feel, and
/// the bound is a build-time fact rather than a runtime one — so an author finds out from `verify` rather than from a
/// user's complaint.
pub const MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;

/// The most bytes a UI bundle may be.
///
/// Thirty-two mebibytes, which is the bound the UI artifact layer uses. Larger means the bundle is shipping something
/// it should be fetching, or a source map that belongs in a debug build.
pub const MAX_UI_BYTES: u64 = 32 * 1024 * 1024;

/// The most files a UI bundle may hold.
pub const MAX_UI_FILES: usize = 2_000;

/// Host functions the kernel never provides, whatever version.
///
/// # Why this is a closed list rather than a warning
///
/// Each of these would let a plugin reach something the kernel's capability system exists to gate. There is no
/// capability that makes `wasi:filesystem` safe for a plugin whose manifest says it needs none, and there is no
/// version in which importing `sockets` is correct. So a plugin importing one is refused, and the message names the
/// import rather than the rule.
pub const REFUSED_IMPORTS: &[&str] = &[
    "wasi:filesystem",
    "wasi:sockets",
    "wasi:cli",
    "wasi:http",
    "wasi:random",
    "wasi:threads",
    "synra:host/raw-socket",
    "synra:host/exec",
    "synra:host/env",
];

/// Host functions this SDK version provides.
///
/// # Why a list and not a version comparison
///
/// A plugin's imports are strings in a binary; the SDK version it was built against is a string in its manifest, and
/// the two are not connected by anything the kernel can check. So the check is against the *host's* surface: every
/// import the artifact names has to be one this build provides, which catches both a plugin built against an older SDK
/// that called something since removed and one built against a newer SDK that called something not yet added.
pub const PROVIDED_IMPORTS: &[&str] = &[
    "synra:host/log",
    "synra:host/storage",
    "synra:host/secrets",
    "synra:host/net",
    "synra:host/notify",
    "synra:host/clipboard",
    "synra:host/open",
    "synra:host/device",
    "synra:host/plugin",
    "synra:host/execute",
];

/// How a finding went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// It is fine.
    Pass,
    /// It will bite later.
    Warn,
    /// The plugin will not work.
    Fail,
}

impl Verdict {
    /// The word a person reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    /// Whether it stops the plugin working.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// A stable machine-readable name, such as `manifest`.
    pub name: String,
    /// How it went.
    pub verdict: Verdict,
    /// What was found, in a sentence.
    pub detail: String,
    /// What to do about it, when there is something to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl Finding {
    /// A passing check.
    #[must_use]
    pub fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            verdict: Verdict::Pass,
            detail: detail.into(),
            suggestion: None,
        }
    }

    /// A check that will bite later.
    #[must_use]
    pub fn warn(name: &str, detail: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            verdict: Verdict::Warn,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// A check that found something broken.
    #[must_use]
    pub fn fail(name: &str, detail: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            verdict: Verdict::Fail,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }
}

/// Everything `verify` concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    /// The plugin, when the manifest parsed far enough to say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    /// The version, likewise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Every finding, in the order the checks ran.
    pub findings: Vec<Finding>,
}

impl VerifyReport {
    /// How many findings reported a failure.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.findings.iter().filter(|finding| finding.verdict.is_failure()).count()
    }

    /// How many reported something that will bite later.
    #[must_use]
    pub fn warnings(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.verdict == Verdict::Warn)
            .count()
    }

    /// Whether the plugin will work.
    ///
    /// Failures only. A warning is something that will bite later, and a plugin that warns still installs.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures() == 0
    }

    /// What the process should exit with.
    ///
    /// `0` when nothing failed, `1` when something did, so a build script branches on it. It is a judgement rather
    /// than a formality: a `verify` that always exited zero would be a check CI could not use.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.is_ok() { 0 } else { 1 }
    }

    /// The lines a person reads.
    ///
    /// Returned rather than printed, so a test asserts the text and the caller decides where it goes.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match (&self.plugin_id, &self.version) {
            (Some(id), Some(version)) => lines.push(format!("{id} {version}")),
            _ => lines.push("the manifest could not be read".to_owned()),
        }

        for finding in &self.findings {
            lines.push(format!(
                "{:<4}  {:<22} {}",
                finding.verdict.as_str(),
                finding.name,
                finding.detail
            ));
            if let Some(suggestion) = &finding.suggestion {
                lines.push(format!("      {:<22} {suggestion}", ""));
            }
        }

        let passed = self.findings.len() - self.failures() - self.warnings();
        lines.push(format!(
            "{passed} ok, {} warn, {} fail",
            self.warnings(),
            self.failures()
        ));
        lines
    }
}

/// What is on disk, as far as `verify` can tell.
///
/// A struct rather than a set of arguments, because the artifact's *kind* decides which checks apply: a UI bundle has
/// a file count and a Wasm artifact has imports, and running both sets against both would report findings about a file
/// that cannot exist.
#[derive(Debug, Clone)]
pub struct Target {
    /// The manifest, as text.
    pub manifest_json: Option<String>,
    /// The Wasm artifact, when there is one.
    pub wasm_bytes: Option<u64>,
    /// The imports the Wasm artifact names.
    pub wasm_imports: Vec<String>,
    /// The UI bundle, as `(file count, total bytes)`.
    pub ui_bundle: Option<(usize, u64)>,
}

impl Target {
    /// What `verify` found on disk, reading the paths a built plugin has.
    ///
    /// # Errors
    ///
    /// Never — a missing file is a finding rather than an error, because "there is no manifest here" is exactly the
    /// answer the author needs.
    #[must_use]
    pub fn read(directory: &Path) -> Self {
        let manifest_json = std::fs::read_to_string(directory.join("manifest.json")).ok();

        let wasm = directory.join("plugin.wasm");
        let wasm_bytes = std::fs::metadata(&wasm).ok().map(|meta| meta.len());
        // The imports are *not* read from the binary here: parsing a Wasm module needs a parser, and this crate's job
        // is the report. A caller that has one fills the field in; a caller that does not gets a warning that the
        // check could not run, which is honest rather than a pass it did not earn.
        let wasm_imports = Vec::new();

        let ui = read_bundle(&directory.join("ui"));

        Self { manifest_json, wasm_bytes, wasm_imports, ui_bundle: ui }
    }
}

/// Counts a UI bundle's files and bytes.
///
/// `None` when the directory does not exist, which is not a failure on its own: a headless plugin has no bundle.
fn read_bundle(directory: &Path) -> Option<(usize, u64)> {
    if !directory.is_dir() {
        return None;
    }
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(entry.path());
            }
            else if kind.is_file() {
                files = files.saturating_add(1);
                if let Ok(meta) = entry.metadata() {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }
    Some((files, bytes))
}

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
fn covers(rule: &str, import: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest for a headless plugin.
    const HEADLESS: &str = r#"{
      "id": "@synra-plugin/example",
      "version": "1.0.0",
      "title": "Example",
      "publisher": { "id": "synra-official" },
      "sdk": { "min": "0.1.0" },
      "wit": "synra:plugin@1.0.0",
      "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
      "capabilities": []
    }"#;

    /// A manifest for a UI plugin.
    const UI: &str = r#"{
      "id": "@synra-plugin/example",
      "version": "1.0.0",
      "title": "Example",
      "publisher": { "id": "synra-official" },
      "sdk": { "min": "0.1.0" },
      "wit": "synra:plugin@1.0.0",
      "runtime": { "ui": { "artifact": "ui", "entry": "index.html" } },
      "capabilities": []
    }"#;

    fn target(manifest: &str) -> Target {
        Target {
            manifest_json: Some(manifest.to_owned()),
            wasm_bytes: None,
            wasm_imports: Vec::new(),
            ui_bundle: None,
        }
    }

    fn headless_ok() -> Target {
        Target { wasm_bytes: Some(1_024), ..target(HEADLESS) }
    }

    // ── The manifest ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_missing_manifest_is_the_first_finding() {
        // The answer an author needs when they ran the command from the wrong directory.
        let report = verify(&Target {
            manifest_json: None,
            wasm_bytes: None,
            wasm_imports: Vec::new(),
            ui_bundle: None,
        });
        assert!(!report.is_ok());
        assert_eq!(report.findings[0].name, "manifest");
        assert_eq!(report.findings[0].verdict, Verdict::Fail);
        assert!(report.plugin_id.is_none());
    }

    #[test]
    fn a_manifest_that_does_not_parse_names_the_problem() {
        let report = verify(&target("{ not json"));
        assert!(!report.is_ok());
        assert!(report.findings[0].detail.contains("does not parse"), "{:?}", report.findings[0]);
    }

    #[test]
    fn a_valid_manifest_passes_and_names_the_plugin() {
        let report = verify(&headless_ok());
        assert_eq!(report.plugin_id.as_deref(), Some("@synra-plugin/example"));
        assert_eq!(report.version.as_deref(), Some("1.0.0"));
        assert!(report.findings.iter().any(|f| f.name == "manifest" && f.verdict == Verdict::Pass));
    }

    // ── The artifact ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_manifest_naming_a_wasm_entry_point_with_no_artifact_fails() {
        // The failure a build script produces when it silently succeeded at nothing.
        let report = verify(&target(HEADLESS));
        assert!(!report.is_ok());
        let wasm = report.findings.iter().find(|f| f.name == "wasm").expect("a wasm finding");
        assert_eq!(wasm.verdict, Verdict::Fail);
        assert!(wasm.suggestion.as_deref().is_some_and(|s| s.contains("build")));
    }

    #[test]
    fn an_empty_artifact_fails_rather_than_passing_on_existence() {
        // Zero bytes is not "small", it is "the build produced nothing" — and a check that only asked whether the file
        // exists would pass it.
        let report = verify(&Target { wasm_bytes: Some(0), ..target(HEADLESS) });
        assert!(!report.is_ok());
        let wasm = report.findings.iter().find(|f| f.name == "wasm").expect("a finding");
        assert!(wasm.detail.contains("empty"), "{}", wasm.detail);
    }

    #[test]
    fn an_oversized_artifact_fails_with_both_numbers() {
        // The bound and the measured size, so the author knows how far over they are.
        let report = verify(&Target { wasm_bytes: Some(MAX_WASM_BYTES + 1), ..target(HEADLESS) });
        assert!(!report.is_ok());
        let wasm = report.findings.iter().find(|f| f.name == "wasm").expect("a finding");
        assert!(wasm.detail.contains(&(MAX_WASM_BYTES + 1).to_string()), "{}", wasm.detail);
        assert!(wasm.detail.contains(&MAX_WASM_BYTES.to_string()), "{}", wasm.detail);
    }

    #[test]
    fn a_large_but_legal_artifact_warns() {
        // Inside the bound and worth saying: a plugin's size is what the user pays on every install.
        let report = verify(&Target { wasm_bytes: Some(MAX_WASM_BYTES / 2 + 1), ..target(HEADLESS) });
        assert!(report.is_ok(), "a warning is not a failure");
        // Two: the size, and the imports this tool could not read. The assertion names which, rather than counting —
        // a count would break the moment a different warning was added for a good reason.
        assert!(
            report.findings.iter().any(|f| f.name == "wasm-size" && f.verdict == Verdict::Warn),
            "{:?}",
            report.findings
        );
        assert!(report.warnings() >= 1);
    }

    #[test]
    fn a_ui_plugin_with_no_bundle_fails() {
        let report = verify(&target(UI));
        assert!(!report.is_ok());
        assert!(report.findings.iter().any(|f| f.name == "ui" && f.verdict == Verdict::Fail));
    }

    #[test]
    fn an_empty_ui_bundle_fails_rather_than_passing_on_the_directory_existing() {
        let report = verify(&Target { ui_bundle: Some((0, 0)), ..target(UI) });
        assert!(!report.is_ok());
        let ui = report.findings.iter().find(|f| f.name == "ui").expect("a finding");
        assert!(ui.detail.contains("empty"), "{}", ui.detail);
    }

    #[test]
    fn a_ui_bundle_over_the_file_count_fails() {
        let report = verify(&Target { ui_bundle: Some((MAX_UI_FILES + 1, 10)), ..target(UI) });
        assert!(!report.is_ok());
        let ui = report.findings.iter().find(|f| f.name == "ui").expect("a finding");
        assert!(ui.detail.contains("files"), "{}", ui.detail);
    }

    #[test]
    fn a_headless_plugin_is_not_asked_for_an_interface() {
        // The kind decides which checks apply. Running both sets against both would report a finding about a file that
        // cannot exist, and an author would go looking for it.
        let report = verify(&headless_ok());
        assert!(!report.findings.iter().any(|f| f.name == "ui"), "{:?}", report.findings);
        assert!(report.is_ok(), "{:?}", report.findings);
    }

    #[test]
    fn a_ui_plugin_is_not_asked_for_wasm() {
        let report = verify(&Target { ui_bundle: Some((3, 100)), ..target(UI) });
        assert!(!report.findings.iter().any(|f| f.name == "wasm"), "{:?}", report.findings);
        assert!(report.is_ok(), "{:?}", report.findings);
    }

    // ── The imports ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_unread_artifact_is_a_warning_rather_than_a_pass() {
        // ★ A pass it did not earn is worse than a warning: an author would publish believing the imports were fine.
        let report = verify(&headless_ok());
        let imports = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
        assert_eq!(imports.verdict, Verdict::Warn);
        assert!(report.is_ok(), "a warning is not a failure");
    }

    #[test]
    fn every_provided_import_passes() {
        let report = verify(&Target {
            wasm_imports: PROVIDED_IMPORTS.iter().map(|s| (*s).to_owned()).collect(),
            ..headless_ok()
        });
        let imports = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
        assert_eq!(imports.verdict, Verdict::Pass, "{}", imports.detail);
    }

    #[test]
    fn a_refused_import_fails_and_names_the_import() {
        // ★ The list that exists because no capability makes these safe. A plugin importing `wasi:filesystem` is one
        // that would read anything on the machine.
        for refused in REFUSED_IMPORTS {
            let report = verify(&Target {
                wasm_imports: vec![(*refused).to_owned()],
                ..headless_ok()
            });
            assert!(!report.is_ok(), "{refused} was accepted");
            let finding = report
                .findings
                .iter()
                .find(|f| f.name == "imports" && f.verdict == Verdict::Fail)
                .unwrap_or_else(|| panic!("{refused}: no finding"));
            assert!(finding.detail.contains(refused), "{}", finding.detail);
        }
    }

    #[test]
    fn an_import_this_sdk_does_not_provide_fails() {
        // The failure that otherwise appears as a trap at the first call, naming nothing.
        let report = verify(&Target {
            wasm_imports: vec!["synra:host/teleport".to_owned()],
            ..headless_ok()
        });
        assert!(!report.is_ok());
        let finding = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
        assert!(finding.detail.contains("teleport"), "{}", finding.detail);
        assert!(
            finding.suggestion.as_deref().is_some_and(|s| s.contains("SDK")),
            "{finding:?}"
        );
    }

    #[test]
    fn a_prefix_of_a_provided_import_is_not_treated_as_refusing_it() {
        // ★ The bug a `starts_with` comparison produced. `synra:host/exec` is refused and `synra:host/execute` is
        // provided, and one is a string prefix of the other — so a plugin importing the *provided* function was
        // refused for importing the forbidden one. A user would have read "exec is never provided" about a line they
        // never wrote.
        let report = verify(&Target {
            wasm_imports: vec!["synra:host/execute".to_owned()],
            ..headless_ok()
        });
        let imports = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
        assert_eq!(imports.verdict, Verdict::Pass, "{}", imports.detail);
    }

    #[test]
    fn a_rule_covers_a_namespace_but_not_a_longer_name() {
        // The rule itself, asserted directly: an import is a namespace and an item, so a rule matches the whole import
        // or the namespace it belongs to — and `wasi:filesystemx` is a different namespace.
        assert!(covers("wasi:filesystem", "wasi:filesystem"));
        assert!(covers("wasi:filesystem", "wasi:filesystem/types"));
        assert!(covers("wasi:filesystem", "wasi:filesystem/preopens"));
        assert!(!covers("wasi:filesystem", "wasi:filesystemx"));
        assert!(!covers("synra:host/exec", "synra:host/execute"));
        assert!(covers("synra:host/exec", "synra:host/exec"));
    }

    #[test]
    fn every_refused_import_is_also_absent_from_the_provided_list() {
        // A function on both lists would be one this tool refuses and the kernel provides, which is a rule nobody
        // could satisfy.
        for refused in REFUSED_IMPORTS {
            assert!(
                !PROVIDED_IMPORTS.iter().any(|provided| provided == refused),
                "{refused} is on both lists"
            );
        }
    }

    // ── The report ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_warning_does_not_make_the_report_fail() {
        // A plugin that warns still installs. Treating it as unhealthy would make `verify` refuse a plugin that works,
        // and an author would learn to ignore the command.
        let report = verify(&headless_ok());
        assert!(report.warnings() > 0, "the unread-imports warning is missing");
        assert!(report.is_ok());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_failure_is_an_exit_code_a_build_script_can_branch_on() {
        assert_eq!(verify(&target(HEADLESS)).exit_code(), 1);
        assert_eq!(verify(&headless_ok()).exit_code(), 0);
    }

    #[test]
    fn the_lines_lead_with_the_plugin_and_end_with_a_tally() {
        let lines = verify(&headless_ok()).lines();
        assert!(lines[0].contains("@synra-plugin/example"), "{:?}", lines[0]);
        assert!(lines[0].contains("1.0.0"), "{:?}", lines[0]);
        let last = lines.last().expect("a line");
        assert!(last.contains(" ok"), "{last}");
        assert!(last.contains("warn"), "{last}");
        assert!(last.contains("fail"), "{last}");
    }

    #[test]
    fn a_suggestion_gets_its_own_line() {
        // The half that tells an author what to do, and a long detail plus a long suggestion on one line is a line
        // nobody reads to the end.
        let report = verify(&target(HEADLESS));
        let lines = report.lines();
        assert!(
            lines.iter().any(|line| line.starts_with("      ") && line.contains("build")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_report_serialises_for_a_script() {
        let report = verify(&headless_ok());
        let json = serde_json::to_value(&report).expect("serialises");
        assert_eq!(json["pluginId"], "@synra-plugin/example");
        assert!(json["findings"].as_array().is_some_and(|f| !f.is_empty()));
        assert_eq!(json["findings"][0]["verdict"], "pass");
    }

    #[test]
    fn the_verdicts_have_words_a_person_reads() {
        assert_eq!(Verdict::Pass.as_str(), "ok");
        assert_eq!(Verdict::Warn.as_str(), "warn");
        assert_eq!(Verdict::Fail.as_str(), "fail");
        assert!(Verdict::Fail.is_failure());
        assert!(!Verdict::Warn.is_failure());
    }

    #[test]
    fn the_bounds_are_the_ones_the_artifact_layer_uses() {
        // Asserted so a change here and not there is a failure rather than two bounds that disagree about the same
        // plugin, one of which the kernel enforces.
        assert_eq!(MAX_UI_BYTES, 32 * 1024 * 1024);
        assert_eq!(MAX_UI_FILES, 2_000);
        // Through a binding, so the comparison is not a constant expression the compiler folds away — and because the
        // relationship is the point: a Wasm bound above the bundle bound would let a plugin the kernel refuses to load
        // pass `verify`.
        let (wasm, ui) = (MAX_WASM_BYTES, MAX_UI_BYTES);
        assert!(wasm > 0 && wasm < ui, "wasm {wasm}, ui {ui}");
    }
}
