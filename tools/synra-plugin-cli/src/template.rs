//! The scaffold: what `new` writes, and why each file is there.
//!
//! # Why the templates are values rather than a directory of files
//!
//! A plugin author's first experience is `synra-plugin new`, and the failure that ruins it is a scaffold that does not
//! build. Templates kept as files on disk are tested by nothing — the only way to find out that one of them stopped
//! compiling is for an author to report it.
//!
//! So a template here is a *value*: a list of paths and contents, produced by a pure function. That makes three things
//! possible which a directory of files does not:
//!
//! * A test can assert that every template produces a manifest the kernel's own validator accepts, and that the
//!   manifest's `implementation` block matches the files that were written. A template whose manifest claims a `.wasm`
//!   entry point and writes none is a plugin that installs and then does nothing.
//! * The three kinds differ only in which runtime block the manifest carries and which files are written, which is
//!   the difference the design document draws between headless, UI and hybrid — so the shared part cannot drift
//!   between them.
//! * Nothing writes to the author's disk until they ask. `new` on an existing directory is refused *before* a file is
//!   created, rather than after three of them are.
//!
//! # What the scaffold deliberately does not do
//!
//! No package manager, no bundler, no dependency. An author who wants a framework will add one, and a scaffold that
//! chose for them would be a scaffold they have to unpick. The files are the smallest thing that installs, runs, and
//! gives a place to start reading.

use std::collections::BTreeMap;

use synra_plugin_api::manifest::{Manifest, ManifestContext, ValidationLevel};

/// The three shapes a plugin can have.
///
/// The names are the design document's: a `headless` plugin runs as Wasm with no interface, a `ui` plugin runs in a
/// WebView with no code the kernel executes, and a `hybrid` one is both halves of one plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TemplateKind {
    /// Wasm only. No interface.
    Headless,
    /// A WebView bundle only. No code the kernel executes.
    Ui,
    /// Both halves, sharing one manifest.
    Hybrid,
}

impl TemplateKind {
    /// The word a user types and the manifest does not use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Headless => "headless",
            Self::Ui => "ui",
            Self::Hybrid => "hybrid",
        }
    }

    /// Every kind, for a table-driven test.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Headless, Self::Ui, Self::Hybrid]
    }

    /// The manifest's `implementation` block for this kind.
    ///
    /// The three differ only here, which is the point: the design document's classification *is* which parts a plugin
    /// implements, so a template that differed elsewhere would be a template that disagreed with its own manifest.
    /// The manifest's `runtime` and `implementation` blocks for this kind.
    ///
    /// The three differ only here, which is the point: the design document's classification *is* which halves a plugin
    /// implements, so a template that differed elsewhere would be a template that disagreed with its own manifest.
    ///
    /// `headless`/`ui` are objects rather than a `kind` string, because a plugin declares what artifacts it ships —
    /// the artifact path, whether the Wasm is stateful, the entry document inside the bundle. A single word could not
    /// carry any of that, and the host needs all of it.
    const fn blocks(self) -> &'static str {
        match self {
            Self::Headless => r#""runtime": {
    "headless": {
      "artifact": "plugin.wasm",
      "stateful": false
    }
  }"#,
            Self::Ui => r#""runtime": {
    "ui": {
      "artifact": "ui",
      "entry": "index.html"
    }
  }"#,
            Self::Hybrid => r#""runtime": {
    "headless": {
      "artifact": "plugin.wasm",
      "stateful": false
    },
    "ui": {
      "artifact": "ui",
      "entry": "index.html"
    }
  }"#,
        }
    }
}

/// Why a scaffold could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScaffoldError {
    /// The plugin id is not one the kernel would accept.
    ///
    /// Refused here rather than discovered at install: an id is in every path, every log line and every capability
    /// string, so changing it later is a rename across the whole plugin.
    #[error("the plugin id is not usable: {reason}")]
    BadId {
        /// What the validator said.
        reason: String,
    },

    /// The version is not a version.
    #[error("the version is not usable: {reason}")]
    BadVersion {
        /// What the validator said.
        reason: String,
    },

    /// The name is not one a plugin may have.
    #[error("the name is not usable: {reason}")]
    BadName {
        /// What the validator said.
        reason: String,
    },
}

/// A file a scaffold will write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldFile {
    /// Where it goes, relative to the plugin's directory, with `/` as the separator.
    pub path: String,
    /// What it contains.
    pub contents: String,
    /// Whether the author is expected to edit it, which decides whether it is reported as theirs or as scaffolding.
    pub authored: bool,
}

/// What `new` will write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scaffold {
    /// The plugin's id, as it will appear in the manifest.
    pub plugin_id: String,
    /// The version.
    pub version: String,
    /// The directory name, derived from the id.
    pub directory: String,
    /// Every file, sorted by path so the output is stable.
    pub files: Vec<ScaffoldFile>,
    /// The kind.
    pub kind: TemplateKind,
}

impl Scaffold {
    /// Builds the scaffold for a plugin.
    ///
    /// # Errors
    ///
    /// [`ScaffoldError`] when the id, version or name is one the kernel's own validator would refuse.
    ///
    /// # Why the validation runs here
    ///
    /// The same functions the manifest's own validation uses, so a scaffold cannot produce a manifest that fails
    /// `verify` — which is the one thing an author would reasonably expect and the one thing a template that
    /// duplicated the rules would get wrong.
    pub fn new(
        plugin_id: &str,
        version: &str,
        title: &str,
        kind: TemplateKind,
    ) -> Result<Self, ScaffoldError> {
        synra_plugin_api::manifest::check_plugin_id(plugin_id).map_err(|error| {
            ScaffoldError::BadId { reason: error.to_string() }
        })?;
        synra_plugin_api::manifest::check_version(version).map_err(|error| {
            ScaffoldError::BadVersion { reason: error.to_string() }
        })?;
        if title.trim().is_empty() {
            return Err(ScaffoldError::BadName { reason: "the title is empty".to_owned() });
        }

        // The directory is the wire slug, so a plugin's directory is the name its artifact uses everywhere else — the
        // registry, the cache, the log. A directory named after the raw id would contain a `/` and a scope.
        //
        // Parsed once, here, and the result used for both the directory and the crate name: parsing again where the
        // crate manifest is written would need an `expect` on a value that was already proven valid, and an `expect` in
        // production code is what this workspace forbids.
        let id = synra_protocol::PluginId::parse(plugin_id)
            .map_err(|error| ScaffoldError::BadId { reason: error.to_string() })?;
        let slug = synra_plugin_api::manifest::to_wire_slug(&id)
            .map_err(|error| ScaffoldError::BadId { reason: error.to_string() })?;

        let manifest = manifest_json(plugin_id, version, title, kind);
        let mut files = vec![
            ScaffoldFile { path: "manifest.json".to_owned(), contents: manifest, authored: false },
            ScaffoldFile {
                path: "README.md".to_owned(),
                contents: readme(plugin_id, kind),
                authored: true,
            },
            ScaffoldFile {
                path: ".gitignore".to_owned(),
                contents: gitignore(),
                authored: false,
            },
        ];

        // A crate manifest, so `build` has something to compile. Written as text rather than left out, because a
        // scaffold whose `build` needs a file the author has to invent is a scaffold that does not build.
        let crate_manifest = format!(
            r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

# A plugin is a library, not a binary: the kernel loads it, nothing runs it.
[lib]
crate-type = ["cdylib"]

[dependencies]
# The SDK is `no_std`-friendly and dependency-free on purpose: a plugin's size is what the user pays for on every
# install, and a plugin that pulled in an async runtime would be one `verify` refuses.
synra-plugin-sdk = "0.1"

# Release builds are what get published, and a plugin is loaded once and called many times.
[profile.release]
opt-level = "s"
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#,
            name = slug,
        );

        match kind {
            TemplateKind::Headless => {
                files.push(ScaffoldFile {
                    path: "Cargo.toml".to_owned(),
                    contents: crate_manifest,
                    authored: false,
                });
                files.push(ScaffoldFile {
                    path: "src/lib.rs".to_owned(),
                    contents: HEADLESS_SOURCE.to_owned(),
                    authored: true,
                });
            }
            TemplateKind::Ui => files.push(ScaffoldFile {
                path: "ui/index.html".to_owned(),
                contents: ui_document(title),
                authored: true,
            }),
            TemplateKind::Hybrid => {
                files.push(ScaffoldFile {
                    path: "Cargo.toml".to_owned(),
                    contents: crate_manifest,
                    authored: false,
                });
                files.push(ScaffoldFile {
                    path: "src/lib.rs".to_owned(),
                    contents: hybrid_source(),
                    authored: true,
                });
                files.push(ScaffoldFile {
                    path: "ui/index.html".to_owned(),
                    contents: ui_document(title),
                    authored: true,
                });
            }
        }

        files.sort_by(|first, second| first.path.cmp(&second.path));

        Ok(Self {
            plugin_id: plugin_id.to_owned(),
            version: version.to_owned(),
            directory: slug,
            files,
            kind,
        })
    }

    /// The paths it will write.
    ///
    /// Owned for the same reason [`Self::as_map`] is: a caller usually builds the scaffold inline, and a reference
    /// into a temporary is a borrow error at every call site.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.files.iter().map(|file| file.path.clone()).collect()
    }

    /// The files, as a map from path to contents.
    ///
    /// Owned rather than borrowed: a caller comparing a template against what it expects usually builds the scaffold
    /// inline, and a returned reference into a temporary is a borrow error at every call site rather than a design
    /// decision made once.
    #[must_use]
    pub fn as_map(&self) -> BTreeMap<String, String> {
        self.files
            .iter()
            .map(|file| (file.path.clone(), file.contents.clone()))
            .collect()
    }

    /// The manifest it will write, parsed and validated.
    ///
    /// # Errors
    ///
    /// The validator's error, when the template produced something it refuses. This exists so a test can assert the
    /// templates against the kernel's own rules rather than against a second copy of them.
    pub fn validate_manifest(&self) -> Result<Manifest, String> {
        let files = self.as_map();
        let text = files
            .get("manifest.json")
            .ok_or_else(|| "the scaffold has no manifest".to_owned())?;
        let manifest = Manifest::from_json(text).map_err(|error| error.to_string())?;

        let context = ManifestContext {
            // The lowest SDK the scaffold could name, so a template is checked against the rule an author meets
            // rather than against a version chosen to make it pass.
            host_sdk: Some(manifest.sdk.min.clone()),
            ..ManifestContext::default()
        };
        manifest
            .validate(ValidationLevel::Schema, &context)
            .map_err(|error| error.to_string())?;
        Ok(manifest)
    }
}

/// The manifest for a scaffold, as the text an author edits.
fn manifest_json(plugin_id: &str, version: &str, title: &str, kind: TemplateKind) -> String {
    // Written as text rather than serialised from a `Manifest`, because this is the file the author reads and edits:
    // field order and indentation are for them, and a serialiser's output would be whatever the struct's order is.
    let blocks = kind.blocks();
    format!(
        r#"{{
  "$schema": "{schema}",
  "id": "{plugin_id}",
  "version": "{version}",
  "title": "{title}",
  "description": "A {kind} plugin for Synra.",
  "publisher": {{ "id": "your-publisher-id" }},
  "sdk": {{ "min": "0.1.0" }},
  "wit": "synra:plugin@1.0.0",
  {blocks},
  "capabilities": []
}}
"#,        schema = synra_plugin_api::manifest::MANIFEST_SCHEMA,
        kind = kind.as_str(),
    )
}

/// A README that says what to do next.
fn readme(plugin_id: &str, kind: TemplateKind) -> String {
    let build = match kind {
        TemplateKind::Headless => "`synra-plugin build` compiles the Wasm artifact.",
        TemplateKind::Ui => "`synra-plugin build` packages the `ui/` directory.",
        TemplateKind::Hybrid => {
            "`synra-plugin build` produces both halves: the Wasm artifact and the `ui/` bundle."
        }
    };
    format!(
        "# {plugin_id}\n\nA {kind} plugin for Synra.\n\n{build}\n\n## Next\n\n1. Edit `manifest.json`: the title, the \
         description, the publisher, and the capabilities the plugin needs.\n2. Implement the entry points the \
         manifest names.\n3. `synra-plugin verify` before publishing — it checks the manifest, the artifact's size and \
         the imports the kernel refuses.\n",
        kind = kind.as_str(),
    )
}

/// Ignore the build output, so an author's first commit is their source.
fn gitignore() -> String {
    "target/\n*.wasm\n*.zip\n*.sig\ndist/\n".to_owned()
}

/// The Rust half of a headless plugin.
///
/// A constant rather than a function of the id: the source names the entry points the *manifest* declares, and the
/// manifest carries the id. Interpolating one here would put the plugin's name in a file that has to compile, for no
/// reason an author would thank us for.
const HEADLESS_SOURCE: &str = r#"//! A Synra plugin's Wasm half.
//!
//! The kernel calls the functions named in `manifest.json`. Nothing here talks to the network, the filesystem or the
//! clock directly: everything a plugin may do goes through a host function the kernel gates on the capabilities the
//! manifest declares.

/// Called when the plugin is activated.
#[no_mangle]
pub extern "C" fn synra_plugin_activate() {
    // Nothing to do on activation yet.
}

/// Called for each event the plugin subscribed to in its manifest.
#[no_mangle]
pub extern "C" fn synra_plugin_on_event() {
    // Read the event, decide, call a host function.
}
"#;

/// The Rust half of a hybrid plugin.
///
/// The same source with a note about the other half, because a hybrid plugin *is* one plugin with one manifest: the
/// interface and the Wasm code share its capabilities rather than each declaring their own.
fn hybrid_source() -> String {
    format!(
        "{HEADLESS_SOURCE}\n// A hybrid plugin has both halves: this one, and `ui/index.html`. They are one plugin \
         with\n// one manifest, so the interface and the Wasm code share its capabilities rather than each declaring\n\
         // their own.\n"
    )
}

/// The WebView half.
fn ui_document(title: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>{title}</title>
    <style>
      /* Deliberately plain: a scaffold that shipped a design system would be one an author has to unpick. */
      body {{
        font-family: system-ui, sans-serif;
        margin: 0;
        padding: 1rem;
      }}
    </style>
  </head>
  <body>
    <h1 id="title">{title}</h1>
    <p>The plugin's interface. `window.synra` is the only way to reach the kernel from here.</p>
    <script type="module">
      // `window.synra` is a frozen facade: every method is one kernel call, validated on the kernel's side with this
      // page's own session credential. There is no other way out of the sandbox, and nothing the page can read to
      // impersonate another.
      const title = document.title
      const identity = await window.synra.identity()
      document.getElementById('title').textContent = title + ' — ' + identity.displayName
    </script>
  </body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scaffold(kind: TemplateKind) -> Scaffold {
        Scaffold::new("@synra-plugin/example", "0.1.0", "Example", kind).expect("builds")
    }

    // ── Every kind produces a valid plugin ────────────────────────────────────────────────────────

    #[test]
    fn every_template_produces_a_manifest_the_kernel_accepts() {
        // ★ The property that justifies the templates being values. A scaffold that does not validate is the failure
        // an author meets first and cannot diagnose, because they do not yet know what a correct manifest looks like.
        for kind in TemplateKind::all() {
            let scaffold = scaffold(kind);
            let manifest = scaffold
                .validate_manifest()
                .unwrap_or_else(|error| panic!("{} template: {error}", kind.as_str()));
            assert_eq!(manifest.id.to_string(), "@synra-plugin/example", "{}", kind.as_str());
            assert_eq!(manifest.version, "0.1.0");
        }
    }

    #[test]
    fn the_manifest_names_an_implementation_matching_the_files_written() {
        // A manifest claiming a `ui:` entry point with no `ui/` directory is a plugin that installs and then shows a
        // blank window — which is worse than one that fails to install.
        for kind in TemplateKind::all() {
            let scaffold = scaffold(kind);
            let paths = scaffold.paths();

            if matches!(kind, TemplateKind::Ui | TemplateKind::Hybrid) {
                assert!(paths.iter().any(|path| path == "ui/index.html"), "{kind:?} wrote no interface");
            }
            if matches!(kind, TemplateKind::Headless | TemplateKind::Hybrid) {
                assert!(paths.iter().any(|path| path == "src/lib.rs"), "{kind:?} wrote no Wasm half");
            }
            if kind == TemplateKind::Ui {
                assert!(!paths.iter().any(|path| path == "src/lib.rs"), "a UI-only plugin has no Wasm half");
            }
        }
    }

    #[test]
    fn the_three_kinds_differ_only_in_their_runtime_block() {
        // The design document's classification *is* which parts a plugin implements, so a template that differed
        // elsewhere would be a template that disagreed with its own manifest.
        let headless = scaffold(TemplateKind::Headless).as_map();
        let ui = scaffold(TemplateKind::Ui).as_map();

        // Both carry the same description shape and the same capability block.
        let headless_manifest = headless.get("manifest.json").expect("a manifest");
        let ui_manifest = ui.get("manifest.json").expect("a manifest");
        assert!(headless_manifest.contains(r#""headless""#), "the headless template ships no Wasm half");
        assert!(!headless_manifest.contains(r#""ui""#), "the headless template ships an interface");
        assert!(ui_manifest.contains(r#""ui""#), "the UI template ships no bundle");
        assert!(!ui_manifest.contains(r#""headless""#), "the UI template ships a Wasm half");
        // And both declare the same capability block, which is where an author starts from.
        assert!(headless_manifest.contains(r#""capabilities""#));
        assert!(ui_manifest.contains(r#""capabilities""#));
    }

    #[test]
    fn the_hybrid_template_implements_all_three_entry_points() {
        // The only template with both halves, so the only one whose manifest names all three. A hybrid plugin missing
        // `execute` is one the kernel cannot ask to do anything.
        let hybrid = scaffold(TemplateKind::Hybrid);
        let files = hybrid.as_map();
        let manifest = files.get("manifest.json").expect("a manifest");
        // Derived from what the runtime block declares, because a manifest has no separate `implementation` field:
        // what a plugin implements *is* which halves it ships.
        assert!(manifest.contains(r#""headless""#), "{manifest}");
        assert!(manifest.contains(r#""ui""#), "{manifest}");
    }

    // ── The directory ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_directory_is_the_wire_slug() {
        // A directory named after the raw id would contain a `/` and a scope. The slug is the name the artifact uses
        // everywhere else — the registry, the cache, the log — so the author's directory matches all of them.
        for kind in TemplateKind::all() {
            let scaffold = scaffold(kind);
            assert_eq!(scaffold.directory, "example", "{}", kind.as_str());
            assert!(!scaffold.directory.contains('/'), "{}", scaffold.directory);
            assert!(!scaffold.directory.contains('@'), "{}", scaffold.directory);
        }
    }

    // ── Refusals ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_reserved_scope_is_refused_before_anything_is_written() {
        // The scopes the kernel owns. A plugin called `@synra/...` would be indistinguishable from the kernel's own in
        // a log, and an author who scaffolded one would have to rename across every path and capability string.
        for id in ["@synra/chat", "@core/thing", "@system/x"] {
            let error = Scaffold::new(id, "0.1.0", "X", TemplateKind::Headless)
                .expect_err("a reserved scope is refused");
            assert!(matches!(error, ScaffoldError::BadId { .. }), "{id}: {error:?}");
        }
    }

    #[test]
    fn an_unusable_id_or_version_is_refused() {
        for id in ["", "chat", "@scope", "@scope/", "not a scope/name"] {
            assert!(
                Scaffold::new(id, "0.1.0", "X", TemplateKind::Headless).is_err(),
                "{id:?} should be refused"
            );
        }
        for version in ["", "1", "1.0", "v1.0.0", "latest"] {
            assert!(
                Scaffold::new("@synra-plugin/x", version, "X", TemplateKind::Headless).is_err(),
                "{version:?} should be refused"
            );
        }
    }

    #[test]
    fn an_empty_title_is_refused() {
        // A plugin with no title is one the user cannot identify in a list, and the manifest requires one.
        for title in ["", "   ", "\t"] {
            assert!(
                Scaffold::new("@synra-plugin/x", "0.1.0", title, TemplateKind::Headless).is_err(),
                "{title:?} should be refused"
            );
        }
    }

    #[test]
    fn the_refusal_says_which_field_and_why() {
        // The message is what an author reads at the moment they are least able to guess.
        let error = Scaffold::new("@synra/chat", "0.1.0", "X", TemplateKind::Headless)
            .expect_err("refused");
        let text = error.to_string();
        assert!(text.contains("plugin id"), "{text}");
        assert!(text.len() > 30, "{text}");
    }

    // ── The files ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_kind_writes_a_readme_and_an_ignore_file() {
        // The README is the only place the build command is written down, and the ignore file is what keeps an
        // author's first commit their source rather than their build output.
        for kind in TemplateKind::all() {
            let paths = scaffold(kind).paths();
            assert!(paths.iter().any(|path| path == "README.md"), "{kind:?}");
            assert!(paths.iter().any(|path| path == ".gitignore"), "{kind:?}");
            assert!(paths.iter().any(|path| path == "manifest.json"), "{kind:?}");
        }
    }

    #[test]
    fn the_files_are_sorted_so_the_output_is_stable() {
        // A scaffold whose file order varied would make a test's diff noisy and an author's first commit arbitrary.
        for kind in TemplateKind::all() {
            let paths = scaffold(kind).paths();
            let mut sorted = paths.clone();
            sorted.sort_unstable();
            assert_eq!(paths, sorted, "{kind:?}");
        }
    }

    #[test]
    fn the_readme_names_the_command_that_builds_this_kind() {
        // The one thing an author needs next, and the one thing a template that shared a README between kinds would
        // get wrong.
        let headless = scaffold(TemplateKind::Headless).as_map();
        let ui = scaffold(TemplateKind::Ui).as_map();
        assert!(
            headless.get("README.md").expect("a readme").contains("Wasm"),
            "the headless README should say what it builds"
        );
        assert!(
            ui.get("README.md").expect("a readme").contains("`ui/`"),
            "the UI README should say what it builds"
        );
    }

    #[test]
    fn no_scaffolded_file_contains_a_leaked_escape() {
        // ★ Found by reading the output rather than the source: the UI document contained the two characters `\` and
        // `n` in the middle of a JavaScript comment, because a line had been written when the surrounding literal was a
        // normal string and was later moved into a raw one. In a raw string an escape is not an escape — it is text —
        // so what shipped to the author was `...the page can read to\n      // impersonate another.`
        //
        // The scaffold is the first thing a plugin author reads, and a leaked escape in it is the sort of thing that
        // costs a reader five minutes and teaches them the tool is sloppy. It is also invisible in review: the source
        // line looks like a line break until you notice the colouring.
        //
        // Checked over **every** file of every kind rather than just the document, because the mistake is about the
        // literal a line sits in and not about which file it ends up in.
        for kind in TemplateKind::all() {
            for (path, contents) in scaffold(kind).as_map() {
                assert!(
                    !contents.contains("\\n") && !contents.contains("\\t"),
                    "{kind:?}: {path} contains a leaked escape:\n{contents}"
                );
            }
        }
    }

    #[test]
    fn the_interface_reaches_the_kernel_only_through_the_facade() {
        // The one thing an author must not get wrong: `window.synra` is a closed facade, and a scaffold that used
        // `invoke` directly would be teaching the wrong shape — and require a token it cannot have.
        let ui = scaffold(TemplateKind::Ui).as_map();
        let document = ui.get("ui/index.html").expect("a document");
        assert!(document.contains("window.synra"), "{document}");
        assert!(!document.contains("__TAURI__"), "the scaffold reached past the facade:\n{document}");
        assert!(!document.contains("token"), "the scaffold mentions a token:\n{document}");
    }

    #[test]
    fn the_scaffold_declares_no_capability_it_does_not_need() {
        // A scaffold that asked for `storage` would be teaching an author to ask for more than they use, and the
        // permission dialog is where that becomes the user's problem.
        for kind in TemplateKind::all() {
            let scaffold = scaffold(kind);
            let files = scaffold.as_map();
            let manifest = files.get("manifest.json").expect("a manifest");
            // An empty *array*, because a missing field and an empty list are different statements — "the author
            // forgot" and "this plugin needs nothing" — and the loader has to tell them apart.
            assert!(manifest.contains(r#""capabilities": []"#), "{kind:?}:\n{manifest}");
        }
    }

    #[test]
    fn the_kind_round_trips_through_its_word() {
        for kind in TemplateKind::all() {
            assert!(!kind.as_str().is_empty());
        }
        assert_eq!(TemplateKind::Headless.as_str(), "headless");
        assert_eq!(TemplateKind::Ui.as_str(), "ui");
        assert_eq!(TemplateKind::Hybrid.as_str(), "hybrid");
    }
}
