use super::TemplateKind;

/// The manifest for a scaffold, as the text an author edits.
pub(super) fn manifest_json(plugin_id: &str, version: &str, title: &str, kind: TemplateKind) -> String {
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
"#,
        schema = synra_plugin_api::manifest::MANIFEST_SCHEMA,
        kind = kind.as_str(),
    )
}

/// A README that says what to do next.
pub(super) fn readme(plugin_id: &str, kind: TemplateKind) -> String {
    let build = match kind {
        TemplateKind::Headless => {
            "`synra-plugin build` writes a complete package with the Wasm artifact into `dist/`."
        }
        TemplateKind::Hybrid => {
            "`synra-plugin build` packages static `ui/` assets into `ui.zip` alongside the Wasm artifact in `dist/`."
        }
    };
    format!(
        "# {plugin_id}\n\nA {kind} plugin for Synra.\n\n{build}\n\n## Next\n\n1. Edit `manifest.json`: the title, the \
         description, the publisher, and the capabilities the plugin needs.\n2. Implement the entry points the \
         manifest names.\n3. `synra-plugin verify --dir dist` before publishing — it checks the manifest, the artifact's size and \
         the imports the kernel refuses.\n",
        kind = kind.as_str(),
    )
}

/// Ignore the build output, so an author's first commit is their source.
pub(super) fn gitignore() -> String {
    "target/\n*.wasm\n*.zip\n*.sig\ndist/\n.synra-build*\n".to_owned()
}

/// The Rust half of a headless plugin.
///
/// A constant rather than a function of the id: the source names the entry points the *manifest* declares, and the
/// manifest carries the id. Interpolating one here would put the plugin's name in a file that has to compile, for no
/// reason an author would thank us for.
pub(super) const HEADLESS_SOURCE: &str = include_str!("headless.rs");

/// The Rust half of a hybrid plugin.
///
/// The same source with a note about the other half, because a hybrid plugin *is* one plugin with one manifest: the
/// interface and the Wasm code share its capabilities rather than each declaring their own.
pub(super) fn hybrid_source() -> String {
    format!(
        "{HEADLESS_SOURCE}\n// A hybrid plugin has both halves: this one, and `ui/index.html`. They are one plugin \
         with\n// one manifest, so the interface and the Wasm code share its capabilities rather than each declaring\n\
         // their own.\n"
    )
}

/// The WebView half.
pub(super) fn ui_document(title: &str) -> String {
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
    <p>The plugin interface. Connect host capabilities through the Synra UI SDK.</p>
  </body>
</html>
"#
    )
}
