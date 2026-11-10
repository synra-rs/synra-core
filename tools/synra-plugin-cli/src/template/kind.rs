/// The two supported shapes: a Wasm plugin, with an optional interface.
///
/// Every plugin ships a Rust headless component. Hybrid plugins also ship a WebView bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TemplateKind {
    /// Wasm only. No interface.
    Headless,
    /// Both halves, sharing one manifest.
    Hybrid,
}

impl TemplateKind {
    /// The word a user types and the manifest does not use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Headless => "headless",
            Self::Hybrid => "hybrid",
        }
    }

    /// Every kind, for a table-driven test.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::Headless, Self::Hybrid]
    }

    /// Runtime artifacts declared by this supported template.
    pub(super) const fn blocks(self) -> &'static str {
        match self {
            Self::Headless => {
                r#""runtime": {
    "headless": {
      "artifact": "plugin.wasm",
      "stateful": false
    }
  }"#
            }
            Self::Hybrid => {
                r#""runtime": {
    "headless": {
      "artifact": "plugin.wasm",
      "stateful": false
    },
    "ui": {
      "artifact": "ui.zip",
      "entry": "index.html"
    }
  }"#
            }
        }
    }
}
