//! The shape of a manifest, and the constants that bound it.
//!
//! # Why the bounds are here and not in the validator
//!
//! Because a limit is part of what a field *is*. A title is at most `MAX_TITLE_LEN` characters; a reader of these types
//! should not have to find the validator to learn that, and a change to one should be visible beside the other.

pub use declarations::CapabilityDeclaration;

use serde::{Deserialize, Serialize};

use synra_protocol::PluginId;

/// The manifest schema version this build understands.
pub const MANIFEST_SCHEMA: &str = "https://synra-app.dev/schema/manifest/v1.json";

/// The longest a title may be.
///
/// Bounded because it is drawn in a list, and a title of a thousand characters is one that pushes everything
/// else off the screen.
pub const MAX_TITLE_LEN: usize = 64;

/// The longest a description may be.
pub const MAX_DESCRIPTION_LEN: usize = 512;

/// The longest an action or event logical name may be.
pub const MAX_NAME_LEN: usize = 64;

/// Scopes that belong to the host.
///
/// Reserved so that a plugin cannot present itself as part of the application. `@synra-plugin/…` is the
/// official scope and is not on this list — it is the one the host itself publishes under.
pub const RESERVED_SCOPES: &[&str] = &["synra", "core", "system"];

/// The scope the official plugins use.
pub const OFFICIAL_SCOPE: &str = "synra-plugin";

// ──────────────────────────────────────────────────────────────────────────────────────────────────────
// The manifest
// ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// A plugin manifest, as parsed from `manifest.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    /// The schema this file claims to follow.
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none", default)]
    pub schema: Option<String>,

    /// The plugin's id.
    pub id: PluginId,
    /// Its version, as semver.
    pub version: String,
    /// The name shown to a person.
    pub title: String,
    /// A sentence describing it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// A path to an icon, relative to the package root.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icon: Option<String>,

    /// Who published it. Used for trust and for signing.
    pub publisher: Publisher,
    /// An SPDX licence identifier.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub license: Option<String>,
    /// Where its source lives.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub repository: Option<String>,

    /// Which host SDK versions it works with.
    pub sdk: SdkRequirement,
    /// Which WIT world it was built against.
    pub wit: String,

    /// How it runs. At least one half must be present.
    pub runtime: Runtime,

    /// What it needs permission for.
    ///
    /// Required and may be empty. A missing field and an empty list are different statements — "the author
    /// forgot" and "this plugin needs nothing" — and the loader has to be able to tell them apart.
    pub capabilities: Vec<CapabilityDeclaration>,

    /// Actions other plugins or the host may call.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub actions: Vec<ActionDeclaration>,
    /// Share kinds this plugin wants to be offered.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub share_handlers: Vec<ShareHandler>,
    /// Events this plugin defines and emits.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub events: Vec<EventDeclaration>,
    /// Events this plugin wants delivered.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub handles: Vec<HandleDeclaration>,

    /// Other plugins it composes with.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub compose: Vec<ComposeDependency>,
    /// The hosts it may reach, for the consent screen.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<NetworkDeclaration>,
    /// The pages it adds to the interface.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub pages: Vec<PageDeclaration>,
    /// What it would like to be allowed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resources: Option<ResourceHints>,
    /// Translations of the human-readable strings.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub locales: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Who published a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publisher {
    /// A stable identifier, used for trust decisions.
    pub id: String,
    /// A name to show.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    /// A homepage.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
}

/// Which host SDK versions a plugin works with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SdkRequirement {
    /// The oldest host it works with.
    pub min: String,
    /// The host it was built against.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preferred: Option<String>,
}

/// How a plugin runs.
///
/// A validated plugin always has a headless Wasm component and may add a UI bundle.
/// The optional input field lets validation classify missing headless declarations explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Runtime {
    /// The Wasm artifact.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub headless: Option<HeadlessRuntime>,
    /// The interface bundle.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ui: Option<UiRuntime>,
}

/// The headless half of a runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeadlessRuntime {
    /// The Wasm module, relative to the package root.
    pub artifact: String,
    /// Whether memory may persist between calls to this instance.
    ///
    /// `false` means the host may reuse an instance freely; `true` means the plugin keeps state and the host
    /// must not hand its instance to a different conversation.
    pub stateful: bool,
    /// Soft hints the host may ignore, such as `cpu-heavy`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hints: Vec<String>,
}

/// The interface half of a runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiRuntime {
    /// The bundle, relative to the package root.
    pub artifact: String,
    /// The entry document inside the bundle.
    pub entry: String,
    /// The page shown first.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub default_page: Option<String>,
}

mod context;
mod declarations;

pub use context::{ManifestContext, ResourceHints, manifest_digest};
pub use declarations::{
    ActionDeclaration, ComposeDependency, EventDeclaration, HandleDeclaration, NetworkDeclaration,
    OutboundHost, PageDeclaration, ShareHandler,
};
