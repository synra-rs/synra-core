//! The shape of a manifest, and the constants that bound it.
//!
//! # Why the bounds are here and not in the validator
//!
//! Because a limit is part of what a field *is*. A title is at most `MAX_TITLE_LEN` characters; a reader of these types
//! should not have to find the validator to learn that, and a change to one should be visible beside the other.

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

/// One capability the plugin asks for.
///
/// A struct with a `cap` field rather than a bare string, so the list has room to grow — a justification, a
/// scope note — without changing every manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDeclaration {
    /// The capability string.
    pub cap: String,
    /// Why the plugin wants it, if the author chose to say.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

/// An action the plugin offers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionDeclaration {
    /// The action's name within the plugin.
    pub name: String,
    /// The arguments' JSON Schema.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub args: Option<serde_json::Value>,
    /// The return value's JSON Schema.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub returns: Option<serde_json::Value>,
    /// A sentence describing it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

/// A share kind the plugin handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareHandler {
    /// The kinds it accepts, such as `text` or `url`.
    pub kinds: Vec<String>,
    /// A sentence describing what it does with them.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

/// An event the plugin defines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventDeclaration {
    /// The full event name, which must be inside the plugin's own namespace.
    pub name: String,
    /// The payload's JSON Schema.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload: Option<serde_json::Value>,
}

/// An event the plugin wants delivered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandleDeclaration {
    /// An event name or a pattern.
    pub event: String,
    /// A condition on the payload, if the plugin only wants some of them.
    #[serde(rename = "match", skip_serializing_if = "Option::is_none", default)]
    pub conditions: Option<serde_json::Value>,
}

/// Another plugin this one composes with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComposeDependency {
    /// The other plugin's id.
    pub id: PluginId,
    /// A semver range.
    pub version: String,
    /// Whether the plugin works without it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub optional: Option<bool>,
}

/// The hosts a plugin may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkDeclaration {
    /// The hosts it may reach out to.
    pub outbound: Vec<OutboundHost>,
}

/// One host in the network declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutboundHost {
    /// The hostname, possibly with a leading `*.`.
    pub host: String,
    /// The methods it needs, when it needs only some.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub methods: Vec<String>,
}

/// A page the plugin adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageDeclaration {
    /// The page's key.
    pub key: String,
    /// Its title.
    pub title: String,
    /// Its route.
    pub path: String,
    /// An icon name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icon: Option<String>,
}

/// What the plugin would like to be allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceHints {
    /// A memory budget in mebibytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preferred_memory_mb: Option<u32>,
    /// A per-call time budget in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preferred_timeout_ms: Option<u32>,
}

// ──────────────────────────────────────────────────────────────────────────────────────────────────────
// What the checks need from outside
// ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// What the checks need that is not in the manifest.
#[derive(Debug, Clone, Default)]
pub struct ManifestContext {
    /// The host SDK version, for the `sdk.min` comparison.
    pub host_sdk: Option<String>,
    /// The WIT world the host supports.
    pub host_wit: Option<String>,
    /// Artifacts that exist in the package, relative to its root.
    ///
    /// `None` skips the existence check, which is what the schema-level validation wants: a manifest can be
    /// checked for self-consistency before anything has been unpacked.
    ///
    /// A package walk produces a short ordered list; validation only needs membership checks.
    pub present_artifacts: Option<Vec<String>>,
}

/// The digest a consent decision is recorded against.
///
/// # ★ Why this is here rather than at each caller
///
/// Because two callers need it and they must agree to the byte. The shell records the user's decision against this
/// value; the daemon refuses to run a plugin whose manifest no longer hashes to what was recorded. Two implementations
/// that drifted — one hashing the parsed value, one the raw text — would produce a mismatch on every plugin, or worse,
/// a match for a manifest that had only been reformatted.
///
/// So it hashes the **bytes exactly as they are on disk**, which is why it takes text and not a [`Manifest`]: by the
/// time a manifest has been parsed, field order and whitespace are gone, and two files differing only in those would
/// hash alike.
///
/// SHA-256 in hex, and **not** an SRI string. Artifacts are signed and compared as SRI (`sha256-<base64>`); the manifest
/// is a text document rather than an addressed blob, and this is the encoding the plugin CLI signs and every recorded
/// consent decision carries. The two encodings differ on purpose — and using this function's sibling by accident is a
/// genuine signature reported as covering a different manifest, which is why the install and scan paths both call this
/// rather than hashing for themselves.
#[must_use]
pub fn manifest_digest(text: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}
