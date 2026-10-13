//! The plugin manifest: what an author declares, and the checks that hold them to it.
//!
//! # One declaration, four questions
//!
//! A manifest answers four things, and they are answered in one file because splitting them would let them
//! drift apart:
//!
//! * **What is this?** — id, version, title, publisher.
//! * **What does it need to run?** — which SDK range, which WIT world, and which artifact to load.
//! * **What may it do?** — the capability list the user is shown and asked to approve.
//! * **How does it connect?** — the actions it offers, the events it defines, and the events it wants to
//!   receive.
//!
//! # The checks are not a formality
//!
//! Every rule in [`Manifest::validate`] exists because the alternative is a failure somewhere much worse:
//!
//! * A **namespace violation** — an event named `_plugin.someone-else.thing` — is one plugin impersonating
//!   another, and it fails silently: the receiving side sees a legitimate name and routes it.
//! * A **capability the runtime cannot use** — `ui:*` on a headless plugin — is a permission the user approves
//!   at install time and that nothing can ever exercise. The consent screen said something untrue.
//! * A **`handles` entry with no `on_event`** produces a plugin that is installed, appears to work, and
//!   silently drops every message it asked for.
//! * An **unbounded `maxLength`** in an event's payload schema is a promise the host cannot keep when it
//!   validates the payload, and the promise is what the receiving side trusted.
//!
//! Each of those is a failure a user cannot diagnose, which is why they are refused at load rather than
//! tolerated.
//!
//! # What this crate does not do
//!
//! * It does not read files. [`Manifest::from_json`] takes text; finding and reading the file is the loader's
//!   job, and the loader is what knows about package roots and symlinks.
//! * It does not check that artifacts exist, or that declared methods are implemented. Both need the
//!   filesystem and the Wasm module, so they arrive as [`ManifestContext`] and [`Implementation`].
//! * It does not compile capabilities. [`synra_capability`] does that; this calls it.


use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use synra_capability::{Capability, CapabilityError, Domain};
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
/// Both halves are optional and at least one is required: one is headless, one is interface-only, and both
/// together are a hybrid. There is no fourth state, and the validation enforces that rather than leaving a
/// manifest with neither artifact to be discovered as a load failure later.
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

/// What the methods a manifest's declarations imply.
///
/// The manifest declares what the plugin *wants* to handle; the Wasm module or the interface bundle has to
/// actually implement the entry point. Both directions are checked, because each catches a different mistake:
///
/// * `handles` without `on_event` is a plugin that is installed, appears to work, and silently drops every
///   message it asked for.
/// * `on_event` without `handles` is dead code, and more importantly a sign that the manifest and the
///   implementation have drifted apart — at which point no other declaration can be trusted either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Implementation {
    /// Whether the plugin implements the event entry point.
    pub on_event: bool,
    /// Whether it implements the action entry point.
    pub execute: bool,
    /// Whether it has an activation entry point.
    pub activate: bool,
}

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
    /// # Why a slice and not a set
    ///
    /// This field is part of a stable crate's public signature, and a public `HashSet` is a promise about the
    /// implementation: replacing it with a `BTreeSet` would be a breaking change, and that replacement is exactly what
    /// a determinism problem calls for. The check it feeds is a membership test over a handful of paths, so the
    /// container's choice buys nothing and costs a promise.
    ///
    /// A slice also takes what a caller has: a package's file list comes from walking a directory, and a `Vec` is what
    /// that produces.
    pub present_artifacts: Option<Vec<String>>,
    /// Which entry points the implementation provides.
    pub implementation: Option<Implementation>,
}

/// How thorough the check is.
///
/// Two levels because they run in different places with different information. The loader has the package on
/// disk and the module parsed; the CLI has the source tree. A check that needs something neither has is not
/// in either level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ValidationLevel {
    /// What the manifest alone can be held to: schema, names, namespaces, capability syntax, runtime shape.
    ///
    /// Runs at load and in the CLI.
    Schema,
    /// Everything, including the checks that need the package and the parsed module.
    ///
    /// Runs where a caller supplies a [`ManifestContext`] with the artifacts and the implementation.
    Verify,
}

/// A plugin's wire slug: the segment its events live under.
///
/// `@synra-plugin/chat` becomes `chat`, and `@imba97/synra-plugin-notes` becomes `notes`. The
/// `synra-plugin-` prefix is dropped because it is noise that every official plugin carries, and the slug is
/// what an author types in an event name.
///
/// # Errors
///
/// [`ManifestError::UnsluggedId`] when the name has no usable ending — an empty name, or one that is all
/// prefixes.
pub fn to_wire_slug(id: &PluginId) -> Result<String, ManifestError> {
    let text = id.as_str();
    // The name is everything after the last `/`, or the whole string when there is no scope.
    let name = text.rsplit('/').next().unwrap_or(text);
    let stripped = name.strip_prefix("synra-plugin-").unwrap_or(name);

    if stripped.is_empty() || !is_slug_segment(stripped) {
        return Err(ManifestError::UnsluggedId { id: text.to_owned() });
    }
    Ok(stripped.to_owned())
}

/// Whether a string is usable as a slug segment.
fn is_slug_segment(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    // Must start with a lowercase letter, then lowercase letters, digits or hyphens, and not end with one: a
    // trailing hyphen makes `_plugin.chat-.text` legal, which reads as a typo.
    if !first.is_ascii_lowercase() {
        return false;
    }
    if text.ends_with('-') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// Checks a plugin id against the grammar.
///
/// # Errors
///
/// [`ManifestError::BadId`] with the reason.
pub fn check_plugin_id(id: &str) -> Result<(), ManifestError> {
    let Some((scope, name)) = id.strip_prefix('@').and_then(|rest| rest.split_once('/')) else {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a plugin id must be scoped, as `@scope/name`".to_owned(),
        });
    };

    if RESERVED_SCOPES.contains(&scope) {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: format!("the scope `{scope}` is reserved for the host"),
        });
    }

    // `scope ::= [a-z0-9][a-z0-9-]{1,38}` — at least two characters, and the first may be a digit.
    if scope.len() < 2 || scope.len() > 39 {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a scope must be between 2 and 39 characters".to_owned(),
        });
    }
    if !scope
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a scope may contain only lowercase letters, digits and hyphens".to_owned(),
        });
    }

    // `name ::= [a-z0-9][a-z0-9-]{0,63}`
    if name.is_empty() || name.len() > 64 {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a name must be between 1 and 64 characters".to_owned(),
        });
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a name may contain only lowercase letters, digits and hyphens".to_owned(),
        });
    }

    Ok(())
}

/// Checks a version string is a legal semver.
///
/// Hand-written rather than pulled from the `semver` crate: the manifest needs `major.minor.patch` with
/// optional pre-release and build metadata, and a dependency for that is one more thing to keep current in a
/// crate whose whole job is to be a stable contract.
///
/// # Errors
///
/// [`ManifestError::BadVersion`] with the reason.
pub fn check_version(version: &str) -> Result<(), ManifestError> {
    let bad = |reason: &str| ManifestError::BadVersion {
        version: version.to_owned(),
        reason: reason.to_owned(),
    };

    // Build metadata first, since it may contain `+` and dots.
    let (without_build, _build) = match version.split_once('+') {
        Some((head, build)) => {
            if build.is_empty() || !build.split('.').all(is_identifier) {
                return Err(bad("build metadata is empty or malformed"));
            }
            (head, Some(build))
        }
        None => (version, None),
    };

    let (core, _pre) = match without_build.split_once('-') {
        Some((head, pre)) => {
            if pre.is_empty() || !pre.split('.').all(is_identifier) {
                return Err(bad("a pre-release is empty or malformed"));
            }
            (head, Some(pre))
        }
        None => (without_build, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(bad("a version is `major.minor.patch`"));
    }
    for part in parts {
        if part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(bad("each of major, minor and patch must be digits"));
        }
        // A leading zero is legal only for the number zero itself.
        if part.len() > 1 && part.starts_with('0') {
            return Err(bad("a numeric part must not have a leading zero"));
        }
    }
    Ok(())
}

/// Whether a pre-release or build identifier is well formed.
fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

/// Compares two versions, returning their ordering.
///
/// Pre-release versions sort *below* the release they lead to, which is the rule that makes `1.0.0-rc.1` less
/// than `1.0.0`. Getting that backwards would let a release candidate satisfy a minimum that the release was
/// written for.
///
/// # Errors
///
/// [`ManifestError::BadVersion`] if either string is not a legal semver.
pub fn compare_versions(left: &str, right: &str) -> Result<core::cmp::Ordering, ManifestError> {
    check_version(left)?;
    check_version(right)?;

    let parse = |version: &str| {
        let (without_build, _) = version.split_once('+').unwrap_or((version, ""));
        let (core, pre) = without_build.split_once('-').unwrap_or((without_build, ""));
        let numbers: Vec<u64> = core
            .split('.')
            .filter_map(|part| part.parse::<u64>().ok())
            .collect();
        (numbers, pre.to_owned())
    };

    let (left_numbers, left_pre) = parse(left);
    let (right_numbers, right_pre) = parse(right);

    match left_numbers.cmp(&right_numbers) {
        core::cmp::Ordering::Equal => {}
        other => return Ok(other),
    }

    Ok(match (left_pre.is_empty(), right_pre.is_empty()) {
        // A release is above any of its pre-releases.
        (true, true) => core::cmp::Ordering::Equal,
        (true, false) => core::cmp::Ordering::Greater,
        (false, true) => core::cmp::Ordering::Less,
        // Both are pre-releases: compared identifier by identifier.
        (false, false) => compare_prerelease(&left_pre, &right_pre),
    })
}

/// Compares two pre-release strings.
fn compare_prerelease(left: &str, right: &str) -> core::cmp::Ordering {
    let left_parts: Vec<&str> = left.split('.').collect();
    let right_parts: Vec<&str> = right.split('.').collect();

    for (a, b) in left_parts.iter().zip(&right_parts) {
        let ordering = match (a.parse::<u64>(), b.parse::<u64>()) {
            // Numeric identifiers compare numerically, so `rc.10` is above `rc.9` rather than below it.
            (Ok(a), Ok(b)) => a.cmp(&b),
            // A numeric identifier is below an alphanumeric one.
            (Ok(_), Err(_)) => core::cmp::Ordering::Less,
            (Err(_), Ok(_)) => core::cmp::Ordering::Greater,
            (Err(_), Err(_)) => a.cmp(b),
        };
        if ordering != core::cmp::Ordering::Equal {
            return ordering;
        }
    }
    // Fewer identifiers is lower, so `rc` is below `rc.1`.
    left_parts.len().cmp(&right_parts.len())
}

// ──────────────────────────────────────────────────────────────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// Why a manifest is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// The text is not valid JSON, or does not match the manifest's shape.
    #[error("the manifest is not readable: {0}")]
    Malformed(String),

    /// The id does not follow the grammar.
    #[error("the plugin id {id:?} is not usable: {reason}")]
    BadId {
        /// The id that was offered.
        id: String,
        /// What is wrong with it.
        reason: String,
    },

    /// The id has no usable wire slug.
    #[error("the plugin id {id:?} has no usable event namespace")]
    UnsluggedId {
        /// The id that was offered.
        id: String,
    },

    /// A version is not a legal semver.
    #[error("{version:?} is not a version: {reason}")]
    BadVersion {
        /// The version that was offered.
        version: String,
        /// What is wrong with it.
        reason: String,
    },

    /// Neither half of the runtime is declared.
    #[error("a plugin must declare `runtime.headless`, `runtime.ui`, or both")]
    NoRuntime,

    /// A declared artifact is not in the package.
    #[error("the declared {kind} artifact {path:?} is not in the package")]
    MissingArtifact {
        /// Which half of the runtime.
        kind: &'static str,
        /// The path that was declared.
        path: String,
    },

    /// A capability string does not parse.
    #[error("the capability {cap:?} is not usable: {source}")]
    BadCapability {
        /// The capability that was offered.
        cap: String,
        /// Why it did not parse.
        #[source]
        source: CapabilityError,
    },

    /// A capability cannot be exercised by this kind of plugin.
    #[error("{cap} cannot be used by a {kind} plugin")]
    UnusableCapability {
        /// The capability that was offered.
        cap: String,
        /// Which kind of plugin cannot use it.
        kind: &'static str,
    },

    /// The network declaration and the network capabilities disagree.
    #[error("the network declaration and its capabilities disagree: {detail}")]
    NetworkMismatch {
        /// What disagrees.
        detail: String,
    },

    /// Two declarations share a name.
    #[error("the {kind} name {name:?} is declared more than once")]
    DuplicateName {
        /// Which kind of declaration.
        kind: &'static str,
        /// The repeated name.
        name: String,
    },

    /// An event is declared outside the plugin's own namespace.
    #[error("the event {name:?} is not inside the plugin's namespace {namespace:?}")]
    ForeignEventNamespace {
        /// The event that was offered.
        name: String,
        /// The namespace the plugin owns.
        namespace: String,
    },

    /// An event payload schema is not usable.
    #[error("the payload schema for {name:?} is not usable: {detail}")]
    BadPayloadSchema {
        /// The event whose payload it is.
        name: String,
        /// What is wrong with it.
        detail: String,
    },

    /// A `handles` entry is not a known event, a declared event, or a legal pattern.
    #[error("the handle {event:?} is not a known event, a declared event, or a legal pattern")]
    BadHandle {
        /// The entry that was offered.
        event: String,
    },

    /// The declarations and the implementation disagree.
    #[error("the manifest declares {declared} but the plugin does not implement it")]
    MissingImplementation {
        /// What was declared.
        declared: &'static str,
    },

    /// The implementation provides something the manifest does not declare.
    #[error("the plugin implements {implemented} but the manifest does not declare it")]
    UndeclaredImplementation {
        /// What was implemented.
        implemented: &'static str,
    },

    /// A page key is repeated.
    #[error("the page key {key:?} is declared more than once")]
    DuplicatePageKey {
        /// The repeated key.
        key: String,
    },

    /// The SDK requirement excludes the host.
    #[error("this plugin needs SDK {min} or newer, and this host is {host}")]
    SdkTooOld {
        /// What the plugin needs.
        min: String,
        /// What the host is.
        host: String,
    },

    /// The WIT world does not match the host's.
    #[error("this plugin was built against WIT {plugin}, and this host speaks {host}")]
    WitMismatch {
        /// What the plugin was built against.
        plugin: String,
        /// What the host speaks.
        host: String,
    },

    /// A `compose` entry describes a cycle.
    #[error("the plugin composes with itself, directly or through {through:?}")]
    CompositionCycle {
        /// Where the cycle was found.
        through: Vec<String>,
    },

    /// A string field is too long.
    #[error("the {field} is {len} characters, and the limit is {max}")]
    TooLong {
        /// Which field.
        field: &'static str,
        /// How long it is.
        len: usize,
        /// The limit.
        max: usize,
    },
}

impl Manifest {
    /// Parses a manifest, rejecting anything the shape does not allow.
    ///
    /// Unknown fields are **refused**, like the wire protocol's envelopes and unlike the discovery datagrams.
    /// The reasoning is the same as for an envelope: a manifest is a contract the host enforces, and a field
    /// the host silently ignores is a field whose author believes it does something.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Malformed`] if the text does not match the shape.
    pub fn from_json(text: &str) -> Result<Self, ManifestError> {
        let mut manifest: Self =
            serde_json::from_str(text).map_err(|error| ManifestError::Malformed(error.to_string()))?;

        // The schema field is checked here rather than in `validate`, because it is about the *file* rather
        // than the plugin: a manifest that names a schema this build does not know may have fields whose
        // meaning changed, and the unknown-field rule above would not catch a field that kept its name.
        if let Some(schema) = &manifest.schema
            && schema != MANIFEST_SCHEMA
        {
            return Err(ManifestError::Malformed(format!(
                "the manifest names schema {schema:?}, and this build understands {MANIFEST_SCHEMA:?}"
            )));
        }
        // Normalised, so a later comparison does not have to remember that it is optional in the file.
        manifest.schema = Some(MANIFEST_SCHEMA.to_owned());
        Ok(manifest)
    }

    /// The wire slug this plugin's events live under.
    ///
    /// # Errors
    ///
    /// [`ManifestError::UnsluggedId`] for an id with no usable slug.
    pub fn wire_slug(&self) -> Result<String, ManifestError> {
        to_wire_slug(&self.id)
    }

    /// The event namespace this plugin owns, including the trailing dot.
    ///
    /// # Errors
    ///
    /// As [`Self::wire_slug`].
    pub fn event_namespace(&self) -> Result<String, ManifestError> {
        Ok(format!("_plugin.{}.", self.wire_slug()?))
    }

    /// The capabilities, compiled into a set.
    ///
    /// # Errors
    ///
    /// [`ManifestError::BadCapability`] for the first entry that does not parse, or a set error for a list
    /// that is too large.
    pub fn capability_set(&self) -> Result<synra_capability::CapabilitySet, ManifestError> {
        let mut set = synra_capability::CapabilitySet::new();
        for declaration in &self.capabilities {
            let parsed =
                Capability::parse(&declaration.cap).map_err(|source| ManifestError::BadCapability {
                    cap: declaration.cap.clone(),
                    source,
                })?;
            set.insert(parsed)
                .map_err(|error| ManifestError::Malformed(error.to_string()))?;
        }
        Ok(set)
    }

    /// Whether the plugin has a headless half.
    #[must_use]
    pub const fn is_headless(&self) -> bool {
        self.runtime.headless.is_some()
    }

    /// Whether the plugin has an interface half.
    #[must_use]
    pub const fn has_ui(&self) -> bool {
        self.runtime.ui.is_some()
    }

    /// Whether the plugin has both halves.
    #[must_use]
    pub const fn is_hybrid(&self) -> bool {
        self.is_headless() && self.has_ui()
    }

    /// The title in the reader's language, falling back to the default.
    ///
    /// A location is a language tag such as `zh-CN`. The fallback chain is exact match, then the primary
    /// subtag, then the default — so a manifest with only `zh-CN` still answers for `zh`.
    #[must_use]
    pub fn localised_title(&self, locale: &str) -> &str {
        self.localised("title", locale).unwrap_or(&self.title)
    }

    /// The description in the reader's language, falling back to the default.
    #[must_use]
    pub fn localised_description(&self, locale: &str) -> Option<&str> {
        self.localised("description", locale)
            .or(self.description.as_deref())
    }

    /// Looks a localised string up.
    ///
    /// The fallback chain is exact match, then the primary subtag, then nothing — and "nothing" is important:
    /// returning an empty string for a locale the manifest does not name would make a description disappear
    /// rather than fall back to the default.
    fn localised(&self, key: &str, locale: &str) -> Option<&str> {
        let locales = self.locales.as_ref()?;

        // The exact tag first, then the primary subtag so a manifest declaring `zh-CN` answers for
        // `zh-Hans-CN`. Built as a list rather than a chain of closures, because a closure returning a borrow
        // of `locales` has a lifetime the compiler cannot tie to `self`.
        let primary = locale.split(['-', '_']).next().unwrap_or(locale);
        let mut candidates: Vec<&str> = vec![locale];
        if primary != locale {
            candidates.push(primary);
        }

        candidates.into_iter().find_map(|tag| {
            locales
                .get(tag)
                .and_then(|entry| entry.as_object())
                .and_then(|entry| entry.get(key))
                .and_then(|value| value.as_str())
        })
    }

    /// Every check the manifest alone can be held to.
    ///
    /// # Errors
    ///
    /// The first [`ManifestError`] found.
    pub fn validate(&self, level: ValidationLevel, context: &ManifestContext) -> Result<(), ManifestError> {
        self.check_identity()?;
        self.check_runtime(context)?;
        let capabilities = self.check_capabilities()?;
        self.check_names()?;
        self.check_events()?;
        self.check_handles()?;
        self.check_network(&capabilities)?;
        self.check_pages()?;
        self.check_composition()?;
        self.check_size_limits()?;
        self.check_versions(context)?;

        if level >= ValidationLevel::Verify {
            self.check_implementation(context)?;
        }
        Ok(())
    }

    /// The id, the slug and the versions.
    fn check_identity(&self) -> Result<(), ManifestError> {
        check_plugin_id(self.id.as_str())?;
        self.wire_slug()?;
        check_version(&self.version)?;
        check_version(&self.sdk.min)?;
        if let Some(preferred) = &self.sdk.preferred {
            check_version(preferred)?;
        }
        Ok(())
    }

    /// The runtime's shape and its artifacts.
    fn check_runtime(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        if !self.is_headless() && !self.has_ui() {
            return Err(ManifestError::NoRuntime);
        }

        if let Some(present) = &context.present_artifacts {
            let check = |kind: &'static str, path: &str| {
                if present.iter().any(|artifact| artifact == path) {
                    Ok(())
                }
                else {
                    Err(ManifestError::MissingArtifact { kind, path: path.to_owned() })
                }
            };
            if let Some(headless) = &self.runtime.headless {
                check("headless", &headless.artifact)?;
            }
            if let Some(ui) = &self.runtime.ui {
                check("ui", &ui.artifact)?;
            }
        }

        if let Some(ui) = &self.runtime.ui
            && ui.entry.trim().is_empty()
        {
            return Err(ManifestError::Malformed(
                "the ui runtime declares an empty entry document".to_owned(),
            ));
        }
        Ok(())
    }

    /// The capabilities, and whether this kind of plugin can use them.
    fn check_capabilities(&self) -> Result<synra_capability::CapabilitySet, ManifestError> {
        let set = self.capability_set()?;

        for declaration in &self.capabilities {
            let capability = Capability::parse(&declaration.cap).map_err(|source| {
                ManifestError::BadCapability { cap: declaration.cap.clone(), source }
            })?;

            // A headless plugin has no interface, so a `ui:*` grant is one the user would approve at install
            // time and that nothing can ever exercise. The consent screen said something untrue.
            if !self.has_ui() && capability.domain() == Domain::Ui {
                return Err(ManifestError::UnusableCapability {
                    cap: declaration.cap.clone(),
                    kind: "headless",
                });
            }
        }
        Ok(set)
    }

    /// Names within the manifest.
    fn check_names(&self) -> Result<(), ManifestError> {
        let mut actions = HashSet::new();
        for action in &self.actions {
            if action.name.is_empty() {
                return Err(ManifestError::Malformed("an action has an empty name".to_owned()));
            }
            if !actions.insert(action.name.as_str()) {
                return Err(ManifestError::DuplicateName {
                    kind: "action",
                    name: action.name.clone(),
                });
            }
        }
        Ok(())
    }

    /// The event declarations and their payload schemas.
    fn check_events(&self) -> Result<(), ManifestError> {
        let namespace = self.event_namespace()?;
        let mut names = HashSet::new();

        for event in &self.events {
            if !names.insert(event.name.as_str()) {
                return Err(ManifestError::DuplicateName {
                    kind: "event",
                    name: event.name.clone(),
                });
            }

            // The namespace check is the one that stops a plugin emitting under another plugin's name. Without
            // it, a receiving side sees a legitimate name and routes it: one plugin impersonating another, with
            // nothing in any log to say so.
            if !event.name.starts_with(&namespace) || event.name.len() <= namespace.len() {
                return Err(ManifestError::ForeignEventNamespace {
                    name: event.name.clone(),
                    namespace,
                });
            }

            if let Some(payload) = &event.payload {
                check_payload_schema(&event.name, payload)?;
            }
        }
        Ok(())
    }

    /// The `handles` entries.
    fn check_handles(&self) -> Result<(), ManifestError> {
        let declared: HashSet<&str> = self.events.iter().map(|event| event.name.as_str()).collect();
        let namespace = self.event_namespace()?;

        for handle in &self.handles {
            // Four things an entry may be, and the order matters only for the message:
            //
            // 1. a known host event,
            // 2. one of this plugin's own declared names,
            // 3. a pattern in the host's namespace, which covers host events a newer build defines,
            // 4. a pattern in this plugin's own namespace, which is what a plugin uses to catch its own family.
            //
            // A pattern anywhere else is a subscription to a plugin that is not this one, or to a name that can
            // never exist — and a plugin that silently never receives anything is the hardest kind of bug to
            // find. `HandlePattern::parse` alone is not enough to tell: it validates the character class, so
            // `nonsense` is a legal pattern and a meaningless subscription.
            let entry = handle.event.as_str();
            let is_known_host_event = synra_protocol::event::builtin::ALL.contains(&entry)
                || synra_protocol::event::events::ALL.contains(&entry);
            let is_own_event = declared.contains(entry);
            let is_host_pattern =
                entry.starts_with(synra_protocol::event::SYSTEM_PREFIX) || entry.starts_with("device.");
            let is_own_pattern = entry.starts_with(&namespace);
            let is_legal_pattern = synra_protocol::inbound::HandlePattern::parse(entry).is_ok();

            let acceptable = is_known_host_event
                || is_own_event
                || ((is_host_pattern || is_own_pattern) && is_legal_pattern);

            if !acceptable {
                return Err(ManifestError::BadHandle { event: handle.event.clone() });
            }
        }
        Ok(())
    }

    /// Whether the network declaration and the network capabilities agree.
    ///
    /// The declaration exists so the consent screen can say "read from api.github.com" rather than "use the
    /// network". Two lists that disagree produce a screen showing one thing and a plugin holding another, which
    /// is worse than either list alone.
    fn check_network(
        &self,
        capabilities: &synra_capability::CapabilitySet,
    ) -> Result<(), ManifestError> {
        let declared_hosts: Vec<&str> = self
            .network
            .as_ref()
            .map(|network| network.outbound.iter().map(|host| host.host.as_str()).collect())
            .unwrap_or_default();

        // Every declared host must be covered by a `network:fetch:<host>` capability.
        for host in &declared_hosts {
            let capability = Capability::parse(&format!("network:fetch:{host}"));
            let covered = capability.map(|cap| capabilities.contains(&cap)).unwrap_or(false);
            if !covered {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "{host:?} is declared as reachable but no `network:fetch:{host}` capability backs it"
                    ),
                });
            }
        }

        // And every `network:fetch:<host>` capability must be described, unless it is a wildcard — a wildcard
        // has no finite description, which is exactly why the design document says the interface must spell it
        // out as "any website" rather than pretending otherwise.
        for capability in capabilities.iter() {
            if capability.domain() != Domain::Network {
                continue;
            }
            let resource = capability
                .prefixes()
                .first()
                .map(synra_capability::Segment::as_str)
                .unwrap_or_default();
            if resource != "fetch" {
                continue;
            }
            let Some(host) = capability.qualifier().first().map(synra_capability::Segment::as_str) else {
                continue;
            };
            if host.contains('*') {
                continue;
            }
            if !declared_hosts.contains(&host) {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "the capability `network:fetch:{host}` is declared but {host:?} is not in \
                         `network.outbound`"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Page keys.
    fn check_pages(&self) -> Result<(), ManifestError> {
        let mut keys = HashSet::new();
        for page in &self.pages {
            if !keys.insert(page.key.as_str()) {
                return Err(ManifestError::DuplicatePageKey { key: page.key.clone() });
            }
        }
        if self.pages.is_empty() {
            return Ok(());
        }
        // A headless plugin has no interface to put a page in.
        if !self.has_ui() {
            return Err(ManifestError::UnusableCapability {
                cap: "ui:page".to_owned(),
                kind: "headless",
            });
        }
        if let Some(default_page) = self.runtime.ui.as_ref().and_then(|ui| ui.default_page.as_deref())
            && !keys.contains(default_page)
        {
            return Err(ManifestError::Malformed(format!(
                "the default page {default_page:?} is not one of the declared pages"
            )));
        }
        Ok(())
    }

    /// Composition cycles.
    ///
    /// A plugin naming itself is the cycle that matters most, because it is the one an author writes by
    /// accident when copying a template. A cycle between two plugins is the loader's business, since it can see
    /// the whole set; this catches the part that is visible from one file.
    fn check_composition(&self) -> Result<(), ManifestError> {
        for dependency in &self.compose {
            if dependency.id == self.id {
                return Err(ManifestError::CompositionCycle {
                    through: vec![self.id.to_string()],
                });
            }
            check_version(dependency.version.trim_start_matches(['^', '~', '=', '>', '<', ' ']))?;
        }
        Ok(())
    }

    /// The length limits on strings that reach the interface.
    fn check_size_limits(&self) -> Result<(), ManifestError> {
        check_len("title", &self.title, MAX_TITLE_LEN)?;
        if let Some(description) = &self.description {
            check_len("description", description, MAX_DESCRIPTION_LEN)?;
        }
        for action in &self.actions {
            check_len("action name", &action.name, MAX_NAME_LEN)?;
        }
        for page in &self.pages {
            check_len("page title", &page.title, MAX_TITLE_LEN)?;
        }
        Ok(())
    }

    /// The SDK and WIT compatibility checks.
    fn check_versions(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        if let Some(host) = &context.host_sdk
            && compare_versions(&self.sdk.min, host)? == core::cmp::Ordering::Greater
        {
            return Err(ManifestError::SdkTooOld {
                min: self.sdk.min.clone(),
                host: host.clone(),
            });
        }
        if let Some(host_wit) = &context.host_wit
            && self.wit != *host_wit
        {
            return Err(ManifestError::WitMismatch {
                plugin: self.wit.clone(),
                host: host_wit.clone(),
            });
        }
        Ok(())
    }

    /// Whether the declarations and the implementation agree, in both directions.
    const fn check_implementation(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        let Some(implementation) = context.implementation else {
            return Ok(());
        };

        if !self.handles.is_empty() && !implementation.on_event {
            return Err(ManifestError::MissingImplementation { declared: "`handles`" });
        }
        if self.handles.is_empty() && implementation.on_event {
            return Err(ManifestError::UndeclaredImplementation { implemented: "on_event" });
        }

        // An interface-only plugin's actions run in the interface, so `execute` is about the headless half.
        if !self.actions.is_empty() && self.is_headless() && !implementation.execute {
            return Err(ManifestError::MissingImplementation { declared: "`actions`" });
        }
        if self.actions.is_empty() && implementation.execute {
            return Err(ManifestError::UndeclaredImplementation { implemented: "execute" });
        }
        Ok(())
    }
}

/// Checks a string's length.
fn check_len(field: &'static str, value: &str, max: usize) -> Result<(), ManifestError> {
    let len = value.chars().count();
    if len > max {
        return Err(ManifestError::TooLong { field, len, max });
    }
    Ok(())
}

/// Checks an event's payload schema is one the host can enforce.
///
/// The rules are about what the *host* can do, not about JSON Schema in general. A payload is validated on
/// every inbound message, so the validator is deliberately small: no `$ref` to follow, no `format` needing a
/// library, no regex to run, and every bound a literal. A schema using something outside that subset is
/// refused rather than partially honoured, because a partial check is a promise the receiving side believes.
fn check_payload_schema(name: &str, payload: &serde_json::Value) -> Result<(), ManifestError> {
    let bad = |detail: &str| ManifestError::BadPayloadSchema {
        name: name.to_owned(),
        detail: detail.to_owned(),
    };

    let Some(object) = payload.as_object() else {
        return Err(bad("a payload schema must be a JSON object"));
    };

    // A top-level object, because a payload that is not an object cannot carry named fields and the wire
    // format's `payload` is an object everywhere else.
    match object.get("type").and_then(|value| value.as_str()) {
        Some("object") => {}
        Some(other) => return Err(bad(&format!("a payload schema must have type `object`, not {other:?}"))),
        None => {
            // `properties` without `type` is a common shorthand, and accepting it would mean two spellings of
            // one schema that the validator would have to keep in step.
            if object.contains_key("properties") {
                return Err(bad("a payload schema with `properties` must also say `type: object`"));
            }
            return Err(bad("a payload schema must say `type: object`"));
        }
    }

    walk_schema(&bad, payload, 0)?;
    Ok(())
}

/// Walks a schema, rejecting anything the host's validator cannot enforce.
fn walk_schema(bad: &impl Fn(&str) -> ManifestError, node: &serde_json::Value, depth: usize) -> Result<(), ManifestError> {
    // A schema is data, so it can be nested arbitrarily. Bounded because the loader walks it on every install
    // and a deeply nested one is either a mistake or an attempt to make the walk expensive.
    const MAX_DEPTH: usize = 16;
    if depth > MAX_DEPTH {
        return Err(bad(&format!("a payload schema nests deeper than {MAX_DEPTH} levels")));
    }

    match node {
        serde_json::Value::Object(object) => {
            for key in ["$ref", "format", "pattern", "patternProperties", "unevaluatedProperties"] {
                if object.contains_key(key) {
                    // `$ref` would need an external document, `format` a library, `pattern` a regex engine.
                    // Each is a validator the host does not have, so honouring the rest of the schema while
                    // ignoring it would be a partial check reported as a complete one.
                    return Err(bad(&format!("`{key}` is not supported in a payload schema")));
                }
            }

            // Numeric bounds must be literal numbers, so the validator never has to resolve anything.
            for key in ["maxLength", "minLength", "maximum", "minimum", "maxItems", "minItems"] {
                if let Some(value) = object.get(key)
                    && !value.is_number()
                {
                    return Err(bad(&format!("`{key}` must be a number")));
                }
            }

            // A string without a `maxLength` is a string whose length the host cannot bound, which makes it a
            // string the payload validator cannot promise anything about.
            if object.get("type").and_then(|value| value.as_str()) == Some("string")
                && !object.contains_key("maxLength")
            {
                return Err(bad("a string property must declare `maxLength`"));
            }

            for (key, value) in object {
                walk_schema(bad, value, depth + 1)?;
                let _ = key;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk_schema(bad, item, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// A minimal manifest that passes every check, so a test can change one thing.
    const MINIMAL: &str = r#"{
        "id": "@synra-plugin/chat",
        "version": "1.0.0",
        "title": "Chat",
        "publisher": { "id": "synra-official" },
        "sdk": { "min": "1.0.0" },
        "wit": "synra:plugin@1.0.0",
        "runtime": { "headless": { "artifact": "dist/plugin.wasm", "stateful": false } },
        "capabilities": [{ "cap": "log:*" }]
    }"#;

    fn parse(text: &str) -> Manifest {
        Manifest::from_json(text).expect("the fixture parses")
    }

    fn minimal() -> Manifest {
        parse(MINIMAL)
    }

    // ── Parsing ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_minimal_manifest_parses_and_validates() {
        let manifest = minimal();
        assert_eq!(manifest.id.as_str(), "@synra-plugin/chat");
        assert_eq!(manifest.title, "Chat");
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
        assert!(manifest.is_headless());
        assert!(!manifest.has_ui());
        assert!(!manifest.is_hybrid());
    }

    #[test]
    fn the_schema_field_is_normalised_and_an_unknown_one_is_refused() {
        let manifest = minimal();
        assert_eq!(manifest.schema.as_deref(), Some(MANIFEST_SCHEMA));

        // A manifest naming a schema this build does not know may have fields whose meaning changed, and the
        // unknown-field rule would not catch a field that kept its name.
        let wrong = MINIMAL.replace("\"id\":", "\"$schema\": \"https://example.com/v9.json\", \"id\":");
        assert!(matches!(Manifest::from_json(&wrong), Err(ManifestError::Malformed(_))));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // A field the host silently ignores is a field whose author believes it does something.
        let text = MINIMAL.replace("\"title\": \"Chat\",", "\"title\": \"Chat\", \"mystery\": true,");
        assert!(matches!(Manifest::from_json(&text), Err(ManifestError::Malformed(_))));
    }

    #[test]
    fn a_missing_required_field_is_refused() {
        for field in ["\"id\": \"@synra-plugin/chat\",", "\"version\": \"1.0.0\",", "\"capabilities\": [{ \"cap\": \"log:*\" }]"] {
            let text = MINIMAL.replace(field, "");
            assert!(Manifest::from_json(&text).is_err(), "removing {field} should fail");
        }
    }

    #[test]
    fn capabilities_may_be_an_empty_list_but_the_field_must_be_present() {
        // A missing field and an empty list are different statements — "the author forgot" and "this plugin
        // needs nothing" — and the loader has to be able to tell them apart.
        let empty = MINIMAL.replace("\"capabilities\": [{ \"cap\": \"log:*\" }]", "\"capabilities\": []");
        let manifest = parse(&empty);
        assert!(manifest.capabilities.is_empty());
        assert!(manifest.capability_set().expect("compiles").is_empty());

        let missing = MINIMAL.replace(",\n        \"capabilities\": [{ \"cap\": \"log:*\" }]", "");
        assert!(Manifest::from_json(&missing).is_err());
    }

    #[test]
    fn optional_arrays_are_absent_rather_than_empty() {
        let manifest = minimal();
        assert!(manifest.actions.is_empty());
        assert!(manifest.events.is_empty());
        assert!(manifest.handles.is_empty());
        assert!(manifest.pages.is_empty());
        assert!(manifest.network.is_none());

        // And a round trip does not turn them into empty arrays, so two manifests of the same plugin compare
        // equal.
        let json = serde_json::to_string(&manifest).expect("serialises");
        assert!(!json.contains("\"actions\""), "{json}");
    }

    // ── Ids and slugs ─────────────────────────────────────────────────────────────────────────────

    #[rstest]
    #[case("@synra-plugin/chat", "chat")]
    #[case("@imba97/synra-plugin-notes", "notes")]
    #[case("@my-scope/thing", "thing")]
    #[case("@a1/b2", "b2")]
    fn a_slug_is_the_name_without_the_official_prefix(#[case] id: &str, #[case] expected: &str) {
        let id = PluginId::parse(id).expect("valid id");
        assert_eq!(to_wire_slug(&id).expect("has a slug"), expected);
    }

    #[test]
    fn an_id_with_no_usable_slug_is_refused() {
        // A plugin whose events would live under `_plugin..` is one nobody can declare a handler for.
        let id = PluginId::parse("@scope/synra-plugin-").expect("parses as a string");
        assert!(matches!(to_wire_slug(&id), Err(ManifestError::UnsluggedId { .. })));
    }

    #[rstest]
    #[case("@synra-plugin/chat", true)]
    #[case("@imba97/synra-plugin-notes", true)]
    #[case("@a1/b2", true)]
    #[case("chat", false)]
    #[case("@synra/chat", false)]
    #[case("@core/chat", false)]
    #[case("@system/chat", false)]
    #[case("@a/chat", false)]
    #[case("@Synra-Plugin/chat", false)]
    #[case("@synra-plugin/Chat", false)]
    #[case("@synra-plugin/", false)]
    #[case("@synra-plugin/a b", false)]
    fn plugin_ids_are_checked_against_the_grammar(#[case] id: &str, #[case] ok: bool) {
        assert_eq!(check_plugin_id(id).is_ok(), ok, "{id}");
    }

    #[test]
    fn a_reserved_scope_says_so() {
        match check_plugin_id("@core/chat") {
            Err(ManifestError::BadId { reason, .. }) => assert!(reason.contains("reserved"), "{reason}"),
            other => panic!("expected a reserved-scope refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_id_too_long_for_its_grammar_is_refused() {
        let long_scope = format!("@{}/chat", "a".repeat(40));
        assert!(check_plugin_id(&long_scope).is_err());
        let long_name = format!("@synra-plugin/{}", "a".repeat(65));
        assert!(check_plugin_id(&long_name).is_err());
        // Exactly at each limit is fine.
        assert!(check_plugin_id(&format!("@{}/chat", "a".repeat(39))).is_ok());
        assert!(check_plugin_id(&format!("@synra-plugin/{}", "a".repeat(64))).is_ok());
    }

    // ── Versions ──────────────────────────────────────────────────────────────────────────────────

    #[rstest]
    #[case("1.0.0")]
    #[case("0.0.0")]
    #[case("10.20.30")]
    #[case("1.0.0-rc.1")]
    #[case("1.0.0-alpha")]
    #[case("1.0.0+build.1")]
    #[case("1.0.0-rc.1+build.2")]
    fn legal_versions_are_accepted(#[case] version: &str) {
        assert_eq!(check_version(version), Ok(()), "{version}");
    }

    #[rstest]
    #[case("1.0")]
    #[case("1")]
    #[case("1.0.0.0")]
    #[case("v1.0.0")]
    #[case("01.0.0")]
    #[case("1.0.0-")]
    #[case("1.0.0+")]
    #[case("1.0.0-rc..1")]
    #[case("")]
    #[case("one.two.three")]
    fn illegal_versions_are_refused(#[case] version: &str) {
        assert!(check_version(version).is_err(), "{version} should not parse");
    }

    #[test]
    fn versions_compare_by_their_parts() {
        use core::cmp::Ordering;
        assert_eq!(compare_versions("1.0.0", "1.0.0").expect("ok"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0.0").expect("ok"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.1.0").expect("ok"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.99.99").expect("ok"), Ordering::Greater);
    }

    #[test]
    fn a_prerelease_sorts_below_its_release() {
        // Getting this backwards would let a release candidate satisfy a minimum that the release was written
        // for, so a plugin would be installed and then fail on a function that is not in the RC.
        use core::cmp::Ordering;
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0").expect("ok"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0.0-rc.1").expect("ok"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0-rc.2").expect("ok"), Ordering::Less);
        // Numeric identifiers compare numerically, not as strings: `rc.10` is above `rc.9`.
        assert_eq!(compare_versions("1.0.0-rc.10", "1.0.0-rc.9").expect("ok"), Ordering::Greater);
        // Fewer identifiers is lower.
        assert_eq!(compare_versions("1.0.0-rc", "1.0.0-rc.1").expect("ok"), Ordering::Less);
        // A numeric identifier is below an alphanumeric one.
        assert_eq!(compare_versions("1.0.0-1", "1.0.0-alpha").expect("ok"), Ordering::Less);
    }

    #[test]
    fn comparing_an_illegal_version_is_an_error_not_an_ordering() {
        assert!(compare_versions("1.0", "1.0.0").is_err());
        assert!(compare_versions("1.0.0", "nonsense").is_err());
    }

    // ── Runtime ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_must_declare_a_runtime() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": {}",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::NoRuntime)
        ));
    }

    #[test]
    fn a_ui_only_plugin_is_recognised() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
        );
        // And its `log:*` capability is fine, because a UI plugin runs in the interface and can still log.
        let manifest = parse(&text);
        assert!(manifest.has_ui());
        assert!(!manifest.is_headless());
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
    }

    #[test]
    fn a_hybrid_plugin_is_recognised() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \
                \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \
                \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
        );
        let manifest = parse(&text);
        assert!(manifest.is_hybrid());
    }

    #[test]
    fn a_missing_artifact_is_reported_when_the_package_is_known() {
        let context = ManifestContext {
            present_artifacts: Some(vec!["dist/other.wasm".to_owned()]),
            ..ManifestContext::default()
        };
        match minimal().validate(ValidationLevel::Schema, &context) {
            Err(ManifestError::MissingArtifact { kind, path }) => {
                assert_eq!(kind, "headless");
                assert_eq!(path, "dist/plugin.wasm");
            }
            other => panic!("expected a missing artifact, got {other:?}"),
        }
    }

    #[test]
    fn a_present_artifact_passes_that_check() {
        let context = ManifestContext {
            present_artifacts: Some(vec!["dist/plugin.wasm".to_owned()]),
            ..ManifestContext::default()
        };
        assert_eq!(minimal().validate(ValidationLevel::Schema, &context), Ok(()));
    }

    #[test]
    fn an_empty_ui_entry_is_refused() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"  \" } }",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    // ── Capabilities ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_malformed_capability_is_refused_and_names_itself() {
        let text = MINIMAL.replace("\"log:*\"", "\"not a capability\"");
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::BadCapability { cap, .. }) => assert_eq!(cap, "not a capability"),
            other => panic!("expected a capability error, got {other:?}"),
        }
    }

    #[test]
    fn a_headless_plugin_may_not_declare_ui_capabilities() {
        // A `ui:*` grant on a headless plugin is one the user approves at install time and that nothing can
        // ever exercise: the consent screen said something untrue.
        let text = MINIMAL.replace(
            "[{ \"cap\": \"log:*\" }]",
            "[{ \"cap\": \"log:*\" }, { \"cap\": \"ui:page\" }]",
        );
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::UnusableCapability { cap, kind }) => {
                assert_eq!(cap, "ui:page");
                assert_eq!(kind, "headless");
            }
            other => panic!("expected an unusable capability, got {other:?}"),
        }
    }

    #[test]
    fn a_ui_plugin_may_declare_ui_capabilities() {
        let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
            )
            .replace(
                "[{ \"cap\": \"log:*\" }]",
                "[{ \"cap\": \"log:*\" }, { \"cap\": \"ui:page\" }]",
            );
        assert_eq!(
            parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_declared_pages_list_on_a_headless_plugin_is_refused() {
        // There is no interface to put a page in.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"pages\": [{ \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_duplicate_page_key_is_refused() {
        let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
            )
            .replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                "\"capabilities\": [{ \"cap\": \"log:*\" }], \"pages\": [\
                 { \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }, \
                 { \"key\": \"home\", \"title\": \"Again\", \"path\": \"/again\" }]",
            );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::DuplicatePageKey { key }) if key == "home"
        ));
    }

    #[test]
    fn a_default_page_that_is_not_declared_is_refused() {
        let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\", \
                 \"defaultPage\": \"missing\" } }",
            )
            .replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                "\"capabilities\": [{ \"cap\": \"log:*\" }], \
                 \"pages\": [{ \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }]",
            );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    // ── Events ────────────────────────────────────────────────────────────────────────────────────

    /// The minimal manifest with one event declared.
    fn with_event(name: &str) -> Manifest {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"{name}\", \
                 \"payload\": {{ \"type\": \"object\", \"properties\": {{}}, \
                 \"additionalProperties\": false }} }}]"
            ),
        );
        parse(&text)
    }

    #[test]
    fn an_event_in_the_plugins_own_namespace_is_accepted() {
        let manifest = with_event("_plugin.chat.text");
        assert_eq!(manifest.event_namespace().expect("has one"), "_plugin.chat.");
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
    }

    #[test]
    fn an_event_in_another_plugins_namespace_is_refused() {
        // The check that stops one plugin emitting under another's name, which a receiving side would route as
        // a legitimate message with nothing in any log to say otherwise.
        let manifest = with_event("_plugin.notes.text");
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::ForeignEventNamespace { name, namespace }) => {
                assert_eq!(name, "_plugin.notes.text");
                assert_eq!(namespace, "_plugin.chat.");
            }
            other => panic!("expected a namespace refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_event_outside_any_plugin_namespace_is_refused() {
        for name in ["_synra.device.changed", "device.ping", "chat.text"] {
            let manifest = with_event(name);
            assert!(
                manifest
                    .validate(ValidationLevel::Schema, &ManifestContext::default())
                    .is_err(),
                "{name} should be refused"
            );
        }
    }

    #[test]
    fn the_namespace_prefix_alone_is_not_an_event() {
        // `_plugin.chat.` names nothing, and accepting it would make an event whose logical name is empty.
        let manifest = with_event("_plugin.chat.");
        assert!(manifest
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_duplicate_event_name_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [\
             { \"name\": \"_plugin.chat.text\", \"payload\": { \"type\": \"object\" } }, \
             { \"name\": \"_plugin.chat.text\", \"payload\": { \"type\": \"object\" } }]",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::DuplicateName { kind: "event", .. })
        ));
    }

    #[test]
    fn an_event_may_declare_no_payload() {
        // An event that is only a notification has nothing to carry, and requiring a schema would make authors
        // write `{"type":"object","properties":{}}` to say nothing.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"events\": [{ \"name\": \"_plugin.chat.ping\" }]",
        );
        assert_eq!(
            parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Payload schemas ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_payload_schema_must_be_a_top_level_object() {
        for payload in [
            r#"{ "type": "array" }"#,
            r#"{ "type": "string", "maxLength": 10 }"#,
            r#"{ "properties": {} }"#,
            r#"[1, 2]"#,
        ] {
            let text = MINIMAL.replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                &format!(
                    "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                     \"events\": [{{ \"name\": \"_plugin.chat.text\", \"payload\": {payload} }}]"
                ),
            );
            let manifest = parse(&text);
            assert!(
                matches!(
                    manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                    Err(ManifestError::BadPayloadSchema { .. })
                ),
                "{payload} should be refused for its shape"
            );
        }
    }

    #[rstest]
    #[case(r##"{ "type": "object", "properties": { "a": { "$ref": "#/x" } } }"##, "$ref")]
    #[case(r#"{ "type": "object", "properties": { "a": { "type": "string", "format": "email", "maxLength": 5 } } }"#, "format")]
    #[case(r#"{ "type": "object", "properties": { "a": { "type": "string", "pattern": "^x$", "maxLength": 5 } } }"#, "pattern")]
    #[case(r#"{ "type": "object", "patternProperties": {} }"#, "patternProperties")]
    fn a_schema_using_something_the_host_cannot_enforce_is_refused(#[case] payload: &str, #[case] needle: &str) {
        // Each is a validator the host does not have, so honouring the rest while ignoring it would be a
        // partial check reported as a complete one.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"_plugin.chat.text\", \"payload\": {payload} }}]"
            ),
        );
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::BadPayloadSchema { detail, .. }) => {
                assert!(detail.contains(needle), "{detail} does not mention {needle}");
            }
            other => panic!("expected a schema refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_string_property_must_be_bounded() {
        // A string with no `maxLength` is one whose length the host cannot bound, so the payload validator
        // cannot promise anything about it — and the promise is what the receiving side trusted.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [{ \"name\": \"_plugin.chat.text\", \
             \"payload\": { \"type\": \"object\", \"properties\": { \"body\": { \"type\": \"string\" } } } }]",
        );
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::BadPayloadSchema { detail, .. }) => {
                assert!(detail.contains("maxLength"), "{detail}");
            }
            other => panic!("expected a bounds refusal, got {other:?}"),
        }

        // With the bound, it passes.
        let bounded = text.replace("\"type\": \"string\"", "\"type\": \"string\", \"maxLength\": 65536");
        assert_eq!(
            parse(&bounded).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_non_numeric_bound_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [{ \"name\": \"_plugin.chat.text\", \
             \"payload\": { \"type\": \"object\", \"properties\": { \"body\": \
             { \"type\": \"string\", \"maxLength\": \"lots\" } } } }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_deeply_nested_payload_schema_is_refused() {
        // Either a mistake or an attempt to make the loader's walk expensive.
        let mut nested = String::from(r#"{ "type": "object", "properties": { "a": "#);
        for _ in 0..20 {
            nested = format!("{nested} {{ \"type\": \"object\", \"properties\": {{ \"a\": ");
        }
        nested.push_str("{}");
        for _ in 0..21 {
            nested.push_str(" } }");
        }
        nested.push_str(" }");

        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"_plugin.chat.text\", \"payload\": {nested} }}]"
            ),
        );
        // Parsing may fail first if the fixture is malformed; either way it is refused rather than walked.
        if let Ok(manifest) = Manifest::from_json(&text) {
            assert!(
                manifest
                    .validate(ValidationLevel::Schema, &ManifestContext::default())
                    .is_err(),
                "a deeply nested schema should be refused"
            );
        }
    }

    // ── Handles ───────────────────────────────────────────────────────────────────────────────────

    /// The minimal manifest with the given `handles` entries.
    fn with_handles(entries: &str) -> Manifest {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!("\"capabilities\": [{{ \"cap\": \"log:*\" }}], \"handles\": [{entries}]"),
        );
        parse(&text)
    }

    #[test]
    fn a_known_host_event_may_be_handled() {
        for event in [
            "_synra.transfer.completed",
            "_synra.device.changed",
            "_synra.share.received",
        ] {
            let manifest = with_handles(&format!("{{ \"event\": \"{event}\" }}"));
            assert_eq!(
                manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                Ok(()),
                "{event}"
            );
        }
    }

    #[test]
    fn a_plugin_may_handle_its_own_declared_event() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"events\": [{ \"name\": \"_plugin.chat.text\" }], \
             \"handles\": [{ \"event\": \"_plugin.chat.text\" }]",
        );
        assert_eq!(
            parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_wildcard_handle_is_accepted_by_its_grammar() {
        for pattern in ["_plugin.chat.*", "_synra.*", "_synra.device.*"] {
            let manifest = with_handles(&format!("{{ \"event\": \"{pattern}\" }}"));
            assert_eq!(
                manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                Ok(()),
                "{pattern}"
            );
        }
    }

    #[test]
    fn a_handle_that_can_never_fire_is_refused() {
        // A plugin that silently never receives anything is the hardest kind of bug to find.
        for entry in ["", "nonsense", "not-an-event", "_unknown.thing"] {
            let manifest = with_handles(&format!("{{ \"event\": \"{entry}\" }}"));
            assert!(
                matches!(
                    manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                    Err(ManifestError::BadHandle { .. })
                ),
                "{entry:?} should be refused"
            );
        }
    }

    #[test]
    fn a_handle_may_carry_a_condition() {
        let manifest = with_handles(
            "{ \"event\": \"_synra.transfer.completed\", \"match\": { \"kind\": \"attachment\" } }",
        );
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Network ───────────────────────────────────────────────────────────────────────────────────

    /// The minimal manifest with network declarations.
    fn with_network(hosts: &str, capabilities: &str) -> Manifest {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{capabilities}], \
                 \"network\": {{ \"outbound\": [{hosts}] }}"
            ),
        );
        parse(&text)
    }

    #[test]
    fn a_declared_host_without_a_capability_is_refused() {
        // Two lists that disagree produce a consent screen showing one thing and a plugin holding another.
        let manifest = with_network(
            "{ \"host\": \"api.github.com\" }",
            "{ \"cap\": \"network:fetch:api.github.com\" }",
        );
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );

        let mismatched = with_network(
            "{ \"host\": \"api.github.com\" }",
            "{ \"cap\": \"network:fetch:api.x.com\" }",
        );
        assert!(matches!(
            mismatched.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn a_capability_without_a_declared_host_is_refused() {
        let manifest = with_network(
            "{ \"host\": \"api.x.com\" }",
            "{ \"cap\": \"network:fetch:api.x.com\" }, { \"cap\": \"network:fetch:api.y.com\" }",
        );
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::NetworkMismatch { detail }) => {
                assert!(detail.contains("api.y.com"), "{detail}");
            }
            other => panic!("expected a network mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_wildcard_capability_needs_no_declared_host() {
        // A wildcard has no finite description, which is exactly why the interface spells it out as "any
        // website" rather than pretending a list covers it.
        let manifest = with_network("{ \"host\": \"api.x.com\" }", "{ \"cap\": \"network:fetch:*\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_wildcard_declared_host_needs_its_capability() {
        let manifest = with_network(
            "{ \"host\": \"*.example.com\", \"methods\": [\"GET\"] }",
            "{ \"cap\": \"network:fetch:*.example.com\" }",
        );
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_non_fetch_network_capability_needs_no_declared_host() {
        // `network:websocket` is not a host-scoped grant, so the two lists say nothing about each other.
        let manifest = with_network("{ \"host\": \"api.x.com\" }", "{ \"cap\": \"network:websocket\" }, { \"cap\": \"network:fetch:api.x.com\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_network_capability_with_no_qualifier_needs_no_declared_host() {
        let manifest = with_network("{ \"host\": \"api.x.com\" }", "{ \"cap\": \"network:fetch:api.x.com\" }, { \"cap\": \"network:fetch\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Implementation ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn handles_without_on_event_is_refused() {
        // A plugin that is installed, appears to work, and silently drops every message it asked for.
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        let context = ManifestContext {
            implementation: Some(Implementation::default()),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Verify, &context) {
            Err(ManifestError::MissingImplementation { declared }) => assert_eq!(declared, "`handles`"),
            other => panic!("expected a missing implementation, got {other:?}"),
        }
    }

    #[test]
    fn on_event_without_handles_is_refused() {
        // Dead code, and a sign that the manifest and the implementation have drifted apart — at which point no
        // other declaration can be trusted either.
        let manifest = minimal();
        let context = ManifestContext {
            implementation: Some(Implementation { on_event: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Verify, &context) {
            Err(ManifestError::UndeclaredImplementation { implemented }) => {
                assert_eq!(implemented, "on_event");
            }
            other => panic!("expected an undeclared implementation, got {other:?}"),
        }
    }

    #[test]
    fn a_declaration_and_its_implementation_agreeing_passes() {
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        let context = ManifestContext {
            implementation: Some(Implementation { on_event: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        assert_eq!(manifest.validate(ValidationLevel::Verify, &context), Ok(()));
    }

    #[test]
    fn actions_without_execute_is_refused_for_a_headless_plugin() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"actions\": [{ \"name\": \"send-message\" }]",
        );
        let manifest = parse(&text);
        let context = ManifestContext {
            implementation: Some(Implementation::default()),
            ..ManifestContext::default()
        };
        assert!(matches!(
            manifest.validate(ValidationLevel::Verify, &context),
            Err(ManifestError::MissingImplementation { declared }) if declared == "`actions`"
        ));

        let with_execute = ManifestContext {
            implementation: Some(Implementation { execute: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        assert_eq!(manifest.validate(ValidationLevel::Verify, &with_execute), Ok(()));
    }

    #[test]
    fn execute_without_actions_is_refused() {
        let manifest = minimal();
        let context = ManifestContext {
            implementation: Some(Implementation { execute: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        assert!(manifest.validate(ValidationLevel::Verify, &context).is_err());
    }

    #[test]
    fn the_schema_level_skips_the_implementation_checks() {
        // The CLI has the source tree but not a parsed module, so a check that needs one cannot be in this
        // level — and a level that reported a failure it could not see would be worse than not checking.
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        let context = ManifestContext {
            implementation: Some(Implementation::default()),
            ..ManifestContext::default()
        };
        assert_eq!(manifest.validate(ValidationLevel::Schema, &context), Ok(()));
        assert!(manifest.validate(ValidationLevel::Verify, &context).is_err());
    }

    #[test]
    fn a_missing_implementation_context_skips_the_check_rather_than_failing() {
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Verify, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Versions and WIT ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_needing_a_newer_sdk_than_the_host_is_refused_with_both_versions() {
        let manifest = parse(&MINIMAL.replace("\"min\": \"1.0.0\"", "\"min\": \"9.0.0\""));
        let context = ManifestContext {
            host_sdk: Some("1.2.0".to_owned()),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Schema, &context) {
            Err(ManifestError::SdkTooOld { min, host }) => {
                assert_eq!(min, "9.0.0");
                assert_eq!(host, "1.2.0");
            }
            other => panic!("expected an SDK refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plugin_the_host_satisfies_is_accepted() {
        let manifest = minimal();
        let context = ManifestContext { host_sdk: Some("1.0.0".to_owned()), ..ManifestContext::default() };
        assert_eq!(manifest.validate(ValidationLevel::Schema, &context), Ok(()));

        // A host above the minimum is fine, including one where the plugin's minimum is a pre-release of it.
        let below = parse(&MINIMAL.replace("\"min\": \"1.0.0\"", "\"min\": \"1.0.0-rc.1\""));
        assert_eq!(below.validate(ValidationLevel::Schema, &context), Ok(()));
    }

    #[test]
    fn a_wit_mismatch_names_both_worlds() {
        let manifest = minimal();
        let context = ManifestContext {
            host_wit: Some("synra:plugin@2.0.0".to_owned()),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Schema, &context) {
            Err(ManifestError::WitMismatch { plugin, host }) => {
                assert_eq!(plugin, "synra:plugin@1.0.0");
                assert_eq!(host, "synra:plugin@2.0.0");
            }
            other => panic!("expected a WIT refusal, got {other:?}"),
        }
    }

    // ── Composition and names ─────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_that_composes_with_itself_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"compose\": [{ \"id\": \"@synra-plugin/chat\", \"version\": \"^1.0.0\" }]",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::CompositionCycle { .. })
        ));
    }

    #[test]
    fn a_dependency_with_a_bad_version_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"compose\": [{ \"id\": \"@synra-plugin/format\", \"version\": \"latest\" }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_dependency_range_is_accepted_with_its_operator() {
        for range in ["^1.0.0", "~1.2.0", "=1.0.0", ">=1.0.0"] {
            let text = MINIMAL.replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                &format!(
                    "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                     \"compose\": [{{ \"id\": \"@synra-plugin/format\", \"version\": \"{range}\" }}]"
                ),
            );
            assert_eq!(
                parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
                Ok(()),
                "{range}"
            );
        }
    }

    #[test]
    fn a_duplicate_action_name_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"actions\": [\
             { \"name\": \"send\" }, { \"name\": \"send\" }]",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::DuplicateName { kind: "action", .. })
        ));
    }

    #[test]
    fn an_action_with_an_empty_name_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"actions\": [{ \"name\": \"\" }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn length_limits_are_enforced_on_what_the_interface_draws() {
        // A title of a thousand characters pushes everything else off the screen.
        let long = "x".repeat(MAX_TITLE_LEN + 1);
        let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{long}\""));
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::TooLong { field, len, max }) => {
                assert_eq!(field, "title");
                assert_eq!(len, MAX_TITLE_LEN + 1);
                assert_eq!(max, MAX_TITLE_LEN);
            }
            other => panic!("expected a length refusal, got {other:?}"),
        }

        // Exactly at the limit is fine.
        let exact = "x".repeat(MAX_TITLE_LEN);
        let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{exact}\""));
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_ok());
    }

    #[test]
    fn a_long_title_is_measured_in_characters_not_bytes() {
        // A CJK title of the same character count is not "too long" in a unit the user cannot see.
        let cjk = "电".repeat(MAX_TITLE_LEN);
        let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{cjk}\""));
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_ok());
    }

    // ── Localisation ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_localised_title_is_chosen_by_tag_with_a_fallback_chain() {
        let text = MINIMAL.replace(
            "\"title\": \"Chat\"",
            "\"title\": \"Chat\", \"description\": \"Cross-device chat\", \"locales\": { \
             \"zh-CN\": { \"title\": \"聊天\", \"description\": \"跨设备聊天\" }, \
             \"zh\": { \"title\": \"中文\" }, \
             \"en\": { \"title\": \"Chat!\" } }",
        );
        let manifest = parse(&text);

        assert_eq!(manifest.localised_title("zh-CN"), "聊天", "an exact match wins");
        assert_eq!(manifest.localised_title("en"), "Chat!");
        // The chain shortens the *reader's* tag: `zh-Hans-CN` looks for itself, then for `zh`. It does not
        // extend the manifest's, so a manifest declaring only `zh-CN` would not answer here.
        assert_eq!(manifest.localised_title("zh-Hans-CN"), "中文");
        // A language with no entry falls back to the default.
        assert_eq!(manifest.localised_title("fr"), "Chat");
        assert_eq!(manifest.localised_description("fr"), Some("Cross-device chat"));
        assert_eq!(manifest.localised_description("zh-CN"), Some("跨设备聊天"));
        // The `zh` entry has no description, so the reader gets the default rather than an empty string.
        assert_eq!(manifest.localised_description("zh-Hans-CN"), Some("Cross-device chat"));
    }

    #[test]
    fn a_manifest_with_no_locales_uses_its_defaults() {
        let manifest = minimal();
        assert_eq!(manifest.localised_title("zh-CN"), "Chat");
        assert_eq!(manifest.localised_title(""), "Chat");
        assert_eq!(manifest.localised_description("zh-CN"), None);
    }

    #[test]
    fn a_locale_missing_the_requested_string_falls_through() {
        // A `zh-CN` entry with only a `title` must not make the description disappear.
        let text = MINIMAL.replace(
            "\"title\": \"Chat\"",
            "\"title\": \"Chat\", \"description\": \"Cross-device chat\", \
             \"locales\": { \"zh-CN\": { \"title\": \"聊天\" } }",
        );
        let manifest = parse(&text);
        assert_eq!(manifest.localised_title("zh-CN"), "聊天");
        assert_eq!(manifest.localised_description("zh-CN"), Some("Cross-device chat"));
    }

    // ── Round trip ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_full_manifest_parses_and_survives_a_round_trip() {
        // The example from the design document, so a change to the shape is caught here rather than by an
        // author whose manifest stopped loading.
        let text = r#"{
            "$schema": "https://synra-app.dev/schema/manifest/v1.json",
            "id": "@synra-plugin/chat",
            "version": "1.2.0",
            "title": "Chat",
            "description": "cross-device chat",
            "icon": "assets/icon.svg",
            "publisher": { "id": "synra-official", "name": "Synra Official", "url": "https://synra-app.dev" },
            "license": "MIT",
            "repository": "https://github.com/synra/plugin-chat",
            "sdk": { "min": "1.0.0", "preferred": "1.2.0" },
            "wit": "synra:plugin@1.0.0",
            "runtime": {
                "headless": { "artifact": "dist/plugin.wasm", "stateful": false, "hints": ["cpu-heavy"] },
                "ui": { "artifact": "dist/ui.zip", "entry": "index.html", "defaultPage": "home" }
            },
            "capabilities": [
                { "cap": "log:*" },
                { "cap": "device:list" },
                { "cap": "device:send:*" },
                { "cap": "storage:local:read" },
                { "cap": "event:emit:_plugin.chat.*" },
                { "cap": "ui:page" },
                { "cap": "network:fetch:api.github.com" }
            ],
            "actions": [
                { "name": "send-message",
                  "args": { "type": "object", "required": ["target", "body"],
                            "properties": { "target": { "type": "string", "maxLength": 64 },
                                            "body": { "type": "string", "maxLength": 65536 } } },
                  "returns": { "type": "object", "properties": { "messageId": { "type": "string", "maxLength": 64 } } },
                  "description": "send a message" }
            ],
            "shareHandlers": [{ "kinds": ["text", "url"], "description": "recognise message text" }],
            "events": [
                { "name": "_plugin.chat.text",
                  "payload": { "type": "object", "required": ["body"],
                               "properties": { "body": { "type": "string", "maxLength": 65536 },
                                               "sentAtMs": { "type": "integer" } },
                               "additionalProperties": false } },
                { "name": "_plugin.chat.typing",
                  "payload": { "type": "object", "properties": {}, "additionalProperties": false } }
            ],
            "handles": [
                { "event": "_plugin.chat.*" },
                { "event": "_synra.transfer.completed" },
                { "event": "_synra.device.changed" }
            ],
            "compose": [{ "id": "@synra-plugin/format", "version": "^1.0.0", "optional": false }],
            "network": { "outbound": [{ "host": "api.github.com" }] },
            "pages": [
                { "key": "home", "title": "Chat", "path": "/home", "icon": "chat" },
                { "key": "settings", "title": "Settings", "path": "/settings" }
            ],
            "resources": { "preferredMemoryMb": 32, "preferredTimeoutMs": 2000 },
            "locales": { "zh-CN": { "title": "聊天", "description": "跨设备聊天" } }
        }"#;

        let manifest = parse(text);
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
        assert!(manifest.is_hybrid());
        assert_eq!(manifest.capabilities.len(), 7);
        assert_eq!(manifest.events.len(), 2);
        assert_eq!(manifest.pages.len(), 2);
        assert_eq!(manifest.localised_title("zh-CN"), "聊天");

        let json = serde_json::to_string(&manifest).expect("serialises");
        let back = Manifest::from_json(&json).expect("re-parses");
        assert_eq!(back, manifest);
        // And the capability set compiles, which is what the loader actually uses.
        assert!(manifest.capability_set().expect("compiles").contains(
            &Capability::parse("device:list").expect("valid")
        ));
    }

    #[test]
    fn a_full_manifest_with_its_implementation_verifies() {
        let text = r#"{
            "id": "@synra-plugin/chat",
            "version": "1.0.0",
            "title": "Chat",
            "publisher": { "id": "synra-official" },
            "sdk": { "min": "1.0.0" },
            "wit": "synra:plugin@1.0.0",
            "runtime": {
                "headless": { "artifact": "dist/plugin.wasm", "stateful": false },
                "ui": { "artifact": "dist/ui.zip", "entry": "index.html" }
            },
            "capabilities": [{ "cap": "log:*" }],
            "actions": [{ "name": "send" }],
            "handles": [{ "event": "_synra.device.changed" }]
        }"#;
        let manifest = parse(text);
        let context = ManifestContext {
            host_sdk: Some("1.0.0".to_owned()),
            host_wit: Some("synra:plugin@1.0.0".to_owned()),
            present_artifacts: Some(vec![
                "dist/plugin.wasm".to_owned(),
                "dist/ui.zip".to_owned(),
            ]),
            implementation: Some(Implementation { on_event: true, execute: true, activate: true }),
        };
        assert_eq!(manifest.validate(ValidationLevel::Verify, &context), Ok(()));
    }

    #[test]
    fn every_error_variant_explains_itself() {
        // The loader shows these to a user, so a variant without a sentence is one the interface cannot render.
        let errors = vec![
            ManifestError::Malformed("x".to_owned()),
            ManifestError::BadId { id: "x".to_owned(), reason: "y".to_owned() },
            ManifestError::UnsluggedId { id: "x".to_owned() },
            ManifestError::BadVersion { version: "x".to_owned(), reason: "y".to_owned() },
            ManifestError::NoRuntime,
            ManifestError::MissingArtifact { kind: "headless", path: "x".to_owned() },
            ManifestError::BadCapability {
                cap: "x".to_owned(),
                source: Capability::parse("nope").expect_err("invalid"),
            },
            ManifestError::UnusableCapability { cap: "ui:page".to_owned(), kind: "headless" },
            ManifestError::NetworkMismatch { detail: "x".to_owned() },
            ManifestError::DuplicateName { kind: "action", name: "x".to_owned() },
            ManifestError::ForeignEventNamespace { name: "x".to_owned(), namespace: "y".to_owned() },
            ManifestError::BadPayloadSchema { name: "x".to_owned(), detail: "y".to_owned() },
            ManifestError::BadHandle { event: "x".to_owned() },
            ManifestError::MissingImplementation { declared: "`handles`" },
            ManifestError::UndeclaredImplementation { implemented: "on_event" },
            ManifestError::DuplicatePageKey { key: "x".to_owned() },
            ManifestError::SdkTooOld { min: "9".to_owned(), host: "1".to_owned() },
            ManifestError::WitMismatch { plugin: "a".to_owned(), host: "b".to_owned() },
            ManifestError::CompositionCycle { through: vec!["a".to_owned()] },
            ManifestError::TooLong { field: "title", len: 100, max: 64 },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Version comparison is a total order: irreflexive-equal, antisymmetric and transitive. A comparator
        /// that broke any of those would make an SDK requirement depend on which side it was written on.
        #[test]
        fn version_comparison_is_a_total_order(
            a in (0u64..5, 0u64..5, 0u64..5),
            b in (0u64..5, 0u64..5, 0u64..5),
            c in (0u64..5, 0u64..5, 0u64..5),
        ) {
            let render = |(major, minor, patch): (u64, u64, u64)| format!("{major}.{minor}.{patch}");
            let (a, b, c) = (render(a), render(b), render(c));

            // Reflexive.
            prop_assert_eq!(compare_versions(&a, &a).expect("valid"), core::cmp::Ordering::Equal);

            // Antisymmetric.
            let forward = compare_versions(&a, &b).expect("valid");
            let backward = compare_versions(&b, &a).expect("valid");
            prop_assert_eq!(forward, backward.reverse());

            // Transitive.
            if compare_versions(&a, &b).expect("valid") == core::cmp::Ordering::Less
                && compare_versions(&b, &c).expect("valid") == core::cmp::Ordering::Less
            {
                prop_assert_eq!(
                    compare_versions(&a, &c).expect("valid"),
                    core::cmp::Ordering::Less,
                );
            }
        }

        /// Parsing a manifest is total: arbitrary text either yields a manifest or an error, and never panics.
        /// Manifests arrive from disk and from a package the user downloaded, so they are only semi-trusted.
        #[test]
        fn parsing_is_total(text in ".{0,400}") {
            let _ = Manifest::from_json(&text);
        }

        /// Validating a parsed manifest is total, at both levels and with every combination of context. The
        /// loader runs this on input it did not write.
        #[test]
        fn validation_is_total(
            text in ".{0,400}",
            has_artifacts in any::<bool>(),
            has_implementation in any::<bool>(),
        ) {
            let Ok(manifest) = Manifest::from_json(&text) else {
                return Ok(());
            };
            let context = ManifestContext {
                host_sdk: Some("1.0.0".to_owned()),
                host_wit: None,
                present_artifacts: has_artifacts.then(Vec::new),
                implementation: has_implementation.then(Implementation::default),
            };
            let _ = manifest.validate(ValidationLevel::Schema, &context);
            let _ = manifest.validate(ValidationLevel::Verify, &context);
            // And the derived accessors do not panic on whatever survived.
            let _ = manifest.capability_set();
            let _ = manifest.wire_slug();
            let _ = manifest.event_namespace();
            let _ = manifest.localised_title("zh-CN");
        }

        /// A slug is always a legal event-name segment, so whatever it is, an event built from it parses. A slug
        /// that was not would produce a plugin whose events nobody can name.
        #[test]
        fn a_slug_is_always_a_legal_event_segment(
            scope in "[a-z][a-z0-9-]{0,10}",
            name in "[a-z][a-z0-9-]{0,10}",
        ) {
            let id = format!("@{scope}/{name}");
            let Ok(id) = PluginId::parse(&id) else {
                return Ok(());
            };
            if let Ok(slug) = to_wire_slug(&id) {
                let event = format!("_plugin.{slug}.thing");
                prop_assert!(
                    synra_protocol::event::EventName::parse(&event).is_ok(),
                    "the slug produced an unnameable event: {event}",
                );
            }
        }

        /// A payload schema either validates or is refused for a reason. The walk is bounded, so a hostile
        /// schema cannot make the loader's work unbounded.
        #[test]
        fn payload_schemas_are_total(depth in 0usize..40) {
            let mut payload = String::from(r#"{"type":"object","properties":{"a":"#);
            for _ in 0..depth {
                payload.push_str(r#"{"type":"object","properties":{"a":"#);
            }
            payload.push_str("{}");
            for _ in 0..=depth {
                payload.push_str("}}");
            }
            payload.push('}');

            let text = format!(
                "{{\"id\":\"@synra-plugin/chat\",\"version\":\"1.0.0\",\"title\":\"T\",\
                 \"publisher\":{{\"id\":\"p\"}},\"sdk\":{{\"min\":\"1.0.0\"}},\
                 \"wit\":\"synra:plugin@1.0.0\",\
                 \"runtime\":{{\"headless\":{{\"artifact\":\"a\",\"stateful\":false}}}},\
                 \"capabilities\":[],\
                 \"events\":[{{\"name\":\"_plugin.chat.x\",\"payload\":{payload}}}]}}"
            );
            if let Ok(manifest) = Manifest::from_json(&text) {
                let _ = manifest.validate(ValidationLevel::Schema, &ManifestContext::default());
            }
        }
    }
}
