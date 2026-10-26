//! What a refusal says, and how thorough the check that found it was.
//!
//! # Why the level describes the check and not the failure
//!
//! Because the same manifest may fail a warning and pass a strict check: a caller chooses which set it ran under. Keeping
//! the level with the call rather than with the message is what lets one manifest be reported two ways without rebuilding
//! the errors.

use synra_capability::CapabilityError;

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
    #[error("the plugin id {id:?} has no usable project directory slug")]
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

    /// An event declaration has invalid syntax or exceeds the event-name bound.
    #[error("the event {name:?} is invalid: {reason}")]
    BadEventName {
        /// The declared name.
        name: String,
        /// The protocol validator's diagnosis.
        reason: String,
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
