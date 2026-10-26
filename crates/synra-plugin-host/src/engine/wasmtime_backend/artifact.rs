//! Compiled component metadata and public artifact views.

use crate::engine::types::{BackendKind, CompiledArtifact};
use wasmtime::component::Component;

/// A component that has been compiled and checked.
pub struct EngineArtifact {
    pub(super) component: Component,
    pub(super) digest: String,
    /// The component's true kind, so an artefact from another backend cannot be run by this one.
    pub(super) kind: BackendKind,
    /// The interfaces the component imports, as `interface/function` pairs.
    ///
    /// Read from the component's own type rather than from a manifest: what is checked is what the artifact actually
    /// imports, which is the difference between a claim and a fact.
    pub(super) imports: Vec<String>,
    /// The interfaces it exports, which is how the contract's four entry points are reached.
    pub(super) exports: Vec<String>,
}

impl std::fmt::Debug for EngineArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineArtifact")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .field("imports", &self.imports)
            .finish_non_exhaustive()
    }
}

impl EngineArtifact {
    /// What the component imports.
    #[must_use]
    pub fn imports(&self) -> &[String] {
        &self.imports
    }

    /// What the component exports.
    #[must_use]
    pub fn exports(&self) -> &[String] {
        &self.exports
    }
}

impl CompiledArtifact for EngineArtifact {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    /// What the component's own type says it imports.
    ///
    /// Already read at compile time and already checked against the host's table — the linker refuses to instantiate a
    /// component naming a function this build does not provide. Exposing it is what lets the *kernel* make the other
    /// check, about the plugin's own capabilities, without knowing which engine produced the artifact.
    fn imports(&self) -> &[String] {
        &self.imports
    }
}
