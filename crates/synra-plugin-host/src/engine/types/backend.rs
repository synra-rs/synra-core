use std::fmt;

use super::{BackendError, BackendKind, CompiledArtifact, Enforcement, PluginInstance};

/// A backend shared by everything that uses it.
///
/// # Why a handle type rather than `Arc<dyn WasmBackend>` alone
///
/// Because an instance needs the backend that made it: its import table, its engine, its counters. An instance holding
/// a borrow would tie every instance's lifetime to the caller's stack; one holding a copy of a *concrete* backend would
/// be an instance of a different backend, which for [`crate::engine::scripted`] means a script table that is never
/// found. And the unsizing coercion from `Arc<Concrete>` to `Arc<dyn Trait>` cannot be named in a trait method's
/// `self` type, so the erasure happens in a constructor instead — one line, in one place, rather than at every call
/// site.
#[derive(Clone)]
pub struct Backend {
    inner: std::sync::Arc<dyn WasmBackend>,
}

impl Backend {
    /// Shares a backend.
    ///
    /// The coercion to a trait object happens here, which is the only place it can.
    pub fn new<T: WasmBackend + 'static>(backend: std::sync::Arc<T>) -> Self {
        Self { inner: backend }
    }

    /// The engine behind the handle.
    #[must_use]
    pub fn engine(&self) -> &dyn WasmBackend {
        self.inner.as_ref()
    }

    /// The same engine as its concrete type, when it is the one asked for.
    ///
    /// # Why this exists
    ///
    /// An instance has to reach its backend's own state — a script table, an engine, a counter — and the only handle it
    /// is given is this erased one. The alternative would be for every backend to thread its state into its instances
    /// through a constructor of its own, which is the same downcast written once per backend with no type check.
    ///
    /// The check is the type id, so a wrong type is `None` rather than a reinterpreted pointer.
    #[must_use]
    pub fn concrete<T: WasmBackend + 'static>(&self) -> Option<&T> {
        // `Any` as a supertrait, which is what makes this cast legal: a downcast needs a type id, and a type id is only
        // meaningful for a type that is `'static` — the same bound the trait already carries.
        (self.inner.as_ref() as &dyn std::any::Any).downcast_ref::<T>()
    }

    /// Which engine this is.
    #[must_use]
    pub fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    /// What this engine can enforce.
    #[must_use]
    pub fn enforcement(&self) -> Enforcement {
        self.inner.enforcement()
    }

    /// The engine's version.
    #[must_use]
    pub fn engine_version(&self) -> &str {
        self.inner.engine_version()
    }

    /// Compiles a component.
    ///
    /// # Errors
    ///
    /// As [`WasmBackend::compile`].
    pub fn compile(
        &self,
        wasm: &[u8],
        plugin_id: &str,
    ) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        self.inner.compile(wasm, plugin_id)
    }

    /// Instantiates a compiled component.
    ///
    /// # Errors
    ///
    /// As [`WasmBackend::instantiate`].
    pub fn instantiate(
        &self,
        compiled: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError> {
        self.inner.instantiate(self, compiled)
    }
}

impl fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Backend")
            .field("kind", &self.kind())
            .field("engine_version", &self.engine_version())
            .finish_non_exhaustive()
    }
}

/// An engine that compiles components and makes instances of them.
///
/// The `Any` supertrait is what makes [`Backend::concrete`] possible: a downcast needs a type id, and a type id is only
/// meaningful for a type that cannot have borrowed a caller's stack.
pub trait WasmBackend: Send + Sync + std::any::Any {
    /// Which engine this is.
    fn kind(&self) -> BackendKind;

    /// What this engine can enforce.
    fn enforcement(&self) -> Enforcement;

    /// The engine's version, which belongs in a compile cache key: a precompiled artefact is only loadable by the
    /// engine that produced it.
    fn engine_version(&self) -> &str;

    /// Compiles a component.
    ///
    /// # Errors
    ///
    /// [`BackendError::Compile`] when the artifact is not a component this engine understands, and
    /// [`BackendError::UnknownImport`] or [`BackendError::UngrantedImport`] when its imports are not ones the host
    /// provides for this plugin.
    fn compile(&self, wasm: &[u8], plugin_id: &str) -> Result<Box<dyn CompiledArtifact>, BackendError>;

    /// Precompiles, for an engine whose compiled form can be cached on disk.
    ///
    /// # Errors
    ///
    /// [`BackendError::BackendUnavailable`] when this engine has no such form, which
    /// [`Enforcement::precompile`] is what reports.
    fn precompile(&self, wasm: &[u8], plugin_id: &str) -> Result<Vec<u8>, BackendError> {
        let _ = (wasm, plugin_id);
        Err(BackendError::BackendUnavailable { kind: self.kind() })
    }

    /// Loads what [`WasmBackend::precompile`] produced.
    ///
    /// # Errors
    ///
    /// As [`WasmBackend::precompile`], plus [`BackendError::Compile`] for bytes this engine did not produce.
    fn load_precompiled(&self, bytes: &[u8], plugin_id: &str) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        let _ = (bytes, plugin_id);
        Err(BackendError::BackendUnavailable { kind: self.kind() })
    }

    /// Instantiates a compiled component.
    ///
    /// Instantiates a compiled component.
    ///
    /// `backend` is the handle this engine is reachable through, because an instance holds one: a plugin call later
    /// needs the engine's import table and its counters, and an instance that could only reach `&self` would need the
    /// caller of *every* call to hand the engine back.
    ///
    /// # Errors
    ///
    /// [`BackendError::Instantiate`] when the component's start function fails or a required export is missing.
    fn instantiate(
        &self,
        backend: &Backend,
        compiled: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError>;
}
