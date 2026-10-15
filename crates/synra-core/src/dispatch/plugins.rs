//! The plugins this kernel can ask, and how it asks them.
//!
//! # What this type is for
//!
//! The design document's flow (`07-core-kernel.md` §6.2) has nine steps, and steps 3 through 8 all require calling
//! code the kernel does not own: compile a component, hold an instance, run one entry point under a budget, and hand
//! back what it said. That machinery is [`synra_plugin_host`], and this file is the part of it the kernel actually needs —
//! without it the kernel can hold an [`crate::intent::Board`] and can never put a candidate into one.
//!
//! # Why the engine is handed in rather than built here
//!
//! Because `wasmtime` is a large dependency and this crate must not acquire it. The engine is a host decision: the
//! windowless daemon and the Tauri shell each build one, and they may legitimately differ. So [`PluginSet`] takes a
//! [`Backend`] in its constructor and every test uses [`synra_plugin_host::ScriptedBackend`], which is a backend with no
//! guest in it at all. That is what makes this file's tests possible without a `.wasm` anyone would have to review —
//! and a test that cannot run on a machine with no engine is a test that does not run.
//!
//! # Why loading compiles
//!
//! Because the artifact's imports are what the host is asked to provide, and finding an import the host cannot satisfy
//! at *call* time is a call that fails on a user's share. [`PluginSet::load`] compiles, so the import table is known
//! before any user-visible moment exists to fail in.
//!
//! # Why instances come from a pool rather than being made per call
//!
//! Instantiation is the expensive part of running a plugin, and a plugin that declares itself `stateful` would lose its
//! memory to a pool that hands out any instance. The pool is what makes both true at once, and its refusal is returned
//! rather than retried here: a plugin at its instance limit is a fact the caller reports, not a delay the kernel hides.

use std::collections::HashMap;
use std::fmt;

use synra_capability::CapabilitySet;
use synra_plugin_host::{
    Backend, BackendError, CallBudget, CallOutcome, CompiledArtifact, InstancePolicy,
    PluginInstance,
};
use synra_protocol::ids::PluginId;

/// Why a plugin could not be loaded, called, or removed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PluginSetError {
    /// The engine refused the artifact.
    ///
    /// Wrapped rather than re-typed: the engine's own reason — an import the host cannot provide, a body that is not a
    /// component — is exactly what a plugin author needs, and flattening it would throw that away.
    #[error("the engine refused the plugin: {0}")]
    Compile(#[from] BackendError),

    /// A call was asked of a plugin this kernel does not have.
    ///
    /// Distinct from a compile failure because the fix is different: this one is answered by installing the plugin,
    /// not by changing its bytes.
    #[error("{id} is not loaded")]
    NotLoaded {
        /// The plugin.
        id: PluginId,
    },

    /// An instance the pool handed out is gone before it was called.
    ///
    /// Reported rather than hidden because the honest repair is to make a new instance, and a caller that treats this
    /// as "the plugin refused" would tell a user their plugin declined a share for a reason that has nothing to do with it.
    #[error("{id} lost the instance the pool handed out")]
    NoInstance {
        /// The plugin.
        id: PluginId,
    },

    /// The pool would not hand out an instance.
    ///
    /// Separate from [`Self::NotLoaded`] on purpose: the plugin is installed and known, it is simply at its limit. A
    /// caller that reported this as "not installed" would tell a user to install a plugin they already have.
    #[error("{id} is at its instance limit")]
    AtInstanceLimit {
        /// The plugin.
        id: PluginId,
    },
}

impl PluginSetError {
    /// Whether trying again could work without anything changing.
    ///
    /// A missing plugin is not retryable: the bytes exist or they do not, and waiting produces neither.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Compile(BackendError::Instantiate { .. }))
    }
}

/// What a caller has to say when it loads a plugin.
///
/// # Why grants and policy are arguments rather than defaults
///
/// Both are decisions the **user** made — the manifest declared them and the consent flow decided them — so a default
/// here would be a default nobody chose. A caller that has not asked the user yet should not be able to load a plugin
/// at all, and that is enforced by this struct having no such constructor.
pub struct PluginSpec {
    /// Which plugin this is.
    pub id: PluginId,
    /// The version being loaded.
    ///
    /// Kept because a dispatch records it: a plugin updated between the prompt being drawn and the user answering is a
    /// plugin they did not agree about, and the only way to notice is to have written down what was asked.
    pub version: String,
    /// The component's bytes.
    pub wasm: Vec<u8>,
    /// What the user granted it.
    pub grants: CapabilitySet,
    /// Whether its instances may be shared between callers.
    pub policy: InstancePolicy,
    /// How many instances may exist at once.
    pub limit: u32,
}

/// One loaded plugin: its compiled form, its grants, and the pool its instances come from.
struct Loaded {
    version: String,
    compiled: Box<dyn CompiledArtifact>,
    grants: CapabilitySet,
    pool: synra_plugin_host::InstancePool,
    live: HashMap<u64, Box<dyn PluginInstance>>,
}

/// The plugins this kernel can ask.
///
/// # Why this is not `Clone`
///
/// Because it holds live instances. A Wasm store has fuel, memory and guest globals in it, and a copy of one is not a
/// second store — it is the same store under a second name, which is how two callers end up corrupting one guest's
/// state. The backend is shared deliberately and cheaply; the set of instances is not shared at all.
pub struct PluginSet {
    backend: Backend,
    loaded: HashMap<PluginId, Loaded>,
}

impl fmt::Debug for PluginSet {
    /// Deliberately not derived.
    ///
    /// A derived `Debug` would need `Loaded: Debug`, and getting there would mean printing compiled artifacts and live
    /// instances. What is useful in a log is the shape of the table — which plugins, at which versions, with how many
    /// instances — and that is what this writes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSet")
            .field("engine", &self.backend.kind())
            .field("plugins", &self.ids())
            .finish()
    }
}

impl PluginSet {
    /// A set with no plugins, over a given engine.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            loaded: HashMap::new(),
        }
    }

    /// The engine these plugins run on.
    #[must_use]
    pub const fn backend(&self) -> &Backend {
        &self.backend
    }

    /// How many plugins are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    /// Whether a plugin is loaded.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.loaded.contains_key(id)
    }

    /// The loaded plugins, in a stable order.
    ///
    /// Sorted rather than in insertion order because two calls that read the same table should print the same line, and
    /// a `HashMap`'s order is not a thing a reader can hold in their head.
    #[must_use]
    pub fn ids(&self) -> Vec<PluginId> {
        let mut ids: Vec<PluginId> = self.loaded.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// What a plugin has been granted.
    #[must_use]
    pub fn grants(&self, id: &PluginId) -> Option<&CapabilitySet> {
        self.loaded.get(id).map(|loaded| &loaded.grants)
    }

    /// Compiles a plugin and makes it askable.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::Compile`] when the engine refuses the bytes. A plugin already loaded is replaced, because a
    /// reinstall is how an update arrives and refusing the second write would make updates depend on a clean shutdown.
    pub fn load(&mut self, spec: PluginSpec) -> Result<(), PluginSetError> {
        let compiled = self.backend.compile(&spec.wasm, spec.id.as_str())?;
        let pool = synra_plugin_host::InstancePool::new(spec.policy, spec.limit);
        pool.start();
        self.loaded.insert(
            spec.id.clone(),
            Loaded {
                version: spec.version,
                compiled,
                grants: spec.grants,
                pool,
                live: HashMap::new(),
            },
        );
        Ok(())
    }

    /// The version a plugin is loaded at.
    #[must_use]
    pub fn version(&self, id: &PluginId) -> Option<&str> {
        self.loaded.get(id).map(|loaded| loaded.version.as_str())
    }

    /// Forgets a plugin, dropping its compiled form and every instance of it.
    ///
    /// The reason this is more than a `HashMap::remove`: an instance still holding a `Box<dyn PluginInstance>` is a live
    /// Wasm store, and leaving one behind is a leak the kernel would report on every restart as a slowly rising number.
    pub fn unload(&mut self, id: &PluginId) -> bool {
        self.loaded.remove(id).is_some()
    }

    /// Runs one entry point on one plugin.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::NotLoaded`] when the plugin is not here. A guest that *failed while running* is a
    /// [`CallOutcome`], not an error — a trap is something the caller decides about, and turning it into a failure here
    /// would mean the kernel could not tell "the plugin refused" from "the plugin is broken".
    pub fn call(
        &mut self,
        id: &PluginId,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
        now_ms: u64,
    ) -> Result<CallOutcome, PluginSetError> {
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        let handle = match loaded.pool.acquire(None, now_ms) {
            Ok(handle) => handle,
            // A plugin at its instance limit is reported, not waited on. The caller turns this into something the user
            // can act on; a retry loop here would hide the limit by turning it into latency.
            Err(_) => {
                return Err(PluginSetError::AtInstanceLimit { id: id.clone() });
            }
        };
        let outcome = Self::run_on(&self.backend, loaded, id, handle, work, budget);
        let _ = loaded.pool.release(handle, now_ms);
        outcome
    }

    /// Runs the call against whichever instance the pool handed out.
    ///
    /// # Why the instance is made lazily and kept
    ///
    /// Instantiation is the expensive part, and the pool exists precisely so it is not paid per call. An instance is
    /// therefore created on the handle's first use and kept for as long as the pool holds the handle.
    ///
    /// # Why `loaded` and `backend` are passed rather than found
    ///
    /// Because **a handle is only meaningful to the pool that issued it**. Searching every loaded plugin for one that
    /// recognises a handle is how a call ends up running on another plugin's instance, and that failure is invisible:
    /// both plugins are loaded and both answers parse. Taking both arguments from the caller also keeps the borrow of
    /// one entry from reaching across the whole set.
    fn run_on(
        backend: &Backend,
        loaded: &mut Loaded,
        id: &PluginId,
        handle: u64,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
    ) -> Result<CallOutcome, PluginSetError> {
        if !loaded.live.contains_key(&handle) {
            match backend.instantiate(loaded.compiled.as_ref()) {
                Ok(instance) => {
                    loaded.live.insert(handle, instance);
                }
                Err(error) => return Err(PluginSetError::Compile(error)),
            }
        }
        match loaded.live.get_mut(&handle) {
            Some(instance) => instance.call(work, budget).map_err(PluginSetError::Compile),
            None => Err(PluginSetError::NoInstance { id: id.clone() }),
        }
    }
}
