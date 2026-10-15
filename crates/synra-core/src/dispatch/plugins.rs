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
use std::sync::Arc;

use parking_lot::Mutex;
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

    /// The artifact imports a host function its capabilities do not cover.
    ///
    /// # Why the imported function is named and the capability is not
    ///
    /// Because the two readers need different halves. An author needs to know **which import** to remove or declare —
    /// they wrote the code that reaches it. A user needs to know the plugin is not trustworthy as built, and naming a
    /// capability at them would suggest a setting they could change to make it work, which is the opposite of true.
    ///
    /// Refused at load rather than at the call, because a call is where it becomes invisible: the guest would get a
    /// refusal for a function it genuinely imports, on a code path nobody is looking at, and the plugin would appear to
    /// work while quietly failing at one thing.
    #[error("{id} imports {import}, which its capabilities do not cover")]
    UndeclaredImport {
        /// The plugin.
        id: PluginId,
        /// The imported host function, as the component's own type reports it.
        import: String,
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
    /// How much a call may use, and how often.
    ///
    /// ★ An argument for the same reason grants are: a quota is what the *host* decided this plugin may spend, so a
    /// default here would be a limit nobody chose. It becomes the `Budget` every host call is counted against — the
    /// object the gate consults when it decides whether a call is over its rate.
    pub quota: synra_plugin_host::quota::Quota,
}

/// One loaded plugin: its compiled form, its grants, and the pool its instances come from.
struct Loaded {
    version: String,
    compiled: Box<dyn CompiledArtifact>,
    pool: synra_plugin_host::InstancePool,
    live: HashMap<u64, Box<dyn PluginInstance>>,
    /// What this plugin may do: its grants, its rate and its record.
    ///
    /// Separated from the artifact because the two answer different questions — "what is this" and "what may it do" —
    /// and because the second is a statement that should be testable without a `.wasm` fixture to compile.
    authority: Authority,
}

impl Loaded {
    /// The quota in force for this plugin, which is the degraded one once it has been degraded.
    ///
    /// Forwarded rather than stored: the `Budget` is what knows, and asking it is the difference between enforcing
    /// the number a user set and enforcing the number somebody copied at load time.
    #[must_use]
    pub(crate) fn quota(&self) -> synra_plugin_host::quota::Quota {
        self.authority.quota()
    }
}

/// What a plugin may do, for as long as it is loaded.
///
/// # Why the budget and the record are here rather than on the instance
///
/// Because both belong to the **plugin**. A budget cloned per instance would multiply the rate by the instance limit —
/// a plugin allowed ten calls a minute with four instances would get forty, which is not what its quota says — and an
/// audit buffer of the instance's own would die with the store, which is the same as having no audit at all.
pub(crate) struct Authority {
    grants: CapabilitySet,
    budget: Arc<synra_plugin_host::quota::Budget>,
    audit: Arc<Mutex<Vec<synra_observe::audit::AuditEntry>>>,
}

impl Authority {
    /// A plugin's authority: what it holds, what it may spend, and where its record goes.
    #[must_use]
    pub(crate) fn new(
        grants: CapabilitySet,
        quota: synra_plugin_host::quota::Quota,
        audit: Arc<Mutex<Vec<synra_observe::audit::AuditEntry>>>,
    ) -> Self {
        Self { grants, budget: Arc::new(synra_plugin_host::quota::Budget::new(quota)), audit }
    }

    /// The quota in force for this plugin, which is the degraded one once it has been degraded.
    ///
    /// ★ Why this is read rather than remembered.
    ///
    /// Because a plugin's health can change how much it is allowed, and the `Budget` is what knows: asking it is the
    /// difference between enforcing the number a user set and enforcing the number somebody copied at load time.
    #[must_use]
    pub(crate) fn quota(&self) -> synra_plugin_host::quota::Quota {
        self.budget.quota()
    }

    /// The session a host call is authorised against.
    ///
    /// The `Arc`s are cloned rather than rebuilt, so every instance of one plugin shares one rate and one record.
    #[must_use]
    pub(crate) fn session_for(
        &self,
        id: &PluginId,
        host: &Arc<dyn synra_plugin_host::host_calls::Host>,
    ) -> synra_plugin_host::engine::LinkerSession {
        synra_plugin_host::engine::LinkerSession::with_audit(
            id.clone(),
            self.grants.clone(),
            Arc::clone(&self.budget),
            Arc::clone(host),
            Arc::clone(&self.audit),
        )
    }
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
    /// Where a plugin's effects reach.
    ///
    /// ★ The piece that was missing, and the reason the capability gate never ran. Every instance used to be created
    /// with `session: None`, and `linker::run` refuses **every** host call when there is no session — so no plugin could
    /// reach a host function at all and nothing was audited. The gate is the mechanism the whole capability model rests
    /// on, and it was inert.
    host: Arc<dyn synra_plugin_host::host_calls::Host>,
    /// What plugins have done, bounded and readable.
    ///
    /// The kernel already has a ring for this ([`synra_observe::audit::AuditRing`]); what it did not have was a writer,
    /// because the only path to one was `synra_core::Kernel::record_action`, and no host constructs that type.
    audit: synra_observe::audit::AuditRing,
    /// Where a record goes besides the ring, when a host has somewhere to put it.
    ///
    /// ★ Why this is a callback rather than a store handle
    ///
    /// Because the kernel is what decides that a call is auditable, and the **host** is what has a database. `synra-core`
    /// depends on neither `rusqlite` nor a path, so the only honest way to hand a record on is to be given somewhere to put
    /// it — which is the same split as `decide` returning an envelope it cannot send and the daemon sending it.
    ///
    /// `None` is the ordinary state for a kernel with nowhere durable to write: a test, or a build whose store is not
    /// open. The ring still fills, so the audit the interface shows is complete for this process either way.
    audit_sink: Option<AuditSink>,
}

/// Where one audit record goes, besides the ring.
///
/// A boxed closure rather than a trait, because there is exactly one thing it can do — take a record — and a trait with one
/// method would be a name for the same signature. `Send + Sync` because the set is behind a lock that callers on several
/// threads take.
pub type AuditSink = Arc<dyn Fn(&synra_observe::audit::AuditEntry) + Send + Sync>;

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
    /// A set with no plugins, over a given engine and reaching a given host.
    ///
    /// # Why the host is required rather than defaulted
    ///
    /// Because there is no honest default. An instance with no session refuses every host call, so a set built without a
    /// host would be one whose plugins can do nothing — and the failure would read as a plugin problem rather than as a
    /// host that never said where its effects should go. Requiring it makes each caller state what its host is, which is
    /// the same reason `PluginSpec` has no default grants.
    #[must_use]
    pub fn new(backend: Backend, host: Arc<dyn synra_plugin_host::host_calls::Host>) -> Self {
        Self {
            backend,
            loaded: HashMap::new(),
            host,
            audit: synra_observe::audit::AuditRing::new(),
            audit_sink: None,
        }
    }

    /// What plugins have done, oldest first.
    #[must_use]
    pub fn audit(&self) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.all()
    }

    /// What one plugin has done, oldest first.
    #[must_use]
    pub fn audit_for(&self, id: &PluginId) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.for_plugin(id)
    }

    /// What one plugin had refused, which is what a user reads when asking why something did not work.
    #[must_use]
    pub fn refusals_for(&self, id: &PluginId) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.refusals_for_plugin(id)
    }

    /// Hands every record to a sink as well as to the ring.
    ///
    /// # Why the host installs one
    ///
    /// Because the ring is bounded (`synra_observe::audit::MEMORY_CAPACITY`) and lives in this process, so the audit a user
    /// sees is the recent history **of this run** — and the migration that created `plugin_audit` says what the table is
    /// for: *"the durable part is what makes the interface's 'recent activity' survive a restart."* A sink is how the two
    /// are the same trail rather than two.
    #[must_use]
    pub fn with_audit_sink(mut self, sink: AuditSink) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Moves whatever a plugin recorded during its last call into the ring.
    ///
    /// Called once per call rather than from inside the host call, because the entries are produced while the guest runs
    /// and the set is borrowed by the caller for the duration. Draining after the fact is also what makes the buffer
    /// bounded in practice: it holds one call's worth of entries, not a process's.
    fn drain_audit(
        loaded: &mut Loaded,
        ring: &mut synra_observe::audit::AuditRing,
        sink: Option<&AuditSink>,
    ) {
        let entries = {
            let mut buffered = loaded.authority.audit.lock();
            if buffered.is_empty() {
                return;
            }
            std::mem::take(&mut *buffered)
        };
        for entry in entries {
            // ★ The sink is called **before** the record is moved into the ring, because the ring takes it by value. Both
            // get the same record: the ring is what the interface reads now, and the sink is what survives a restart. A
            // trail written to only one of them is a trail that disagrees with itself after a restart.
            if let Some(sink) = sink {
                sink(&entry);
            }
            ring.record(entry);
        }
    }

    /// Feeds one record to the drain, the way a gated call does.
    ///
    /// # ★ Why this exists, and why it is `#[cfg(test)]`
    ///
    /// The entries a sink receives are produced by a **real** component calling a host function. The scripted backend these
    /// tests use answers from a table, so no guest runs, no host function is called, and nothing is audited — which is why
    /// the first version of the sink test asserted the sink had seen something and seen nothing. A test of this seam has to
    /// put the record where a call puts it, and that is not an entry point production has any use for.
    ///
    /// # Returns
    ///
    /// `false` when no plugin by that name is loaded, so a caller cannot mistake "nothing happened" for "it was drained".
    #[cfg(test)]
    pub(crate) fn drain_record_for_test(
        &mut self,
        plugin: &PluginId,
        entry: synra_observe::audit::AuditEntry,
    ) -> bool {
        // Destructured rather than reached through `self` three times: the drain needs the buffer, the ring and the sink at
        // once, and borrowing them from `self` separately is what the compiler refuses.
        let Self { loaded, audit, audit_sink, .. } = self;
        let Some(loaded) = loaded.get_mut(plugin) else {
            return false;
        };
        loaded.authority.audit.lock().push(entry);
        Self::drain_audit(loaded, audit, audit_sink.as_ref());
        true
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
        self.loaded.get(id).map(|loaded| &loaded.authority.grants)
    }

    /// Compiles a plugin and makes it askable.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::Compile`] when the engine refuses the bytes, and [`PluginSetError::UndeclaredImport`] when the
    /// artifact imports a host function its capabilities do not cover. A plugin already loaded is replaced, because a
    /// reinstall is how an update arrives and refusing the second write would make updates depend on a clean shutdown.
    pub fn load(&mut self, spec: PluginSpec) -> Result<(), PluginSetError> {
        let compiled = self.backend.compile(&spec.wasm, spec.id.as_str())?;

        // ★ The load-time import check, which had no caller until now.
        //
        // `host_surface::undeclared_imports` was written, tested, and called by nothing in production: the pipeline that
        // uses it (`synra_plugin_host::verify::verify`) has no caller either. So an artifact importing a host function
        // its capabilities never covered was loaded and run, and the first sign of it would have been a call refused at
        // the gate — long after the install, and for a reason the author could not act on.
        //
        // What is checked is what the **component** imports, read from its own type at compile time, rather than what
        // its manifest claims. That is the difference between a claim and a fact, and it is why the check can only
        // happen here: the imports do not exist until the bytes have been compiled.
        //
        // The comparison is against `spec.grants`, which in today's caller is the manifest's declared set — see the
        // daemon's `grants_of`. That makes the check "the artifact imports nothing its manifest did not declare", which
        // is exactly layer 1 of the three-layer gate and holds whatever the grants came from. When the consent flow
        // starts narrowing `grants` to the user's actual decisions, this check narrows with it and needs no change.
        let undeclared = synra_plugin_host::host_surface::undeclared_imports(compiled.imports(), &spec.grants);
        if let Some(import) = undeclared.first() {
            return Err(PluginSetError::UndeclaredImport {
                id: spec.id,
                import: import.clone(),
            });
        }

        let pool = synra_plugin_host::InstancePool::new(spec.policy, spec.limit);
        pool.start();
        self.loaded.insert(
            spec.id.clone(),
            Loaded {
                version: spec.version,
                compiled,
                pool,
                live: HashMap::new(),
                // One budget per plugin rather than per instance: the rate is a property of what the plugin may
                // spend, and the pool hands out instances freely — a per-instance budget would multiply the allowance
                // by the instance limit.
                authority: Authority::new(spec.grants, spec.quota, Arc::new(Mutex::new(Vec::new()))),
            },
        );
        Ok(())
    }

    /// The quota in force for a loaded plugin.
    ///
    /// # ★ Why this accessor exists
    ///
    /// Because `CallBudget::from_quota` was written, documented as the mapping — *"Every field is taken from the quota
    /// rather than chosen here, so the number a user sees in a settings screen is the number the sandbox enforces"* — and
    /// **production never called it**. Only the scripted backend's `enforcement` and a test did.
    ///
    /// The consequence was concrete: `share.execute` ran under a fixed five-second timeout with **no instruction limit at
    /// all**, and with no memory ceiling, whatever the plugin's quota said. The rates *were* enforced, which is what made
    /// the gap hard to see — a quota that does something looks like a quota that works.
    #[must_use]
    pub fn quota(&self, id: &PluginId) -> Option<synra_plugin_host::quota::Quota> {
        self.loaded.get(id).map(Loaded::quota)
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
        let outcome = Self::run_on(&self.backend, &self.host, loaded, id, handle, work, budget);
        let _ = loaded.pool.release(handle, now_ms);
        // ★ Drained **after** the call, not inside it: the entries are produced while the guest runs, and the ring lives
        // behind the set that the caller is borrowing. Collecting here is also what keeps the buffer one call deep.
        Self::drain_audit(loaded, &mut self.audit, self.audit_sink.as_ref());
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
        host: &Arc<dyn synra_plugin_host::host_calls::Host>,
        loaded: &mut Loaded,
        id: &PluginId,
        handle: u64,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
    ) -> Result<CallOutcome, PluginSetError> {
        if !loaded.live.contains_key(&handle) {
            match backend.instantiate(loaded.compiled.as_ref()) {
                Ok(mut instance) => {
                    // ★ The session, which is what makes the capability gate run at all.
                    //
                    // `instantiate` leaves the instance with no session, and `linker::run` refuses **every** host call
                    // when there is no session — so before this, no plugin could reach a host function and nothing was
                    // audited. The gate is the mechanism the whole capability model rests on, and it was inert.
                    //
                    // Installed once per instance rather than per call: the session holds the audit buffer and the
                    // rate budget, and rebuilding it every call would reset both. `session_for` is where the loader's
                    // decision about this plugin's authority lives.
                    instance.set_session(loaded.authority.session_for(id, host));
                    loaded.live.insert(handle, instance);
                }
                Err(error) => return Err(PluginSetError::Compile(error)),
            }
        }

        // ★ The host's own panic must not cross this boundary.
        //
        // `Cargo.toml`'s release profile sets `panic = "unwind"` and gives one reason: "插件 panic 必须能被 catch_unwind
        // 捕获". Until this was written, `catch_unwind` appeared nowhere in the workspace — so the profile was built for
        // a mechanism that did not exist, and a panic raised inside a host function called by a guest (an index, an
        // unwrap, an arithmetic overflow in a debug build) unwound straight through `call`, through the pool, and out
        // of whatever kernel thread was dispatching. One plugin's bug took the process with it.
        //
        // The call is wrapped rather than the whole dispatcher, because the instance is what has to be thrown away: a
        // panic that unwound out of the middle of a guest call leaves the store in a state nothing can reason about, so
        // reusing it would trade a loud failure for a quiet wrong answer. The handle is dropped from `live` and a later
        // call instantiates a fresh instance — which is what the pool is for.
        //
        // `AssertUnwindSafe` is required and is sound to give here: the only shared state the closure touches is the
        // instance, and that instance is discarded on the unwind path rather than observed.
        let outcome = {
            let Some(instance) = loaded.live.get_mut(&handle) else {
                return Err(PluginSetError::NoInstance { id: id.clone() });
            };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call(work, budget)))
        };

        match outcome {
            Ok(result) => result.map_err(PluginSetError::Compile),
            Err(payload) => {
                // The instance is gone, so a later call builds a new one instead of inheriting the damage.
                loaded.live.remove(&handle);
                Ok(CallOutcome::Trap { detail: panic_detail(payload.as_ref()) })
            }
        }
    }
}

/// A sentence describing a caught panic, for the plugin author and for the audit record.
///
/// The payload is `Box<dyn Any + Send>` because that is what `catch_unwind` hands back. The two shapes it takes in
/// practice are a `&str` (a `panic!("...")` with a literal) and a `String` (a formatted one); anything else is a
/// payload the caller chose, and saying so is better than guessing at a `Debug` rendering that may itself panic.
fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return format!("the host panicked: {message}");
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return format!("the host panicked: {message}");
    }
    "the host panicked with a payload that is neither a string nor a string slice".to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use synra_capability::CapabilitySet;
    use synra_plugin_host::quota::Quota;
    use synra_protocol::ids::PluginId;

    use super::Authority;

    fn id(name: &str) -> PluginId {
        PluginId::try_from(name.to_owned()).expect("a plugin id")
    }

    fn authority(grants: CapabilitySet) -> Authority {
        Authority::new(grants, Quota::default(), Arc::new(parking_lot::Mutex::new(Vec::new())))
    }

    #[test]
    fn a_session_carries_the_plugins_own_authority() {
        // ★ The test the whole change exists for, and it needs no engine.
        //
        // Every instance used to be created with `session: None`, and `linker::run` refuses **every** host call when
        // there is no session — so the capability gate, the mechanism the entire capability model rests on, never ran.
        // Nothing failed; a plugin simply could not reach a host function, and the only signal was `HOST_FAILED`, which
        // says "no session" rather than "you are not allowed".
        //
        // What is asserted is the session's own contents, because the session is what the linker reads. A test that
        // called through the set could not tell a missing session from a denied capability: both refuse, with different
        // codes, and only one of them means the gate ran.
        let mut grants = CapabilitySet::new();
        grants.insert_str("log:*").expect("a capability");

        let session = authority(grants).session_for(&id("@synra/aaa"), &super::super::tests::host());

        assert_eq!(session.plugin, id("@synra/aaa"));
        assert!(
            session
                .grants
                .contains(&synra_capability::Capability::parse("log:info").expect("a capability")),
            "the session must carry the plugin's grants, not an empty set"
        );
    }

    #[test]
    fn two_instances_of_one_plugin_share_their_rate_and_their_record() {
        // ★ Why the budget and the audit belong to the plugin rather than to the instance.
        //
        // A budget cloned per instance would multiply the rate by the instance limit — a plugin allowed ten calls a
        // minute with four instances would get forty, which is not what its quota says. And a record of the instance's
        // own would die with the store, which is the same as having no audit at all. Asserted with pointer equality,
        // because "the same allowance" is exactly what a copy is not.
        let authority = authority(CapabilitySet::new());
        let host = super::super::tests::host();

        let first = authority.session_for(&id("@synra/bbb"), &host);
        let second = authority.session_for(&id("@synra/bbb"), &host);

        assert!(Arc::ptr_eq(&first.budget, &second.budget), "two instances, two rates");
        assert!(Arc::ptr_eq(&first.audit, &second.audit), "two instances, two records");
    }
}
