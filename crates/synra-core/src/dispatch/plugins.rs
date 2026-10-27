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
    Backend, BackendError, CallBudget, CallOutcome, CompiledArtifact, Health, InstancePolicy,
    Lifecycle, PluginInstance, State, Transition,
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

    /// The lifecycle refused a move the loader thought it was making.
    ///
    /// A bug rather than a user-visible condition: the loader's steps are installed → validated → granted, and every one
    /// of them is legal from the previous state. It is an error instead of a panic so a corrupt plugin cannot take the
    /// kernel down, and it names the move so a log line is enough to find where the pair diverged.
    #[error("the lifecycle refused the move: {0}")]
    Lifecycle(String),

    /// The plugin reached the bottom of the health ladder and is no longer called.
    ///
    /// Distinct from [`Self::NotLoaded`]: the bytes are here and the plugin is installed, but it misbehaved often enough
    /// that the host stopped asking. The reason is the ladder's own explanation, not a second sentence invented here.
    #[error("{id} is faulted: {reason}")]
    Faulted {
        /// The plugin.
        id: PluginId,
        /// Why the host stopped calling it.
        reason: String,
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

    /// The protocol code a caller reports for this failure.
    ///
    /// # Why the mapping lives here
    ///
    /// Because two paths need it and they are on opposite sides of the network: `decide` reports a failure that happened
    /// on this device, and `accept_remote` reports one that happened elsewhere. Both used to answer `Internal`, which threw
    /// away the one fact the interface branches on — `capability_denied` and `plugin_not_installed` ask the user to do two
    /// different things, and `Internal` asks them to file a bug.
    #[must_use]
    pub const fn code(&self) -> synra_protocol::ErrorCode {
        use synra_protocol::ErrorCode;
        match self {
            // A compile failure is a package this build cannot run, not a plugin that misbehaved.
            Self::Compile(_) => ErrorCode::Internal,
            Self::NotLoaded { .. } => ErrorCode::PluginNotInstalled,
            Self::NoInstance { .. } => ErrorCode::Internal,
            Self::AtInstanceLimit { .. } => ErrorCode::RateLimited,
            // A host function the artifact imports without the capability to back it is exactly a capability refusal.
            Self::UndeclaredImport { .. } => ErrorCode::CapabilityDenied,
            Self::Lifecycle(_) => ErrorCode::Internal,
            Self::Faulted { .. } => ErrorCode::PluginTrapped,
        }
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
    execution: Arc<crate::plugin_events::context::Execution>,
    version: String,
    /// Whether the user denied part of what this plugin asked for, kept so clearing a fault can re-grant honestly.
    partially_denied: bool,
    /// Where this plugin is in its life: installed, validated, granted, active, faulted.
    ///
    /// Stored beside the compiled form rather than derived on read, because the transitions are what make the ladder
    /// meaningful: a state recomputed from flags cannot refuse a move, and a refusal is the only thing it is for.
    lifecycle: Lifecycle,
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
    /// Where this plugin's gate decisions are counted, when the kernel keeps numbers.
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
}

impl Authority {
    /// A plugin's authority: what it holds, what it may spend, and where its record goes.
    #[must_use]
    pub(crate) fn new(
        grants: CapabilitySet,
        quota: synra_plugin_host::quota::Quota,
        audit: Arc<Mutex<Vec<synra_observe::audit::AuditEntry>>>,
    ) -> Self {
        Self { grants, metrics: None, budget: Arc::new(synra_plugin_host::quota::Budget::new(quota)), audit }
    }

    /// The same authority, counting what it does.
    ///
    /// ★ Why the recorder is a builder rather than a constructor argument.
    ///
    /// Because a plugin's authority is a statement about what it may do, and it should be constructible — and testable —
    /// without a kernel that keeps numbers. A required argument would make every test that asks "what may this plugin do"
    /// also state where its metrics go; `None` inside the struct is the same fact with the caller left alone.
    #[must_use]
    pub(crate) fn with_metrics(
        mut self,
        metrics: Arc<synra_observe::metrics::RingRecorder>,
    ) -> Self {
        self.metrics = Some(metrics);
        self
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
        let session = synra_plugin_host::engine::LinkerSession::with_audit(
            id.clone(),
            self.grants.clone(),
            Arc::clone(&self.budget),
            Arc::clone(host),
            Arc::clone(&self.audit),
        );
        match self.metrics.as_ref() {
            Some(metrics) => session.with_metrics(Arc::clone(metrics)),
            None => session,
        }
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
    runtime_id: synra_protocol::RequestId,
    events: Option<Arc<crate::plugin_events::EventService>>,
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
    /// Where the gate's counters go, when the kernel keeps numbers.
    ///
    /// Shared rather than one per plugin, because the design's `gate_*` metrics are read as one series across plugins: the
    /// plugin is a **label** on a series, not a series of its own.
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
    /// Where a health change goes, when a host has a window to tell.
    ///
    /// ★ Why this is a callback and not an event type here: `synra-core` does not own the event contract, and a kernel
    /// that constructed IPC events would depend on the interface's vocabulary. The host passes what it wants done; the
    /// event's field names are the host's business.
    health_sink: Option<HealthSink>,
}

/// Where one health change goes.
///
/// The arguments are the plugin, the new rung's `snake_case` name and the ladder's own explanation. A boxed closure with
/// three arguments rather than a trait, for the same reason [`AuditSink`] is one: there is exactly one thing it can do.
pub type HealthSink = Arc<dyn Fn(&PluginId, &str, &str) + Send + Sync>;

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

impl Drop for PluginSet {
    fn drop(&mut self) {
        if let Some(events) = &self.events {
            events.stop_runtime(self.runtime_id);
        }
    }
}

impl PluginSet {
    /// Use the same bounded local event service as this set's native host adapter.
    #[must_use]
    pub fn with_event_delivery(mut self, events: Arc<crate::plugin_events::EventService>) -> Self {
        self.events = Some(events);
        self
    }

    /// Share the runtime and bind its event worker before activating plugins.
    ///
    /// # Errors
    /// Refuses reusing an event service for another runtime or after shutdown.
    pub fn into_shared(self) -> Result<Arc<Mutex<Self>>, synra_protocol::SynraError> {
        let runtime = self.runtime_id;
        let events = self.events.clone();
        let metrics = self.metrics.clone();
        let shared = Arc::new(Mutex::new(self));
        if let Some(events) = events {
            events.bind(runtime, Arc::downgrade(&shared), metrics)?;
        }
        Ok(shared)
    }

    pub(crate) fn event_executions(&self) -> Vec<Arc<crate::plugin_events::context::Execution>> {
        let mut executions: Vec<_> = self
            .loaded
            .values()
            .filter(|loaded| matches!(loaded.lifecycle.state(), State::Active { .. }))
            .map(|loaded| Arc::clone(&loaded.execution))
            .collect();
        executions.sort_by(|left, right| left.plugin.cmp(&right.plugin));
        executions
    }

    pub(crate) fn event_execution_current(
        &self,
        execution: &Arc<crate::plugin_events::context::Execution>,
    ) -> bool {
        self.loaded.get(&execution.plugin).is_some_and(|loaded| {
            Arc::ptr_eq(&loaded.execution, execution)
                && matches!(loaded.lifecycle.state(), State::Active { .. })
        })
    }

    pub(crate) fn call_event(
        &mut self,
        execution: &Arc<crate::plugin_events::context::Execution>,
        grants: CapabilitySet,
        event_json: String,
        budget: CallBudget,
        trace: synra_protocol::TraceId,
    ) -> Result<CallOutcome, PluginSetError> {
        if !self.event_execution_current(execution) {
            return Err(PluginSetError::NotLoaded {
                id: execution.plugin.clone(),
            });
        }
        if let Some(loaded) = self.loaded.get_mut(&execution.plugin) {
            loaded.authority.grants = grants;
        }
        self.call_traced(
            &execution.plugin,
            &synra_plugin_host::Work::Event { event_json },
            budget,
            u64::try_from(synra_store::sqlite::now_ms()).unwrap_or_default(),
            Some(trace),
        )
    }

    /// The health a loaded plugin is in **right now**.
    ///
    /// ★ Why this accessor had to exist for the ladder to mean anything.
    ///
    /// Round 114 made a trap count towards the ladder and found that nothing could read the result: the daemon's `status`
    /// reports the **database row**, recorded at install time, and the live rung was unreachable. A mechanism whose state
    /// has no reader is one nobody can act on — and the point of telling a user their plugin is degrading is that they act
    /// before it is disabled.
    ///
    /// `None` for a plugin that is not loaded, which is a different fact from "healthy".
    #[must_use]
    pub fn health_of(&self, id: &str) -> Option<Health> {
        let id = PluginId::try_from(id.to_owned()).ok()?;
        self.loaded.get(&id).map(|loaded| loaded.authority.budget.health())
    }

    /// The quota report of a loaded plugin, for a screen that shows its health.
    ///
    /// The rung alone is what [`PluginSet::health_of`] answers; this is the rung plus the sentence, the call counts and the
    /// quota in force — the facts a card needs to say *why* a plugin is degraded rather than only that it is.
    pub fn report_of(&self, id: &str) -> Option<synra_plugin_host::quota::QuotaReport> {
        let id = PluginId::try_from(id.to_owned()).ok()?;
        self.loaded.get(&id).map(|loaded| loaded.authority.budget.report())
    }

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
            runtime_id: synra_protocol::RequestId::new(),
            events: None,
            backend,
            loaded: HashMap::new(),
            host,
            audit: synra_observe::audit::AuditRing::new(),
            audit_sink: None,
            metrics: None,
            health_sink: None,
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

    /// Forgets one plugin's records, which is the user's "clear this plugin's history".
    ///
    /// # Why it is per plugin rather than whole-ring
    ///
    /// Because the screen an audit is read on is a plugin's card, and the action is taken beside one plugin's trail. A
    /// `clear()` of the whole ring would let the button on one card erase what the user was about to read on another.
    ///
    /// The counts go with the entries: a history the user cleared that still reports a total is one they did not clear.
    /// That detail belongs to `AuditRing::clear_plugin` rather than here, so the two readers of the ring cannot disagree
    /// about it.
    pub fn clear_audit(&mut self, id: &PluginId) {
        self.audit.clear_plugin(id);
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

    /// The same set, telling a host when a plugin's health moves.
    #[must_use]
    pub fn with_health_sink(mut self, sink: HealthSink) -> Self {
        self.health_sink = Some(sink);
        self
    }

    /// The same set, counting the gate's decisions.
    ///
    /// # Why this is separate from the audit sink
    ///
    /// Because the two answer different questions and have different lifetimes. A sink is *what happened*, one row per call,
    /// written down and read by a person; a recorder is *how often*, aggregated, and read by a graph. A host may reasonably
    /// want one without the other — a diagnostic run wants numbers and no writes — and a single "observe this" switch would
    /// have made that impossible to express.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<synra_observe::metrics::RingRecorder>) -> Self {
        self.metrics = Some(metrics);
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
        trace: Option<synra_protocol::ids::TraceId>,
    ) {
        let entries = {
            let mut buffered = loaded.authority.audit.lock();
            if buffered.is_empty() {
                return;
            }
            std::mem::take(&mut *buffered)
        };
        for mut entry in entries {
            // ★ The trace is stamped here, on the entries this call produced. The gate inside the guest knows the
            // capability and the outcome; it has no way to know which user action the call belongs to, and a session is
            // installed once per pooled instance rather than once per call. The funnel that does know is this one.
            if entry.trace.is_none() {
                entry.trace = trace;
            }
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
        self.drain_record_with_trace_for_test(plugin, entry, None)
    }

    /// The same seam, with the trace a real call would pass.
    ///
    /// # Why the trace is a parameter of its own
    ///
    /// Because `drain_record_for_test` is called by tests that are not about traces, and a second entry point is cheaper
    /// than making every one of them pass `None` to say so. This is the one a test about stamping uses.
    #[cfg(test)]
    pub(crate) fn drain_record_with_trace_for_test(
        &mut self,
        plugin: &PluginId,
        entry: synra_observe::audit::AuditEntry,
        trace: Option<synra_protocol::ids::TraceId>,
    ) -> bool {
        // Destructured rather than reached through `self` three times: the drain needs the buffer, the ring and the sink at
        // once, and borrowing them from `self` separately is what the compiler refuses.
        let Self { loaded, audit, audit_sink, .. } = self;
        let Some(loaded) = loaded.get_mut(plugin) else {
            return false;
        };
        loaded.authority.audit.lock().push(entry);
        Self::drain_audit(loaded, audit, audit_sink.as_ref(), trace);
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

    /// The host every plugin instance reaches.
    ///
    /// # Why this is public
    ///
    /// Because the UI channel answers some calls **through the same host the Wasm half uses** — `network.fetch` is the
    /// first. A second fetcher built in the shell would have its own in-flight limit and its own reading of the grants,
    /// so one plugin page and one plugin instance could exceed together what neither may alone, and the two could
    /// disagree about which hosts the user allowed.
    ///
    /// It is `&Arc` rather than the trait object so a caller can clone it and **drop this set's lock** before doing
    /// network work: a fetch held under the plugin lock would make every other plugin command wait for the network.
    #[must_use]
    pub fn host(&self) -> &Arc<dyn synra_plugin_host::host_calls::Host> {
        &self.host
    }

    /// Compiles a plugin and makes it askable.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::Compile`] when the engine refuses the bytes, and [`PluginSetError::UndeclaredImport`] when the
    /// artifact imports a host function its capabilities do not cover. A plugin already loaded is replaced, because a
    /// reinstall is how an update arrives and refusing the second write would make updates depend on a clean shutdown.
    pub fn load(&mut self, spec: PluginSpec) -> Result<(), PluginSetError> {
        // A caller that has no digest or consent detail still gets a lifecycle that records what it did; the two steps
        // are installed → validated → granted, and the empty digest is a fact about the caller rather than a bypass.
        self.load_with_lifecycle(spec, String::new(), false)
    }

    /// Loads a plugin and records the manifest digest and consent outcome it was loaded under.
    ///
    /// # Errors
    ///
    /// The same refusals as [`Self::load`], plus [`PluginSetError::Lifecycle`] if the state machine will not make one of
    /// the two moves every load performs.
    pub fn load_with_lifecycle(
        &mut self,
        spec: PluginSpec,
        manifest_digest: String,
        partially_denied: bool,
    ) -> Result<(), PluginSetError> {
        // Scripted backends execute a table of answers, never untrusted component bytes.
        // Every executing backend must admit the complete world before native compilation.
        if self.backend.kind() != synra_plugin_host::BackendKind::Scripted {
            synra_plugin_host::component::inspect(&spec.wasm).map_err(|error| {
                BackendError::Compile {
                    detail: error.to_string(),
                }
            })?;
        }
        let compiled = self.backend.compile(&spec.wasm, spec.id.as_str())?;

        // Actual engine imports must also be covered by this load's effective grants.
        let undeclared = synra_plugin_host::host_surface::undeclared_imports(compiled.imports(), &spec.grants);
        if let Some(import) = undeclared.first() {
            return Err(PluginSetError::UndeclaredImport {
                id: spec.id,
                import: import.clone(),
            });
        }

        let mut lifecycle = Lifecycle::installed(spec.version.clone());
        lifecycle
            .apply(Transition::Validate {
                manifest_digest: manifest_digest.clone(),
            })
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        lifecycle
            .apply(Transition::Grant { partially_denied })
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;

        let pool = synra_plugin_host::InstancePool::new(spec.policy, spec.limit);
        pool.start();
        self.loaded.insert(
            spec.id.clone(),
            Loaded {
                execution: Arc::new(crate::plugin_events::context::Execution {
                    runtime: self.runtime_id,
                    generation: synra_protocol::RequestId::new(),
                    plugin: spec.id.clone(),
                    version: spec.version.clone(),
                    manifest_digest,
                }),
                version: spec.version,
                partially_denied,
                lifecycle,
                compiled,
                pool,
                live: HashMap::new(),
                // One budget per plugin rather than per instance: the rate is a property of what the plugin may
                // spend, and the pool hands out instances freely — a per-instance budget would multiply the allowance
                // by the instance limit.
                authority: {
                    let authority =
                        Authority::new(spec.grants, spec.quota, Arc::new(Mutex::new(Vec::new())));
                    match self.metrics.as_ref() {
                        Some(metrics) => authority.with_metrics(Arc::clone(metrics)),
                        None => authority,
                    }
                },
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

    /// Where a loaded plugin is in its lifecycle, or `None` when it is not loaded.
    ///
    /// The state is the machine's, not a rendering of the loader's flags: a plugin that is compiled but has not answered
    /// `activate` is `Granted`, and the caller that shows a state can say which step is missing.
    #[must_use]
    pub fn lifecycle(&self, id: &PluginId) -> Option<&Lifecycle> {
        self.loaded.get(id).map(|loaded| &loaded.lifecycle)
    }

    /// Records that a loaded plugin answered its `activate`.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::NotLoaded`] if it is not here, and [`PluginSetError::Lifecycle`] if the machine refuses the
    /// move — which would mean the loader activated something it had not finished validating.
    pub fn mark_active(&mut self, id: &PluginId) -> Result<(), PluginSetError> {
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        loaded
            .lifecycle
            .apply(Transition::Activate)
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        Ok(())
    }

    /// Clears a fault, resetting the health ladder so the plugin can be activated again.
    ///
    /// Returns `false` when the plugin is not faulted, which lets a caller fall back to a reload without asking twice.
    /// The ladder is reset **and** the lifecycle is moved back to `Granted`: clearing one without the other would leave a
    /// plugin that is allowed to run but still refused by `call`, or one that is still marked broken on the card.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::NotLoaded`] when it is not here, and [`PluginSetError::Lifecycle`] if the machine refuses the
    /// move.
    pub fn clear_fault(&mut self, id: &PluginId, now_ms: u64) -> Result<bool, PluginSetError> {
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        if !matches!(loaded.lifecycle.state(), State::Faulted { .. }) {
            return Ok(false);
        }
        loaded
            .lifecycle
            .apply(Transition::ClearFault)
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        loaded
            .lifecycle
            .apply(Transition::Grant { partially_denied: loaded.partially_denied })
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        loaded.authority.budget.reset(now_ms);
        Ok(true)
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
        self.call_traced(id, work, budget, now_ms, None)
    }

    /// The same call, stamped with the trace of the user action it belongs to.
    ///
    /// # Why the trace is an argument rather than ambient
    ///
    /// Because most calls have no action behind them: `can-handle` runs for every plugin the router asks, before the user
    /// has chosen anything, and a lifecycle tick belongs to the plugin's life rather than to a share. Inventing a trace for
    /// those would make the audit say every matching pass was part of one user action. The calls that do have one — the
    /// confirmed action — are exactly the ones that pass a trace here, and the audit entries they produce carry it.
    ///
    /// # Errors
    ///
    /// As [`Self::call`].
    pub fn call_traced(
        &mut self,
        id: &PluginId,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
        now_ms: u64,
        trace: Option<synra_protocol::ids::TraceId>,
    ) -> Result<CallOutcome, PluginSetError> {
        // ★ The action is made current for the whole call, including the guest's host functions. That is what lets a
        // plugin's own `log` line carry the trace without a trace argument in the plugin contract — the thread running the
        // call is the one that knows it.
        let _scope = synra_observe::trace_scope::enter(trace);
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        // ★ A faulted plugin is installed and has bytes, but the host has stopped asking. Running it again would make
        // the lifecycle decorative: the state exists to refuse calls, and this is the refusal.
        if let State::Faulted { reason, .. } = loaded.lifecycle.state() {
            return Err(PluginSetError::Faulted { id: id.clone(), reason: reason.clone() });
        }
        let _execution = crate::plugin_events::context::enter(Arc::clone(&loaded.execution));
        let handle = match loaded.pool.acquire(None, now_ms) {
            Ok(handle) => handle,
            // A plugin at its instance limit is reported, not waited on. The caller turns this into something the user
            // can act on; a retry loop here would hide the limit by turning it into latency.
            Err(_) => {
                return Err(PluginSetError::AtInstanceLimit { id: id.clone() });
            }
        };
        let started = std::time::Instant::now();
        // ★ Whether this handle already had an instance when the call started. That is exactly what a "pool hit" means
        // — the pool handed out a warm slot — and it is knowable here because `live` is the set's own map, not the pool's.
        let had_instance = loaded.live.contains_key(&handle);
        let outcome = Self::run_on(&self.backend, &self.host, loaded, id, handle, work, budget);
        // ★ The plugin group's counter and latency, recorded here because this is the one funnel every call goes through —
        // the matcher's `can-handle`, an action invocation and a lifecycle tick all pass `call`.
        //
        // The interface comes from `Work::interface`, which is the protocol's own spelling (`share`, `actions`,
        // `lifecycle`); a second match here would be the third vocabulary for the same three names.
        if let Some(metrics) = &self.metrics {
            let labels = [
                ("interface".to_owned(), work.interface().to_owned()),
                ("plugin".to_owned(), id.as_str().to_owned()),
            ];
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new("plugin_calls_total", labels.clone()));
            metrics.histogram_observe(
                &synra_observe::metrics::SeriesKey::new("plugin_call_duration_us", labels),
                started.elapsed().as_secs_f64() * 1_000_000.0,
            );
        }
        // ★ A call the plugin misbehaved in counts against its health, which nothing did before.
        //
        // The ladder in `quota::Budget` was reached only by rate-limit refusals, so a plugin that trapped on every call was
        // never degraded: a trap is not a rate, it produced no refusals, nothing counted, and a plugin that could not run
        // kept being asked. `12` recorded that as a missing path, and this is the missing call.
        //
        // Here rather than inside `run_on` because this is where the clock is and where the plugin's own `Budget` is
        // reachable — `run_on` takes the *call* budget, which is a different type with a different job.
        if outcome.as_ref().is_ok_and(CallOutcome::is_misbehaviour) {
            let before = loaded.authority.budget.health();
            loaded.authority.budget.record_misbehaviour(now_ms);
            let after = loaded.authority.budget.health();
            // ★ The health rung is a fact the window can draw, and until this line nothing told it: `PluginHealthChanged`
            // existed in the contract with no publisher. The sink is called only when the rung actually moved, so a
            // plugin that traps ten times at `good` does not produce ten identical events.
            if after != before {
                let report = loaded.authority.budget.report();
                if let Some(sink) = &self.health_sink {
                    sink(id, &report.health, &report.explanation);
                }
                // ★ When the ladder reaches the bottom, the lifecycle follows it. A plugin that trapped, timed out or
                // exhausted its fuel often enough is `Faulted`, and every later call is refused above until a user
                // re-enables it (which reloads) — a health rung nobody enforces is a report, not a decision.
                if after == Health::Faulted {
                    let _ = loaded.lifecycle.apply(Transition::Fault { reason: report.explanation });
                }
            }
            // ★ And the counter the plugin's card can show without reading its health ladder: a plugin that trapped five
            // times is a different story from one that has never run. The outcome is the protocol's own name (`trap`,
            // `timeout`, …), so "why did it fault" is a label rather than a second counter per kind.
            if let Some(metrics) = &self.metrics {
                let outcome = outcome.as_ref().map_or("unknown", CallOutcome::as_str);
                metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                    "plugin_faulted_total",
                    [
                        ("outcome".to_owned(), outcome.to_owned()),
                        ("plugin".to_owned(), id.as_str().to_owned()),
                    ],
                ));
            }
        }
        // ★ The instance's memory, read after the call and before the pool releases the handle: it is the only moment
        // the set can see how much the plugin is holding, and the number is what the design's `plugin_memory_bytes` gauge
        // names. A gauge rather than a delta, because memory can be given back.
        if let Some(metrics) = &self.metrics
            && let Some(instance) = loaded.live.get(&handle)
        {
            metrics.gauge_set(
                &synra_observe::metrics::SeriesKey::new(
                    "plugin_memory_bytes",
                    [("plugin".to_owned(), id.as_str().to_owned())],
                ),
                i64::try_from(instance.memory_bytes()).unwrap_or(i64::MAX),
            );
            // ★ And the fuel the call spent, when the engine counts it: a histogram because the question is "how close to
            // the budget does this plugin run", which is a distribution rather than a current value.
            if let Some(fuel) = instance.last_fuel_consumed() {
                #[allow(clippy::cast_precision_loss)]
                metrics.histogram_observe(
                    &synra_observe::metrics::SeriesKey::new(
                        "plugin_fuel_consumed",
                        [("plugin".to_owned(), id.as_str().to_owned())],
                    ),
                    fuel as f64,
                );
            }
        }
        // ★ One of the two, per call, from the flag taken before the call. A call that could not start (the pool refused
        // it) never reaches here, so the pair always sums to the calls the pool actually served.
        if let Some(metrics) = &self.metrics {
            let counter = if had_instance { "plugin_pool_hit_total" } else { "plugin_pool_miss_total" };
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(counter, []));
        }
        let _ = loaded.pool.release(handle, now_ms);
        // ★ Drained **after** the call, not inside it: the entries are produced while the guest runs, and the ring lives
        // behind the set that the caller is borrowing. Collecting here is also what keeps the buffer one call deep.
        Self::drain_audit(loaded, &mut self.audit, self.audit_sink.as_ref(), trace);
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
            Ok(result) => {
                let outcome = result.map_err(PluginSetError::Compile)?;
                // ★ And the same rule applies when the **engine** stopped the guest, which is where it was missing.
                //
                // The panic path above discards the instance because a store that unwound out of a call cannot be reasoned
                // about. A guest that ran out of fuel, hit its memory ceiling or was interrupted by the clock is in exactly
                // that condition: it trapped **mid-execution**, and a trapped component instance cannot be entered again.
                // wasmtime answers the next call with `Trap { "cannot enter component instance" }`.
                //
                // Keeping it made one overrun permanent. Every later call to that plugin failed with a trap that says
                // nothing about the plugin and everything about the instance the kernel was holding, and the only remedy a
                // user had was to restart the app. Discarding it costs one instantiation on the next call, which is what the
                // pool exists for, and it is the difference between a plugin that misbehaved once and one that is broken.
                if outcome.is_misbehaviour() {
                    loaded.live.remove(&handle);
                }
                Ok(outcome)
            }
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

    use super::{Authority, PluginSetError};

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

    #[test]
    fn every_plugin_failure_names_a_code_the_interface_branches_on() {
        // ★ The mapping used to be `Internal` for all of them, which told a user to file a bug whether the plugin was
        // missing, throttled, or had trapped.
        use synra_protocol::ErrorCode;

        let id = PluginId::parse("@acme/hello").expect("a plugin id");
        assert_eq!(
            PluginSetError::NotLoaded { id: id.clone() }.code(),
            ErrorCode::PluginNotInstalled
        );
        assert_eq!(
            PluginSetError::AtInstanceLimit { id: id.clone() }.code(),
            ErrorCode::RateLimited
        );
        assert_eq!(
            PluginSetError::UndeclaredImport { id: id.clone(), import: "host.call".to_owned() }.code(),
            ErrorCode::CapabilityDenied
        );
        assert_eq!(
            PluginSetError::Faulted { id, reason: "too many traps".to_owned() }.code(),
            ErrorCode::PluginTrapped
        );
    }
}
