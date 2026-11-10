use super::*;

/// The plugins this kernel can ask.
///
/// # Why this is not `Clone`
///
/// Because it holds live instances. A Wasm store has fuel, memory and guest globals in it, and a copy of one is not a
/// second store — it is the same store under a second name, which is how two callers end up corrupting one guest's
/// state. The backend is shared deliberately and cheaply; the set of instances is not shared at all.
pub struct PluginSet {
    pub(super) runtime_id: synra_protocol::RequestId,
    pub(super) events: Option<Arc<crate::plugin_events::EventService>>,
    pub(super) backend: Backend,
    pub(super) loaded: HashMap<PluginId, Loaded>,
    /// Where a plugin's effects reach.
    ///
    /// ★ The piece that was missing, and the reason the capability gate never ran. Every instance used to be created
    /// with `session: None`, and `linker::run` refuses **every** host call when there is no session — so no plugin could
    /// reach a host function at all and nothing was audited. The gate is the mechanism the whole capability model rests
    /// on, and it was inert.
    pub(super) host: Arc<dyn synra_plugin_host::host_calls::Host>,
    /// What plugins have done, bounded and readable.
    ///
    /// The kernel already has a ring for this ([`synra_observe::audit::AuditRing`]); what it did not have was a writer,
    /// because the only path to one was `synra_core::Kernel::record_action`, and no host constructs that type.
    pub(super) audit: synra_observe::audit::AuditRing,
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
    pub(super) audit_sink: Option<AuditSink>,
    /// Where the gate's counters go, when the kernel keeps numbers.
    ///
    /// Shared rather than one per plugin, because the design's `gate_*` metrics are read as one series across plugins: the
    /// plugin is a **label** on a series, not a series of its own.
    pub(super) metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
    /// Where a health change goes, when a host has a window to tell.
    ///
    /// ★ Why this is a callback and not an event type here: `synra-core` does not own the event contract, and a kernel
    /// that constructed IPC events would depend on the interface's vocabulary. The host passes what it wants done; the
    /// event's field names are the host's business.
    pub(super) health_sink: Option<HealthSink>,
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

mod audit;
mod query;
mod runtime;
