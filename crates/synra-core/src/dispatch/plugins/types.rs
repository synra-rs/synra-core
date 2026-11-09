use super::*;

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
pub(super) struct Loaded {
    pub(super) execution: Arc<crate::plugin_events::context::Execution>,
    pub(super) version: String,
    /// Whether the user denied part of what this plugin asked for, kept so clearing a fault can re-grant honestly.
    pub(super) partially_denied: bool,
    /// Where this plugin is in its life: installed, validated, granted, active, faulted.
    ///
    /// Stored beside the compiled form rather than derived on read, because the transitions are what make the ladder
    /// meaningful: a state recomputed from flags cannot refuse a move, and a refusal is the only thing it is for.
    pub(super) lifecycle: Lifecycle,
    pub(super) compiled: Box<dyn CompiledArtifact>,
    pub(super) pool: synra_plugin_host::InstancePool,
    pub(super) live: HashMap<u64, Box<dyn PluginInstance>>,
    /// What this plugin may do: its grants, its rate and its record.
    ///
    /// Separated from the artifact because the two answer different questions — "what is this" and "what may it do" —
    /// and because the second is a statement that should be testable without a `.wasm` fixture to compile.
    pub(super) authority: Authority,
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
    pub(super) grants: CapabilitySet,
    pub(super) budget: Arc<synra_plugin_host::quota::Budget>,
    pub(super) audit: Arc<Mutex<Vec<synra_observe::audit::AuditEntry>>>,
    /// Where this plugin's gate decisions are counted, when the kernel keeps numbers.
    pub(super) metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
}

impl Authority {
    /// A plugin's authority: what it holds, what it may spend, and where its record goes.
    #[must_use]
    pub(crate) fn new(
        grants: CapabilitySet,
        quota: synra_plugin_host::quota::Quota,
        audit: Arc<Mutex<Vec<synra_observe::audit::AuditEntry>>>,
    ) -> Self {
        Self {
            grants,
            metrics: None,
            budget: Arc::new(synra_plugin_host::quota::Budget::new(quota)),
            audit,
        }
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
