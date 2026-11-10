use std::path::Path;

use super::*;

impl Kernel {
    /// Builds a kernel over an already-open store.
    ///
    /// # The order, and why each step is where it is
    ///
    /// 1. **The identity**, read or created — first, because everything a peer sees is derived from it, and because a
    ///    second identity is the failure the protocol's own notes name.
    /// 2. **The settings**, so a later step can consult them.
    /// 3. **The paired devices**, which is the trust the host is built with.
    /// 4. **The plugins**, which is what the interface lists.
    /// 5. **The host**, last of the values, because it is built *from* the identity and the paired devices.
    /// 6. **The supervisor**, which is where the long-running work will be registered — and it is created empty, so a
    ///    caller can register a task before anything starts.
    ///
    /// # Errors
    ///
    /// [`KernelError::Store`] when a read fails, and [`KernelError::Host`] when the host cannot be built from what was
    /// read.
    pub fn bootstrap(store: SynraDb, config: &KernelConfig) -> Result<Self, KernelError> {
        let now_ms = synra_store::sqlite::now_ms();
        let to_store = |detail: String| KernelError::Store { detail };

        // 1 · What the last run left behind, read before anything else — because a report of what went wrong has to be
        // recorded by the layer that is already working, and because a kernel that crashed last time should say so
        // before it does anything a user could see.
        let verdict = config
            .crash_log
            .as_ref()
            .map_or(StartupVerdict::Clean, |directory| {
                synra_observe::crash::CrashStore::new(directory).verdict(now_ms)
            });

        // 2 · This device.
        let identity = Identity::load(&store, &config.platform, now_ms)
            .map_err(|error| to_store(error.to_string()))?;

        // 2 · The settings, loaded from the table they were stored in.
        //
        // A row whose key this build does not know, or whose value is not the JSON it should be, is **skipped rather
        // than fatal**: it is a setting an older or newer build wrote, and refusing to start over one would make a
        // downgrade impossible to recover from. What it does not do is invent a value — the default still applies, and
        // the row stays where it is for the build that understands it.
        let mut settings = Config::new(crate::config::Catalog::new());
        let stored = store
            .config()
            .map_err(|error| to_store(error.to_string()))?;
        let pairs: Vec<(crate::config::SettingKey, serde_json::Value)> = stored
            .into_iter()
            .filter_map(|row| {
                let key = crate::config::SettingKey::parse(&row.key).ok()?;
                let value = serde_json::from_str(&row.value).ok()?;
                Some((key, value))
            })
            .collect();
        let _ = settings.apply(&pairs, &[]);

        // 3 · The trust this device already has, and 4 · the plugins the interface will list.
        //
        // Read here rather than lazily by the first caller, and for a reason the daemon's own pairing test makes: a
        // store that cannot answer is a store that will fail every later read, and a kernel that reported itself
        // started and then failed each question would be one whose first symptom is a screen that never fills in. The
        // rows are not kept — a list a caller asks for should be the list as it is now, not as it was at start — so
        // what this buys is the *check*.
        let paired = store
            .paired_devices()
            .map_err(|error| to_store(error.to_string()))?;
        let _ = paired.len();
        let _ = store
            .plugins()
            .map_err(|error| to_store(error.to_string()))?;

        // 5 · The host, from the identity and the trust — which is why it is last of the values.
        //
        // A host with no discovery is still a host: it can dial and be dialled, and what it does not do is announce
        // itself. That is the configuration a test and a locked-down device both want, and it is why `discovery` is a
        // field rather than a compile-time choice.
        let local = crate::peer::LocalPeer::new(
            identity.device_id,
            identity.display_name.clone(),
            crate::platform_of_os(&identity.platform),
            env!("CARGO_PKG_VERSION"),
        );
        let host = Host::with_flags(identity.clone(), local, crate::peer::Flags::production());

        // 6 · The supervisor, empty: what runs is registered by whoever knows what this role needs.
        let supervisor = Arc::new(Supervisor::new(now_ms));

        Ok(Self {
            store: Mutex::new(store),
            identity,
            config: settings,
            host: Mutex::new(host),
            events: EventBus::new(),
            supervisor,
            role: config.role,
            started: std::sync::atomic::AtomicBool::new(false),
            audit: Mutex::new(AuditRing::new()),
            verdict,
            created_at_ms: now_ms,
        })
    }

    /// Opens a store at a path and builds a kernel over it.
    ///
    /// # Errors
    ///
    /// [`KernelError::Store`] when the database cannot be opened or migrated.
    pub fn open(path: &Path, config: &KernelConfig) -> Result<Self, KernelError> {
        let mut store = SynraDb::open(path).map_err(|error| KernelError::Store {
            detail: error.to_string(),
        })?;
        let _ = store.migrate().map_err(|error| KernelError::Store {
            detail: error.to_string(),
        })?;
        Self::bootstrap(store, config)
    }

    /// Opens an in-memory store and builds a kernel over it, for a test.
    ///
    /// # Errors
    ///
    /// As [`Kernel::open`].
    pub fn in_memory(config: &KernelConfig) -> Result<Self, KernelError> {
        let mut store = SynraDb::open_in_memory().map_err(|error| KernelError::Store {
            detail: error.to_string(),
        })?;
        let _ = store.migrate().map_err(|error| KernelError::Store {
            detail: error.to_string(),
        })?;
        Self::bootstrap(store, config)
    }

    /// This device's identity.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Which role this kernel plays.
    #[must_use]
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    /// When the kernel was built.
    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    /// The supervisor the long-running tasks are registered with.
    #[must_use]
    pub const fn supervisor(&self) -> &Arc<Supervisor> {
        &self.supervisor
    }

    /// Whether the network has been started.
    #[must_use]
    pub fn is_started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::Acquire)
    }
}
