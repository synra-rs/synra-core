use super::*;

impl Kernel {
    /// Registers a long-running task, and starts it.
    ///
    /// # Errors
    ///
    /// [`KernelError::Supervisor`] for a name that is taken, and [`KernelError::ShutDown`] afterwards.
    ///
    /// # Why a task can only be registered before `start`
    ///
    /// Because a task registered afterwards is one nothing announced: its first effect would be observable to an
    /// interface that had already been told the kernel was running, which is the ordering the design document's
    /// startup sequence exists to make impossible.
    pub fn register_task(&self, spec: TaskSpec) -> Result<(), KernelError> {
        if self.is_started() {
            return Err(KernelError::AlreadyStarted);
        }
        self.supervisor.register(spec)?;
        Ok(())
    }

    /// Marks the kernel started, and publishes that it was.
    ///
    /// # What starting means here
    ///
    /// The *decisions* are already made — the store is open, the identity is loaded, the tasks are registered. What
    /// this changes is that an interface may now read the kernel as running, which is the signal the design document
    /// says the first screen should not wait for: the network comes up in parallel with rendering, not before it.
    ///
    /// # Errors
    ///
    /// [`KernelError::AlreadyStarted`] when it is already running.
    pub fn start(&self) -> Result<(), KernelError> {
        // ★ A compare-and-swap rather than a lock, because this is the one flag two threads reach at once: a window
        // asking whether the kernel is running while a task is asking it to stop. A `Mutex` around a boolean would also
        // be a lock somebody could later hold across something else, which is how a start-up path deadlocks.
        if self
            .started
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return Err(KernelError::AlreadyStarted);
        }

        let _ = self.events.emit(KernelEvent::IdentityChanged {
            display_name: self.identity.display_name.clone(),
        });
        Ok(())
    }

    /// Asks everything to stop, in the order the supervisor gives.
    ///
    /// # Returns
    ///
    /// The names in the order they should be stopped: reverse registration, so a task that depends on another is
    /// stopped before the thing it depends on.
    ///
    /// # Errors
    ///
    /// [`KernelError::ShutDown`] when it has already been asked.
    pub fn shutdown(&self) -> Result<Vec<crate::supervisor::TaskId>, KernelError> {
        if self.supervisor.is_shutting_down() {
            return Err(KernelError::ShutDown);
        }
        let order = self.supervisor.begin_shutdown();
        // Written through a binding the compiler can see the end of, rather than through a `drop` call on a guard that
        // A release store, paired with the acquire load in `is_started`: what the flag orders is whether an interface
        // may read the kernel as running, and an interface that saw `true` before the flag was actually written would
        // be one drawing a kernel that is already stopping.
        self.started
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(order)
    }

    /// What an interface draws.
    ///
    /// # Errors
    ///
    /// [`KernelError::Store`] when a read fails. A snapshot that silently dropped a failed read would be a screen
    /// showing an empty list for a database that did not answer, which is the one thing an empty list must not mean.
    pub fn snapshot(&self) -> Result<KernelSnapshot, KernelError> {
        let to_store = |detail: String| KernelError::Store { detail };
        // The two reads, and the guard released before the snapshot is built — it holds nothing the snapshot needs, and
        // a lock held while a struct is constructed is a lock every other reader is waiting on.
        let (devices, plugins) = self.with_store(|store| {
            let paired = store
                .paired_devices()
                .map_err(|error| to_store(error.to_string()));
            let plugins = store.plugins().map_err(|error| to_store(error.to_string()));
            paired.and_then(|devices| plugins.map(|plugins| (devices, plugins)))
        })?;

        Ok(KernelSnapshot {
            identity: self.identity.clone(),
            devices,
            plugins,
            config_overrides: self.config.override_count(),
            role: self.role,
            started: self.is_started(),
        })
    }

    /// Registers a subscriber to the event stream.
    ///
    /// The identifier is what [`Kernel::next_event`] takes, and dropping it is the whole of unsubscribing — which is
    /// why the interface does not have to remember to.
    #[must_use]
    pub fn subscribe(&self) -> SubscriberId {
        self.events.subscribe()
    }

    /// Stops subscribing.
    ///
    /// # Returns
    ///
    /// Whether there was a subscriber to remove.
    pub fn unsubscribe(&self, subscriber: SubscriberId) -> bool {
        self.events.unsubscribe(subscriber)
    }

    /// The next event for a subscriber.
    ///
    /// # Returns
    ///
    /// `None` when the queue has nothing waiting — a poll, not a wait, so the caller's loop decides how long to sleep.
    /// [`Delivery::Missed`] when events were dropped, which the interface's own answer to is to ask for a snapshot
    /// again.
    #[must_use]
    pub fn next_event(&self, subscriber: SubscriberId) -> Option<Delivery<KernelEvent>> {
        self.events.take(subscriber)
    }

    /// Publishes an event.
    ///
    /// # Returns
    ///
    /// The sequence number, which is what an interface uses to tell an event it has already applied from a new one.
    pub fn publish(&self, event: KernelEvent) -> u64 {
        self.events.emit(event)
    }

    /// Publishes that a device was heard from.
    pub fn device_seen(
        &self,
        device_id: DeviceId,
        display_name: impl Into<String>,
        online: bool,
    ) -> u64 {
        self.events.emit(KernelEvent::DeviceSeen {
            device_id,
            display_name: display_name.into(),
            online,
        })
    }

    /// Publishes that a device stopped being reachable.
    pub fn device_offline(&self, device_id: DeviceId) -> u64 {
        self.events.emit(KernelEvent::DeviceOffline { device_id })
    }

    /// The settings.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// The settings and the host, for a caller that needs both.
    ///
    /// # Why this exists
    ///
    /// Because the two are the kernel's mutable halves and a caller that needs them together would otherwise take two
    /// locks in an order it chose — which is how a deadlock between two callers is written.
    pub fn with_host<T>(&self, work: impl FnOnce(&mut Host) -> T) -> T {
        let mut host = self.host.lock();
        work(&mut host)
    }

    /// The store, for a caller that owns a read the kernel does not offer.
    ///
    /// # Why this takes the lock rather than handing out the connection
    ///
    /// Because `rusqlite`'s connection is `!Sync`, and a reference that outlived the call would be a connection used
    /// from two threads — which is a data race the compiler cannot catch through a `&`. The closure is the lock's
    /// scope, and it is the only shape that makes the borrowing rule true.
    pub fn with_store<T>(&self, work: impl FnOnce(&SynraDb) -> T) -> T {
        let store = self.store.lock();
        work(&store)
    }

    /// What the last run left behind.
    ///
    /// Read during the bootstrap, and it stays as it was read: the question a startup screen asks is "did the *previous*
    /// run end badly", and a value that changed while the kernel ran would be answering about this one.
    ///
    /// Cloned rather than borrowed because a `Crashed` verdict carries its report, and a caller that has to hold the
    /// kernel's lock to read it would be one that cannot show it and do anything else at the same time.
    #[must_use]
    pub fn startup_verdict(&self) -> StartupVerdict {
        self.verdict.clone()
    }

    /// Records what a plugin did, for the audit a user can read.
    ///
    /// # Why this is on the kernel and not on the plugin host
    ///
    /// Because the ring outlives any one plugin: a plugin that was removed still has the actions it took, and a
    /// per-plugin ring would have been dropped with it. The kernel is the thing that is still there.
    pub fn record_action(&self, entry: synra_observe::audit::AuditEntry) {
        self.audit.lock().record(entry);
    }

    /// Everything the audit ring holds, oldest first.
    #[must_use]
    pub fn audit(&self) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.lock().all()
    }

    /// What one plugin did.
    #[must_use]
    pub fn audit_for(
        &self,
        plugin: &synra_protocol::ids::PluginId,
    ) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.lock().for_plugin(plugin)
    }

    /// The milliseconds since the epoch this kernel reads the clock at.
    #[must_use]
    pub fn now_ms() -> i64 {
        synra_store::sqlite::now_ms()
    }
}
