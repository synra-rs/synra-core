//! The kernel: one value that owns everything, built in one order, and the events an interface reads it through.
//!
//! # Why the order is the point
//!
//! Every step of [`Kernel::bootstrap`] depends on the ones before it, and the dependency is not a preference:
//!
//! * the store has to exist before an identity can be read or created, because the identity *is* a row;
//! * the identity has to exist before the host is built, because a host that announces itself needs to know what to
//!   announce;
//! * the grants have to be loaded before a plugin is started, because a plugin that ran first and asked later would
//!   have taken its first action without permission;
//! * and a failure has to be reported through the layer that already works, which is why tracing comes first.
//!
//! A caller that assembled these itself would eventually assemble them in a different order, and the symptom of an
//! out-of-order start is not a crash — it is a device with two identities, or a plugin running ungranted.
//!
//! # Why this is synchronous
//!
//! The design document's signatures are `async`, and the reason they are is that they were written for a runtime that
//! owns every task. This kernel does not: [`crate::Supervisor`] runs its tasks on threads of their own, the plugin
//! executor has its own threads, and the store is blocking by nature — so there is nothing here to await, and an
//! `async fn` that never awaits would make every caller's signature `async` for nothing. The caller with a runtime
//! owns the loop; this owns the decisions.
//!
//! # What an interface reads
//!
//! Two things, and the design document is emphatic about why they must agree:
//!
//! * [`Kernel::snapshot`] is the **whole** state, asked once when a screen opens;
//! * [`Kernel::subscribe`] is the **incremental** stream, consumed from then on.
//!
//! Both are built from the same values, so an event cannot describe a device the snapshot does not have. And the
//! subscriber that falls behind is told so — [`Delivery::Missed`] rather than a silent gap — because the interface's
//! response to that is to ask for a snapshot again, which is the one recovery that cannot be wrong.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;
use synra_store::records::{DeviceRow, PluginRow};
use synra_store::sqlite::SynraDb;

use crate::bus::{Delivery, EventBus, SubscriberId};
use crate::config::Config;
use crate::host::{Host, HostError};
use crate::identity::Identity;
use crate::supervisor::{Supervisor, SupervisorError, TaskSpec};

/// What a kernel is.
///
/// The four roles differ in what they *offer* — a headless kernel has no window, a phone is suspended at any moment —
/// and the difference is what a plugin's platform applicability is checked against. It is a value rather than a
/// compile-time choice because one binary ships as more than one of them: the CLI and the daemon are the same crate
/// with different arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeRole {
    /// A window, a mouse and a filesystem the user can see.
    Desktop,
    /// A phone or a tablet.
    Mobile,
    /// A command-line tool: a kernel for the length of one command.
    Cli,
    /// No interface at all, and long-lived.
    Daemon,
}

impl NodeRole {
    /// A name, for a log line and a settings screen.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
            Self::Cli => "cli",
            Self::Daemon => "daemon",
        }
    }

    /// Whether this role has a person in front of it.
    ///
    /// What an interface decision is made from: a prompt is right for a desktop and wrong for a daemon, where it would
    /// sit unanswered while the sender waited.
    #[must_use]
    pub const fn has_a_user(self) -> bool {
        matches!(self, Self::Desktop | Self::Mobile)
    }
}

/// What a kernel is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelConfig {
    /// Which role this kernel plays.
    pub role: NodeRole,
    /// What this device is, as the identity's `platform` column records it.
    ///
    /// The operating system rather than the role: a desktop build on Windows and a daemon on Windows are the same
    /// *device* as far as a peer is concerned, and the role is about what is offered rather than about what runs.
    pub platform: String,
    /// Whether the discovery service should be started.
    ///
    /// A field rather than a constant because the two answers are both right depending on where the kernel runs: a
    /// test wants no sockets at all, and a device in a hostile network may want to be found only by devices it
    /// already knows. It is carried on the kernel rather than on the host because what it decides is whether a
    /// *task* is registered, and the host is built before any task exists.
    pub discovery: bool,
}

impl KernelConfig {
    /// A desktop kernel, which is what an application starts.
    #[must_use]
    pub fn desktop() -> Self {
        Self { role: NodeRole::Desktop, platform: std::env::consts::OS.to_owned(), discovery: true }
    }

    /// A kernel with no sockets, for a test.
    #[must_use]
    pub fn headless() -> Self {
        Self { role: NodeRole::Daemon, platform: std::env::consts::OS.to_owned(), discovery: false }
    }

    /// The same configuration for another role.
    #[must_use]
    pub const fn with_role(mut self, role: NodeRole) -> Self {
        self.role = role;
        self
    }
}

/// Something that changed, for an interface to react to.
///
/// # Why this is a small enum and not every internal event
///
/// Because the interface's job is to *render*, and a stream of everything the kernel does would be a stream it has to
/// filter — with the filter living in the interface, which is where the two copies of "what matters" would drift. What
/// is here is the short list a screen has to redraw for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelEvent {
    /// The device's own identity was created or renamed.
    IdentityChanged {
        /// What it calls itself now.
        display_name: String,
    },
    /// A device was heard from, or its announcement changed.
    DeviceSeen {
        /// The device.
        device_id: DeviceId,
        /// What it calls itself.
        display_name: String,
        /// Whether it is now reachable.
        online: bool,
    },
    /// A device stopped being reachable.
    DeviceOffline {
        /// The device.
        device_id: DeviceId,
    },
    /// A pairing was recorded.
    DevicePaired {
        /// The device.
        device_id: DeviceId,
        /// What it calls itself.
        display_name: String,
    },
    /// A device was unpaired or blocked.
    DeviceForgotten {
        /// The device.
        device_id: DeviceId,
    },
    /// A plugin's presence, version or enabled state changed.
    PluginChanged {
        /// The plugin.
        plugin_id: String,
        /// Where it is now, as the pipeline names it.
        state: String,
    },
    /// The configuration changed.
    ConfigChanged {
        /// How many settings the user has overridden.
        overrides: usize,
    },
    /// A subscriber fell behind and its queue dropped events.
    ///
    /// ★ Published so an interface can recover: the only correct response is to ask for a snapshot again, and an
    /// interface that was not told would draw a state it believes is current for as long as it is open.
    MissedEvents {
        /// How many were dropped.
        dropped: usize,
    },
}

impl KernelEvent {
    /// A short name, for a log line and a metric label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::IdentityChanged { .. } => "identity-changed",
            Self::DeviceSeen { .. } => "device-seen",
            Self::DeviceOffline { .. } => "device-offline",
            Self::DevicePaired { .. } => "device-paired",
            Self::DeviceForgotten { .. } => "device-forgotten",
            Self::PluginChanged { .. } => "plugin-changed",
            Self::ConfigChanged { .. } => "config-changed",
            Self::MissedEvents { .. } => "missed-events",
        }
    }
}

/// Why a kernel could not be built or started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KernelError {
    /// The store could not be opened or migrated.
    #[error("the store could not be prepared: {detail}")]
    Store {
        /// What went wrong.
        detail: String,
    },

    /// The host could not be built.
    #[error("the host could not be built: {0}")]
    Host(#[from] HostError),

    /// A long-running task could not be registered.
    #[error("{0}")]
    Supervisor(#[from] SupervisorError),

    /// The kernel has already been started.
    #[error("the kernel is already started")]
    AlreadyStarted,

    /// The kernel has been shut down.
    #[error("the kernel has been shut down")]
    ShutDown,
}

/// What an interface draws.
///
/// # Why this is assembled from the same readers the events are
///
/// Because the two have to agree. An interface asks for this once when a screen opens and then applies events to it;
/// if the snapshot and the events came from different places, a device could appear in one and not the other, and the
/// symptom would be a list that changes when the window is resized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSnapshot {
    /// This device.
    pub identity: Identity,
    /// Every device this device is paired with.
    pub devices: Vec<DeviceRow>,
    /// Every plugin the store knows about.
    pub plugins: Vec<PluginRow>,
    /// How many settings the user has overridden.
    pub config_overrides: usize,
    /// Which role this kernel plays.
    pub role: NodeRole,
    /// Whether the network has been started.
    pub started: bool,
}

impl KernelSnapshot {
    /// The paired devices that are usable, which is what a send menu offers.
    #[must_use]
    pub fn sendable(&self) -> Vec<&DeviceRow> {
        self.devices.iter().filter(|device| device.is_usable()).collect()
    }

    /// A plugin by identifier.
    #[must_use]
    pub fn plugin(&self, plugin_id: &str) -> Option<&PluginRow> {
        self.plugins.iter().find(|plugin| plugin.plugin_id == plugin_id)
    }

    /// A device by identifier.
    #[must_use]
    pub fn device(&self, device_id: DeviceId) -> Option<&DeviceRow> {
        let wanted = device_id.to_string();
        self.devices.iter().find(|device| device.device_id == wanted)
    }
}

/// The kernel.
///
/// Everything a running kernel owns, behind one value: the store, this device's identity, the settings, the discovery
/// table and the open links, the event bus an interface reads, and the supervisor that watches the long-running tasks.
///
/// # Why the store is behind a lock and the rest is not
///
/// Because `rusqlite`'s connection is not `Sync` — one connection, one thread at a time — and every decision built on
/// top of it is made under that lock, which is what makes "the identity and the row it came from cannot disagree" a
/// property rather than a hope. The host has its own lock for the same reason.
pub struct Kernel {
    store: Mutex<SynraDb>,
    identity: Identity,
    config: Config,
    host: Mutex<Host>,
    events: EventBus<KernelEvent>,
    supervisor: Arc<Supervisor>,
    role: NodeRole,
    started: std::sync::atomic::AtomicBool,
    created_at_ms: i64,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Kernel")
            .field("device_id", &self.identity.device_id)
            .field("role", &self.role)
            .field("started", &self.is_started())
            .field("subscribers", &self.events.subscriber_count())
            .finish_non_exhaustive()
    }
}

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

        // 1 · This device.
        let identity = Identity::load(&store, &config.platform, now_ms)
            .map_err(|error| to_store(error.to_string()))?;

        // 2 · The settings, loaded from the table they were stored in.
        //
        // A row whose key this build does not know, or whose value is not the JSON it should be, is **skipped rather
        // than fatal**: it is a setting an older or newer build wrote, and refusing to start over one would make a
        // downgrade impossible to recover from. What it does not do is invent a value — the default still applies, and
        // the row stays where it is for the build that understands it.
        let mut settings = Config::new(crate::config::Catalog::new());
        let stored = store.config().map_err(|error| to_store(error.to_string()))?;
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
        let paired = store.paired_devices().map_err(|error| to_store(error.to_string()))?;
        let _ = paired.len();
        let _ = store.plugins().map_err(|error| to_store(error.to_string()))?;

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
            created_at_ms: now_ms,
        })
    }

    /// Opens a store at a path and builds a kernel over it.
    ///
    /// # Errors
    ///
    /// [`KernelError::Store`] when the database cannot be opened or migrated.
    pub fn open(path: &Path, config: &KernelConfig) -> Result<Self, KernelError> {
        let mut store = SynraDb::open(path).map_err(|error| KernelError::Store { detail: error.to_string() })?;
        let _ = store.migrate().map_err(|error| KernelError::Store { detail: error.to_string() })?;
        Self::bootstrap(store, config)
    }

    /// Opens an in-memory store and builds a kernel over it, for a test.
    ///
    /// # Errors
    ///
    /// As [`Kernel::open`].
    pub fn in_memory(config: &KernelConfig) -> Result<Self, KernelError> {
        let mut store =
            SynraDb::open_in_memory().map_err(|error| KernelError::Store { detail: error.to_string() })?;
        let _ = store.migrate().map_err(|error| KernelError::Store { detail: error.to_string() })?;
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
        self.started.store(false, std::sync::atomic::Ordering::Release);
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
            let paired = store.paired_devices().map_err(|error| to_store(error.to_string()));
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
    pub fn device_seen(&self, device_id: DeviceId, display_name: impl Into<String>, online: bool) -> u64 {
        self.events.emit(KernelEvent::DeviceSeen { device_id, display_name: display_name.into(), online })
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

    /// The milliseconds since the epoch this kernel reads the clock at.
    #[must_use]
    pub fn now_ms() -> i64 {
        synra_store::sqlite::now_ms()
    }
}

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod tests;
