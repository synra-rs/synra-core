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

use crate::host::HostError;
use crate::supervisor::SupervisorError;
use synra_protocol::ids::DeviceId;

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
    /// Where the crash reports of previous runs are kept, when the caller wants them read.
    ///
    /// # Why this is the first thing the bootstrap does
    ///
    /// Because a kernel that crashed last time should say so before it does anything else, and because a report of what
    /// went wrong is the one thing that has to be recorded by the layer which is already working. `None` is a kernel
    /// with no log directory — a test, or a first run before the data directory exists — and it is not an error: the
    /// verdict is then [`StartupVerdict::FirstRun`](crate::observe_verdict) rather than a guess.
    pub crash_log: Option<std::path::PathBuf>,
}

impl KernelConfig {
    /// A desktop kernel, which is what an application starts.
    #[must_use]
    pub fn desktop() -> Self {
        Self {
            role: NodeRole::Desktop,
            platform: std::env::consts::OS.to_owned(),
            discovery: true,
            crash_log: None,
        }
    }

    /// A kernel with no sockets, for a test.
    #[must_use]
    pub fn headless() -> Self {
        Self {
            role: NodeRole::Daemon,
            platform: std::env::consts::OS.to_owned(),
            discovery: false,
            crash_log: None,
        }
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
