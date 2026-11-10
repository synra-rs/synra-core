use std::fmt;

/// Which engine compiles and runs a plugin's artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum BackendKind {
    /// The full `wasmtime` engine with its JIT. The desktop default: fastest to run, slowest to build.
    WasmtimeCranelift,
    /// `wasmtime` with the Winch baseline compiler: quicker to compile, slower to run.
    WasmtimeWinch,
    /// `wasmtime`'s interpreter, for targets where a JIT is not allowed.
    WasmtimePulley,
    /// A pure-Rust interpreter, for the smallest binary.
    Wasmi,
    /// A backend that executes nothing and answers from a script.
    ///
    /// ★ Not a mock in the testing sense — it is the *only* backend that exists when the `wasm-runtime` feature is off,
    /// and it is what makes the pool, the budget accounting and the isolation policy testable without an engine. A
    /// backend that only ever said "ok" would prove nothing; this one is driven by a table of answers, so a test can
    /// ask for a trap and see the trap reach the caller.
    Scripted,
}

impl BackendKind {
    /// Every backend, for a caller that lists them.
    pub const ALL: &'static [Self] = &[
        Self::WasmtimeCranelift,
        Self::WasmtimeWinch,
        Self::WasmtimePulley,
        Self::Wasmi,
        Self::Scripted,
    ];

    /// The backend a platform runs by default.
    ///
    /// # Why Android is not the desktop default
    ///
    /// Because package size matters there and a baseline compiler is the compromise the design document names: a JIT
    /// costs build time on a phone and an interpreter costs every call. Neither costs anything here, so this is a
    /// table rather than a decision.
    #[must_use]
    pub const fn default_for(platform: HostKind) -> Self {
        match platform {
            HostKind::Desktop => Self::WasmtimeCranelift,
            HostKind::Mobile => Self::WasmtimeWinch,
            HostKind::Headless => Self::WasmtimeCranelift,
        }
    }

    /// A stable name, for a cache key and a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmtimeCranelift => "wasmtime-cranelift",
            Self::WasmtimeWinch => "wasmtime-winch",
            Self::WasmtimePulley => "wasmtime-pulley",
            Self::Wasmi => "wasmi",
            Self::Scripted => "scripted",
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What kind of machine the host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostKind {
    /// A window, a mouse and a filesystem the user can see.
    Desktop,
    /// A phone or a tablet.
    Mobile,
    /// No interface at all: a CLI, a daemon, a test.
    Headless,
}

impl HostKind {
    /// A stable name, which is what `env-host-kind` answers with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
            Self::Headless => "headless",
        }
    }
}

impl fmt::Display for HostKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One entry point the host calls on a plugin.
///
/// # Why this is four variants and not a string
///
/// Because these are the *only* things a host may call, and they are the only four the contract exports. A free string
/// would let a typo name an export that does not exist, and the failure would be a link error at instantiation time
/// rather than a value that cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Work {
    /// `lifecycle.activate`, with the plugin's own settings as JSON.
    Activate {
        /// The plugin's settings, as the JSON object the store holds.
        config_json: String,
    },
    /// `lifecycle.deactivate`. Carries nothing: the contract's own signature has no return value either.
    Deactivate,
    /// `lifecycle.migrate`.
    Migrate {
        /// The version being left.
        from_version: String,
        /// The version being arrived at.
        to_version: String,
    },
    /// `lifecycle.on-tick`, with whatever the timer wanted to say.
    Tick {
        /// The tick's payload, as JSON.
        tick_json: String,
    },
    /// `lifecycle.on-event`, selected by the manifest and authorized by the current host context.
    Event {
        /// The complete event context, encoded as JSON by the host.
        event_json: String,
    },
    /// `share.can-handle`. Runs without side effects, and before the user has chosen anything.
    CanHandle {
        /// The share, as JSON.
        item_json: String,
    },
    /// `share.execute`.
    Execute {
        /// The action `can-handle` proposed.
        action: String,
        /// Its arguments, as JSON.
        args_json: String,
    },
    /// `actions.invoke`, for another plugin calling this one's action.
    InvokeAction {
        /// The action's name.
        name: String,
        /// Its arguments, as JSON.
        args_json: String,
    },
}

impl Work {
    /// The interface the export belongs to.
    #[must_use]
    pub const fn interface(&self) -> &'static str {
        match self {
            Self::Activate { .. }
            | Self::Deactivate
            | Self::Migrate { .. }
            | Self::Tick { .. }
            | Self::Event { .. } => "lifecycle",
            Self::CanHandle { .. } | Self::Execute { .. } => "share",
            Self::InvokeAction { .. } => "actions",
        }
    }

    /// The export's name within its interface.
    #[must_use]
    pub const fn function(&self) -> &'static str {
        match self {
            Self::Activate { .. } => "activate",
            Self::Deactivate => "deactivate",
            Self::Migrate { .. } => "migrate",
            Self::Tick { .. } => "on-tick",
            Self::Event { .. } => "on-event",
            Self::CanHandle { .. } => "can-handle",
            Self::Execute { .. } => "execute",
            Self::InvokeAction { .. } => "invoke",
        }
    }

    /// Whether this call is allowed to have side effects.
    ///
    /// # Why the host enforces this rather than trusting the plugin
    ///
    /// `can-handle` runs for **every** plugin the router asks, before a user has chosen anything. A plugin that wrote a
    /// file, opened a browser or sent a message there would have done it for every share the user then cancelled. The
    /// contract says the function has no side effects; the host is what makes that true, by running it with a context
    /// whose action-shaped calls are refused.
    #[must_use]
    pub const fn allows_side_effects(&self) -> bool {
        !matches!(self, Self::CanHandle { .. })
    }
}

impl fmt::Display for Work {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.interface(), self.function())
    }
}
