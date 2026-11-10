use super::BackendKind;

/// How much of one call a plugin may use.
///
/// # Why three limits and not one
///
/// They catch different things, and each catches something the others do not:
///
/// | A plugin that… | fuel | epoch | memory |
/// | --- | --- | --- | --- |
/// | loops forever | ✅ | ✅ | |
/// | calls a host function that blocks | | ✅ | |
/// | allocates until the machine swaps | | | ✅ |
///
/// A fuel limit alone is the trap that looks sufficient: a guest that never returns from a host call consumes no
/// instructions at all, so the wall clock is the only thing that ends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallBudget {
    /// Instructions this call may execute, or `None` for no limit.
    pub fuel: Option<u64>,
    /// How long this call may take, or `None` for no limit.
    pub timeout: Option<std::time::Duration>,
    /// How much the plugin's memory may grow during this call, in bytes, or `None` for no limit.
    pub max_memory_growth: Option<u64>,
}

impl CallBudget {
    /// The budget a plugin's quota asks for.
    ///
    /// Every field is taken from the quota rather than chosen here, so the number a user sees in a settings screen is
    /// the number the sandbox enforces.
    #[must_use]
    pub const fn from_quota(quota: &crate::quota::Quota) -> Self {
        Self {
            fuel: Some(quota.call_fuel),
            timeout: Some(quota.call_timeout()),
            max_memory_growth: Some(quota.max_memory_bytes),
        }
    }

    /// A budget with nothing limited, for a fixture.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self { fuel: None, timeout: None, max_memory_growth: None }
    }
}

/// What a call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallOutcome {
    /// The call returned a value. Payloads crossing the boundary are JSON strings, per the contract.
    Ok(String),
    /// The plugin returned a structured failure. Not a bug: it is a thing the plugin handled and reported.
    Failed {
        /// The plugin's error code, which may also be a forwarded host-call code.
        code: String,
        /// A sentence for a log.
        message: String,
        /// Optional WIT error details, retained verbatim including empty or non-JSON strings.
        details: Option<String>,
    },
    /// The instruction budget ran out.
    FuelExhausted {
        /// The budget that ran out.
        fuel: u64,
    },
    /// The wall clock ran out, which is the only limit that stops a guest blocked inside a host call.
    Timeout {
        /// How long the call was given.
        after: std::time::Duration,
    },
    /// The memory limit was reached.
    MemoryExceeded {
        /// The limit that was reached.
        limit: u64,
    },
    /// The guest trapped: a panic, an out-of-bounds access, an illegal instruction.
    Trap {
        /// What the engine said, which is what a plugin author needs to see.
        detail: String,
    },
}

impl CallOutcome {
    /// Whether the call produced a value the caller can use.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// The payload, when there is one.
    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        match self {
            Self::Ok(payload) => Some(payload),
            _ => None,
        }
    }

    /// Whether this outcome is a reason to distrust the plugin rather than the call.
    ///
    /// # Why the distinction matters to health
    ///
    /// A plugin that returns `Failed` is working: it reached a decision and said so. A plugin that traps, times out or
    /// exhausts its fuel has done something the host had to stop, and a run of those is what the health model degrades
    /// on. Counting both the same way would fault a plugin for reporting an error, which is the behaviour asked of it.
    #[must_use]
    pub const fn is_misbehaviour(&self) -> bool {
        matches!(
            self,
            Self::FuelExhausted { .. } | Self::Timeout { .. } | Self::MemoryExceeded { .. } | Self::Trap { .. }
        )
    }

    /// A stable name, for a metric label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ok(_) => "ok",
            Self::Failed { .. } => "failed",
            Self::FuelExhausted { .. } => "fuel-exhausted",
            Self::Timeout { .. } => "timeout",
            Self::MemoryExceeded { .. } => "memory-exceeded",
            Self::Trap { .. } => "trap",
        }
    }
}

/// Why a plugin could not be compiled or instantiated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BackendError {
    /// This host's engine cannot enforce a limit its own budgets ask for.
    ///
    /// ★ Why this is a startup refusal rather than a call-time one.
    ///
    /// `engine/mod.rs` writes the layer's safety argument as *"a backend that cannot enforce a limit a caller asks for says so
    /// through `Enforcement::first_gap`, and the caller refuses rather than running third-party code with a bound it does not
    /// have"*. Nothing called it, and the reason it cannot simply be called per call is worth keeping: production budgets
    /// **always** set a timeout (`matching.rs`'s `budget()`), while `ScriptedBackend` honestly reports `epoch: false` — so a
    /// per-call check refuses every call made through the test double, and the double's honesty is itself pinned by a test.
    ///
    /// The decision this variant records is **where the question belongs**. It is asked once, where a kernel chooses its
    /// engine, because that is the only moment a person can act on the answer: an engine missing a limit is a fact about the
    /// installation, not about a call. A kernel that cannot bound what it runs must not start, and it must say which bound is
    /// missing rather than running third-party code without it.
    ///
    /// ★ It is quiet today and that is the point: the wasmtime backend enforces everything and the default quota
    /// asks for everything, so this never fires. The `wasmi` backend the design still lists is exactly the one that would.
    #[error("this engine cannot enforce {missing}, which this host's budgets ask for")]
    CannotEnforce {
        /// Which limit, as `Enforcement::first_gap` names it.
        missing: &'static str,
    },

    /// The engine is not compiled into this build.
    ///
    /// Named separately from [`Self::Compile`] because the caller's next step is different: nothing about the artifact
    /// is wrong, and the build is what has to change.
    #[error("the {kind} backend is not compiled into this build")]
    BackendUnavailable {
        /// Which backend was wanted.
        kind: BackendKind,
    },

    /// The artifact is not a valid component, or is one this engine cannot compile.
    #[error("the artifact could not be compiled: {detail}")]
    Compile {
        /// What the engine said.
        detail: String,
    },

    /// The component imports something the host does not provide.
    ///
    /// ★ Refused at instantiation, not at the first call. A component importing an unknown function is one built
    /// against a host that has it, and letting it link would move the failure to a call site far from the cause.
    #[error("the component imports {import}, which this host does not provide")]
    UnknownImport {
        /// The import name, in full.
        import: String,
    },

    /// The component imports something the plugin was not granted.
    #[error("the component imports {import}, which needs {capability} and was not granted")]
    UngrantedImport {
        /// The import name.
        import: String,
        /// The capability it needs.
        capability: &'static str,
    },

    /// The component does not export an interface the contract requires.
    #[error("the component does not export {export}")]
    MissingExport {
        /// The interface that is missing.
        export: &'static str,
    },

    /// The instance could not be created: a missing memory, a start function that trapped.
    #[error("the instance could not be created: {detail}")]
    Instantiate {
        /// What the engine said.
        detail: String,
    },

    /// Creating another instance would exceed what the quota allows.
    #[error("the plugin already holds {live} instances and may hold {limit}")]
    TooManyInstances {
        /// How many exist.
        live: u32,
        /// What the quota allows.
        limit: u32,
    },

    /// The engine's own failure, which is not the plugin's fault.
    #[error("the engine failed: {detail}")]
    Engine {
        /// What it said.
        detail: String,
    },
}
