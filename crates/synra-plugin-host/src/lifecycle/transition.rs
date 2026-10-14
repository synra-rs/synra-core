//! What may be done to a plugin, and why a move was refused.


/// Something that may be done to a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transition {
    /// Check the manifest, the artifacts and the signature.
    Validate {
        /// The digest the manifest hashed to.
        manifest_digest: String,
    },
    /// Record the user's decisions.
    Grant {
        /// Whether anything was denied.
        partially_denied: bool,
    },
    /// Start the plugin.
    Activate,
    /// Stop the plugin, keeping it installed.
    Deactivate,
    /// Stop it and mark it unusable.
    Fault {
        /// Why.
        reason: String,
    },
    /// Load nothing, so the package may change.
    Park,
    /// Clear a fault, returning the plugin to a usable state.
    ///
    /// The **only** way out of [`State::Faulted`]. Reached when a user re-enables a plugin that the host disabled, or
    /// when the plugin is reinstalled. It is a distinct transition rather than an implicit effect of parking or
    /// upgrading, because those are housekeeping steps a caller may take for unrelated reasons — and a fault that a
    /// package change silently cleared would make the ladder's last rung decorative.
    ClearFault,
    /// Remove it.
    Uninstall,
    /// Replace the artifact with another version.
    Upgrade {
        /// The version being installed.
        version: String,
    },
}

impl Transition {
    /// A name for a log line.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Validate { .. } => "validate",
            Self::Grant { .. } => "grant",
            Self::Activate => "activate",
            Self::Deactivate => "deactivate",
            Self::Fault { .. } => "fault",
            Self::Park => "park",
            Self::ClearFault => "clear-fault",
            Self::Uninstall => "uninstall",
            Self::Upgrade { .. } => "upgrade",
        }
    }
}

/// Why a transition was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransitionError {
    /// The plugin is in a state the transition does not apply to.
    #[error("cannot {transition} a plugin that is {state}")]
    WrongState {
        /// The state it is in.
        state: &'static str,
        /// What was attempted.
        transition: &'static str,
    },

    /// The plugin must be parked first.
    ///
    /// Reported separately from [`Self::WrongState`] because the caller's response is different: it has a step to
    /// perform, not a mistake to fix.
    #[error("the plugin is holding loaded code; it has to be parked before it can be {transition}")]
    NeedsParking {
        /// What was attempted.
        transition: &'static str,
    },

    /// A faulted plugin may not be restarted.
    #[error("the plugin is faulted ({reason}); it has to be reinstalled or re-enabled by the user")]
    Faulted {
        /// Why it was faulted.
        reason: String,
    },
}

impl TransitionError {
    /// Whether the caller can make progress by doing something else first.
    #[must_use]
    pub const fn has_a_next_step(&self) -> bool {
        matches!(self, Self::NeedsParking { .. })
    }
}
