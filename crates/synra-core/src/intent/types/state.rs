use super::*;

/// How much of a user's attention an intent is allowed to need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Choice {
    /// Pick a candidate without asking, when one candidate is clearly the answer.
    ///
    /// ★ The default, and deliberately so: the ordinary share is "open this link", one plugin claims it, and a prompt
    /// would be a dialog the user learns to dismiss. What makes it safe is the two conditions below — a single
    /// candidate **and** the plugin having asked to be automatic — so a plugin cannot make itself the silent answer.
    #[default]
    Automatic,
    /// Ask, whatever the candidate count.
    ///
    /// A user's setting, and the answer for a device that has more than one plugin claiming the same thing.
    AlwaysAsk,
    /// Ask only when more than one plugin claims it.
    AskWhenAmbiguous,
    /// Refuse rather than ask: for an unattended device, where a prompt would sit unanswered.
    Never,
}

/// How an intent is progressing.
///
/// # Why the failure of a *phase* and the failure of an *outcome* are different states
///
/// Because the user's next step is different. "No plugin can handle this" is a fact about what is installed, and the
/// answer is to install something or share it differently. "A plugin refused" is a fact about a plugin, and the answer
/// is to look at that plugin. "The other device never answered" is a fact about the network, and the answer is to try
/// again. One `Failed` state with a message inside would put the burden of telling them apart on whoever renders it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IntentState {
    /// Asking plugins whether they can handle it.
    Matching {
        /// When the asking stops, whether or not every plugin has answered.
        ///
        /// ★ A deadline rather than a barrier. One plugin that never returns must not hold up a share for ever, and a
        /// prompt that appears after an unbounded wait is worse than one that appears with the answers that arrived.
        deadline_ms: i64,
        /// What has arrived so far.
        candidates: Vec<IntentCandidate>,
    },
    /// Matching is over and a user has to choose.
    ///
    /// A state of its own rather than a variant of `Matching`: the two differ in what may happen next — a candidate may
    /// still arrive while matching, and a candidate arriving while a user is reading a prompt must not silently change
    /// the list under them — and a state machine that spelled that as a boolean would let both.
    Choosing {
        /// What to choose between. Never empty: an empty choice is [`IntentState::NoHandler`].
        candidates: Vec<IntentCandidate>,
    },
    /// A candidate and a target are decided, and the user is being asked to confirm the action.
    Confirming {
        /// What would run.
        candidate: IntentCandidate,
        /// Where.
        target: DeviceId,
    },
    /// It has been sent and is running elsewhere.
    Dispatching {
        /// What is running.
        candidate: IntentCandidate,
        /// Where.
        target: DeviceId,
        /// The envelope's id, which is what the outcome is correlated by — and what is reused on a retry so the
        /// receiving side's idempotency cache recognises it.
        request_id: RequestId,
    },
    /// It worked.
    Succeeded {
        /// What the action returned.
        result: serde_json::Value,
        /// How long the remote side said it took.
        elapsed_ms: u64,
    },
    /// A plugin or a device reported a failure.
    Failed {
        /// What went wrong, in the kernel's own error vocabulary.
        error: SynraError,
        /// How long it took, when there was an attempt to time.
        elapsed_ms: u64,
    },
    /// Nothing installed claims this.
    NoHandler,
    /// Nobody answered in time.
    ///
    /// # The two ways to arrive here
    ///
    /// The candidate list arrived too late to be useful, or the intent was sent to another device and the window in which
    /// a late answer could still be delivered has passed. Both are "the network did not answer", and the user's next step
    /// is the same in each — try again — which is why they share a state rather than one being a `Failed` with a message.
    TimedOut {
        /// How long was waited: the matching window, or the time since the dispatch that went unanswered.
        after: Duration,
    },
    /// The intent's admission was refused, so nothing was even attempted.
    ///
    /// Distinct from [`IntentState::Failed`] because a refusal is the kernel's own decision, made before a plugin saw
    /// anything — and the eight checks that produce one each name themselves.
    Refused {
        /// Which check refused it.
        refusal: AdmissionRefusal,
    },
    /// A user or a policy stopped it.
    Cancelled {
        /// Why, in the user's words where there are any.
        reason: String,
    },
}

impl IntentState {
    /// Whether nothing more will happen.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(
            self,
            Self::Succeeded { .. }
                | Self::Failed { .. }
                | Self::NoHandler
                | Self::TimedOut { .. }
                | Self::Refused { .. }
                | Self::Cancelled { .. }
        )
    }

    /// Whether a plugin is doing something right now.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Dispatching { .. })
    }

    /// The [`IntentState::kind`] names of the states nothing more will happen in.
    ///
    /// # ★ Why this list is here rather than where it is used
    ///
    /// Because the store's retention sweep compares a persisted `state` column against these names, and the storage layer
    /// cannot depend on the kernel — so the list has to be handed to it. A list written at the call site would be a second
    /// definition of "finished", and the two would drift the first time a state is renamed: a rename here that is not made
    /// there would make every intent in that state **immortal**, and a rename the other way would collect work still in
    /// progress. There is a test beside this that constructs every variant and asserts the two agree.
    #[must_use]
    pub const fn final_kinds() -> &'static [&'static str] {
        &[
            "succeeded",
            "failed",
            "no-handler",
            "timed-out",
            "refused",
            "cancelled",
        ]
    }

    /// The candidates, wherever they are being held.
    #[must_use]
    pub fn candidates(&self) -> &[IntentCandidate] {
        match self {
            Self::Matching { candidates, .. } | Self::Choosing { candidates } => candidates,
            _ => &[],
        }
    }

    /// A short name, for a log line and a metric label.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Matching { .. } => "matching",
            Self::Choosing { .. } => "choosing",
            Self::Confirming { .. } => "confirming",
            Self::Dispatching { .. } => "dispatching",
            Self::Succeeded { .. } => "succeeded",
            Self::Failed { .. } => "failed",
            Self::NoHandler => "no-handler",
            Self::TimedOut { .. } => "timed-out",
            Self::Refused { .. } => "refused",
            Self::Cancelled { .. } => "cancelled",
        }
    }

    /// The name the control protocol and the interface use, which is not [`Self::kind`].
    ///
    /// # Why two names
    ///
    /// Because they answer two readers. `kind` is a storage and metric label, where a hyphen is the separator a dashboard
    /// groups by. The interface has always received camelCase (`noHandler`, `timedOut`), and changing that to match the
    /// storage would rename every state the window already knows. One definition each, and this is where the difference is
    /// written down rather than in a `match` on the other side of the crate.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Matching { .. } => "matching",
            Self::Choosing { .. } => "choosing",
            Self::Confirming { .. } => "confirming",
            Self::Dispatching { .. } => "dispatching",
            Self::Succeeded { .. } => "succeeded",
            Self::Failed { .. } => "failed",
            Self::NoHandler => "noHandler",
            Self::TimedOut { .. } => "timedOut",
            Self::Refused { .. } => "refused",
            Self::Cancelled { .. } => "cancelled",
        }
    }
}

/// What a caller learns when a move is not legal from where the intent is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntentError {
    /// The intent is not on the board.
    #[error("{intent_id} is not an intent this kernel knows about")]
    Unknown {
        /// Which intent.
        intent_id: IntentId,
    },

    /// The move does not apply to the state it is in.
    ///
    /// Naming both is the point: "cannot answer a prompt that is not being asked" is actionable, and "invalid state"
    /// is not.
    #[error("cannot {attempted} an intent that is {current}")]
    WrongState {
        /// What was attempted.
        attempted: &'static str,
        /// Where the intent is.
        current: &'static str,
    },

    /// A named candidate is not one this intent offers.
    ///
    /// Checked rather than trusted: a choice arrives from an interface, and an index or a name from an interface is
    /// input. Acting on one that is not on the list would run something the user was never shown.
    #[error("{action} by {plugin_id} is not one of this intent's candidates")]
    NotACandidate {
        /// Which plugin was named.
        plugin_id: String,
        /// Which action.
        action: String,
    },

    /// The intent has already ended.
    #[error("the intent already ended as {ended}")]
    AlreadyEnded {
        /// How it ended.
        ended: &'static str,
    },
}
