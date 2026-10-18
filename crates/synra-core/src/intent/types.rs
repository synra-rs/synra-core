//! An intent: what a user asked for, before anything has decided how to do it.
//!
//! # Why this is a type of its own and not a message
//!
//! Because the interesting part of the product is the *gap* between "the user shared a link" and "a plugin opened a
//! browser on another machine", and everything that happens in that gap is a decision somebody has to make: which
//! plugins are even asked, which of their answers count, whether a user is interrupted, which device runs it, and what
//! happens when the answer never comes. A message struct cannot hold a decision that is still being made.
//!
//! # What is here and what is not
//!
//! This module is the **vocabulary**: what an intent is made of, what a candidate is, and every way one can end. The
//! board that sequences them — matching, deadlines, idempotency — is [`crate::intent`], and it is deliberately a
//! separate file because the two have different readers: this one is read by whoever adds a source of intents, and the
//! board by whoever changes the order things happen in.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use synra_protocol::ids::{DeviceId, IntentId, PluginId, RequestId, TraceId};
use synra_protocol::SynraError;

use crate::admission::AdmissionRefusal;

/// What an intent will carry once a plugin has been chosen.
///
/// The same shape the wire uses, so a candidate that becomes a dispatch does not get rebuilt on the way out: a second
/// structure would be a second place for the action's name to drift from the one the user was shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedAction {
    /// Which plugin would run it.
    pub plugin_id: PluginId,
    /// Which of that plugin's actions.
    pub action: String,
    /// The action's arguments, as JSON.
    pub args: serde_json::Value,
}

/// One plugin's answer to "can you handle this?".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentCandidate {
    /// Who answered.
    pub plugin_id: PluginId,
    /// The version that answered, which a dispatch records: a plugin updated between the prompt and the decision is a
    /// plugin the user did not agree about.
    pub plugin_version: String,
    /// What it proposes to do.
    pub planned: PlannedAction,
    /// The capabilities the action needs, which the gate checks before anything runs.
    pub required_caps: Vec<String>,
    /// Where it suggests running, when it has an opinion.
    pub suggested_target: Option<DeviceId>,
    /// One line for a prompt, which is what a user chooses between.
    pub title: String,
    /// Optional detail, such as the URL that would be opened.
    pub detail: Option<String>,
}

impl IntentCandidate {
    /// Whether this candidate is the same plugin answering twice.
    ///
    /// # Why a second answer from one plugin replaces the first rather than joining it
    ///
    /// Because a plugin asked twice — once for the same share under two event names, say — has not offered the user two
    /// choices; it has offered one and described it twice. Two entries in a prompt would ask a user to choose between
    /// the same thing.
    #[must_use]
    pub fn supersedes(&self, other: &Self) -> bool {
        self.plugin_id == other.plugin_id && self.planned.action == other.planned.action
    }
}

/// Where an intent came from.
///
/// # Why the source is kept rather than flattened into an action
///
/// Because it is what the *next* decision is made from: a share is matched by asking every plugin that declares a share
/// handler, a direct call names its plugin already, and a clipboard push is neither. Flattening these into "an action
/// and its arguments" would lose the fact that decides who gets asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IntentSource {
    /// The operating system's share sheet handed something over.
    Share {
        /// The shared item, as the inbound layer parsed it.
        item: synra_protocol::inbound::ShareItem,
        /// The application that shared it, when the platform said.
        source_app: Option<String>,
    },
    /// This device's own clipboard changed and the user asked for it to go somewhere.
    Clipboard {
        /// Which device it is meant for, or `None` to ask.
        target: Option<DeviceId>,
    },
    /// A plugin's own window asked for something.
    PluginUi {
        /// Which plugin.
        plugin_id: PluginId,
        /// Which action.
        action: String,
        /// Its arguments.
        params: serde_json::Value,
    },
    /// Somebody named the plugin and the action directly: a CLI, a test, a deep link.
    Direct {
        /// Which plugin.
        plugin_id: PluginId,
        /// Which action.
        action: String,
        /// Its arguments.
        params: serde_json::Value,
        /// Where it should run.
        target: DeviceId,
    },
}

impl IntentSource {
    /// A short name, for a log line and a metric label.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Share { .. } => "share",
            Self::Clipboard { .. } => "clipboard",
            Self::PluginUi { .. } => "plugin-ui",
            Self::Direct { .. } => "direct",
        }
    }

    /// The plugin already named by the source, when there is one.
    ///
    /// A [`IntentSource::Direct`] or [`IntentSource::PluginUi`] names its plugin, so nothing has to be matched: the
    /// candidate list has one entry and the matching phase has no questions to ask. Answering `None` here is what makes
    /// a share go through matching.
    #[must_use]
    pub const fn named_plugin(&self) -> Option<&PluginId> {
        match self {
            Self::PluginUi { plugin_id, .. } | Self::Direct { plugin_id, .. } => Some(plugin_id),
            Self::Share { .. } | Self::Clipboard { .. } => None,
        }
    }

    /// The device the source already chose, when it did.
    #[must_use]
    pub const fn named_target(&self) -> Option<DeviceId> {
        match self {
            Self::Clipboard { target } => *target,
            Self::Direct { target, .. } => Some(*target),
            Self::Share { .. } | Self::PluginUi { .. } => None,
        }
    }

    /// The candidate this source implies without asking anyone, when it implies one.
    #[must_use]
    pub fn implied_action(&self) -> Option<PlannedAction> {
        // Two arms rather than one with an `|`: `Direct` carries a `target` that `PluginUi` does not, and a pattern
        // that names only the shared fields is the one a field added to either variant would silently stop binding.
        let (plugin_id, action, params) = match self {
            Self::PluginUi { plugin_id, action, params } => (plugin_id, action, params),
            Self::Direct { plugin_id, action, params, .. } => (plugin_id, action, params),
            Self::Share { .. } | Self::Clipboard { .. } => return None,
        };
        Some(PlannedAction {
            plugin_id: plugin_id.clone(),
            action: action.clone(),
            args: params.clone(),
        })
    }
}

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
    /// The candidate list arrived too late to be useful.
    TimedOut {
        /// How long the matching window was.
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
        &["succeeded", "failed", "no-handler", "timed-out", "refused", "cancelled"]
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

/// An intent, with everything known about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// Identifies it for its whole life, and travels with the dispatch.
    pub id: IntentId,
    /// Follows it across devices and into logs.
    pub trace: TraceId,
    /// What asked for it.
    pub source: IntentSource,
    /// Where it is.
    pub state: IntentState,
    /// How much attention it may need.
    pub choice: Choice,
    /// When it was raised, in signed milliseconds since the epoch.
    pub created_at_ms: i64,
    /// The envelope id a dispatch carries, once there is one.
    pub request_id: Option<RequestId>,
    /// Which device it came from, when it came over a link.
    ///
    /// Part of the idempotency key: two devices may both pick the same identifier, and the same device may send the
    /// same request twice because its answer was lost.
    pub origin: Option<DeviceId>,
}

impl Intent {
    /// Whether this intent's action is the same one another request names.
    ///
    /// # Why the whole triple and not the request id alone
    ///
    /// A request id is chosen by the sender, and two senders choose independently: the same id from two devices is two
    /// requests. Comparing all three is what makes "have I already done this?" a question with an answer.
    #[must_use]
    pub fn is_same_request_as(&self, origin: DeviceId, request: RequestId) -> bool {
        self.origin == Some(origin) && self.request_id == Some(request)
    }
}
