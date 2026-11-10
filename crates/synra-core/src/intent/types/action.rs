use super::*;

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
