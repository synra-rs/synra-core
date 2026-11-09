use super::*;

/// An intent identifier from its text.
pub(super) fn parse_intent(text: &str) -> Result<synra_protocol::ids::IntentId, RouteError> {
    text.parse::<synra_protocol::ids::IntentId>().map_err(|_| {
        RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            "that is not an intent identifier",
        )
    })
}

/// Turns a board error into a refusal, keeping its own words.
///
/// # Why the board's message is passed through
///
/// Because it already says what a user needs — "this intent is not waiting to be confirmed, it is choosing" names both the
/// attempt and the state — and re-wording it here would be a second description of the same state machine, free to
/// disagree with the first.
pub(super) fn refuse_intent(error: &crate::intent::IntentError) -> RouteError {
    RouteError::new(
        synra_protocol::ErrorCode::InvalidArgument,
        error.to_string(),
    )
}

/// The candidates the board is holding for an intent.
///
/// # Why this is not `IntentState::candidates()`
///
/// Because that method answers "what is the user choosing **between**", and it returns an empty slice once the board has
/// settled on one — `Confirming` holds a single candidate rather than a list. A snapshot built from it alone showed a
/// share that had been routed successfully as having no candidates at all, which is precisely the fact a prompt needs.
/// The states are listed here rather than defaulted, so a state added later has to be considered.
pub(super) fn candidates_of(
    board: &Board,
    id: synra_protocol::ids::IntentId,
) -> Vec<CandidateView> {
    use crate::intent::IntentState;
    let Some(intent) = board.get(id) else {
        return Vec::new();
    };
    let one;
    let candidates: &[crate::intent::IntentCandidate] = match &intent.state {
        IntentState::Matching { candidates, .. } | IntentState::Choosing { candidates } => {
            candidates
        }
        IntentState::Confirming { candidate, .. } | IntentState::Dispatching { candidate, .. } => {
            one = std::slice::from_ref(candidate);
            one
        }
        // Over, one way or another, and there is nothing left to offer.
        _ => &[],
    };
    candidates
        .iter()
        .map(|candidate| CandidateView {
            plugin_id: candidate.plugin_id.clone(),
            plugin_version: candidate.plugin_version.clone(),
            action: candidate.planned.action.clone(),
            args: candidate.planned.args.clone(),
            title: candidate.title.clone(),
            detail: candidate.detail.clone(),
            required_caps: candidate.required_caps.clone(),
            suggested_target: candidate.suggested_target,
        })
        .collect()
}

/// A stable name for a state, for a client that switches on it.
pub(super) const fn state_name(state: &crate::intent::IntentState) -> &'static str {
    // One definition, in `IntentState::name`. The match that used to stand here was a second copy, and the two names
    // (`kind` for storage, `name` for the wire) are documented where the states are.
    state.name()
}
